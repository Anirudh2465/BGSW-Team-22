// Stage 3 class-graph extractor (runs inside the offline scan sandbox, --network=none).
//
// Parses every .java file under the source root with JavaParser and writes AST facts as
// JSON: type declarations, their members and every type reference, categorised by how it
// is used (extends, implements, field, method signature, instantiation, static call,
// annotation, other use). It does not resolve names: scanner-intel resolves references
// against the project's own declarations with NetworkX. Only facts leave the sandbox,
// never source text.
//
// Usage: java -cp javaparser-core.jar:class-graph.jar ClassGraphExtractor <src-dir> <out.json>

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.AnnotationDeclaration;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.ReferenceType;
import com.github.javaparser.ast.type.TypeParameter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

public final class ClassGraphExtractor {
    static final String VERSION = "1.0.0";
    static final String JAVAPARSER_VERSION = "3.26.2";
    static final int MAX_FILES = 20_000;
    static final long MAX_FILE_BYTES = 1_000_000;
    static final int MAX_ERRORS = 200;
    static final Set<String> SKIP_DIRS = Set.of(
            ".git", "node_modules", "target", "build", "out", "dist", "vendor", ".gradle", ".idea", ".mvn", "bin");

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: ClassGraphExtractor <src-dir> <out.json>");
            System.exit(2);
        }
        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        List<Path> files = collect(root);

        ParserConfiguration cfg = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
                .setAttributeComments(false)
                .setStoreTokens(false);
        JavaParser parser = new JavaParser(cfg);

        StringBuilder units = new StringBuilder();
        List<String> errors = new ArrayList<>();
        int parsed = 0, failed = 0, skippedLarge = 0;
        for (Path file : files) {
            String rel = root.relativize(file).toString().replace('\\', '/');
            try {
                if (Files.size(file) > MAX_FILE_BYTES) {
                    skippedLarge++;
                    continue;
                }
                String code = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                ParseResult<CompilationUnit> res = parser.parse(code);
                Optional<CompilationUnit> cu = res.getResult();
                if (!res.isSuccessful()) {
                    failed++;
                    if (errors.size() < MAX_ERRORS) {
                        String msg = res.getProblems().isEmpty() ? "parse failed" : res.getProblem(0).getMessage();
                        errors.add("{\"path\":" + q(rel) + ",\"error\":" + q(firstLine(msg)) + "}");
                    }
                }
                if (cu.isPresent()) {
                    if (units.length() > 0) units.append(',');
                    units.append(unit(rel, cu.get(), res.isSuccessful()));
                    if (res.isSuccessful()) parsed++;
                }
            } catch (Exception | StackOverflowError e) {
                failed++;
                if (errors.size() < MAX_ERRORS) {
                    errors.add("{\"path\":" + q(rel) + ",\"error\":" + q(e.getClass().getSimpleName()) + "}");
                }
            }
        }

        String json = "{\"tool\":\"javaparser\",\"tool_version\":" + q(JAVAPARSER_VERSION)
                + ",\"extractor_version\":" + q(VERSION)
                + ",\"language_level\":\"JAVA_21\""
                + ",\"files_found\":" + files.size()
                + ",\"files_parsed\":" + parsed
                + ",\"files_failed\":" + failed
                + ",\"files_skipped_large\":" + skippedLarge
                + ",\"truncated\":" + (files.size() >= MAX_FILES)
                + ",\"errors\":[" + String.join(",", errors) + "]"
                + ",\"compilation_units\":[" + units + "]}";
        Files.createDirectories(Paths.get(args[1]).toAbsolutePath().getParent());
        Files.write(Paths.get(args[1]), json.getBytes(StandardCharsets.UTF_8));
    }

    static List<Path> collect(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && SKIP_DIRS.contains(dir.getFileName().toString())) return FileVisitResult.SKIP_SUBTREE;
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isRegularFile() && !attrs.isSymbolicLink() && file.toString().endsWith(".java")) out.add(file);
                return out.size() >= MAX_FILES ? FileVisitResult.TERMINATE : FileVisitResult.CONTINUE;
            }
        });
        Collections.sort(out);
        return out;
    }

    static String unit(String path, CompilationUnit cu, boolean complete) {
        String pkg = cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
        StringBuilder imports = new StringBuilder();
        for (ImportDeclaration imp : cu.getImports()) {
            if (imports.length() > 0) imports.append(',');
            imports.append("{\"name\":").append(q(imp.getNameAsString()))
                    .append(",\"static\":").append(imp.isStatic())
                    .append(",\"asterisk\":").append(imp.isAsterisk()).append('}');
        }
        StringBuilder types = new StringBuilder();
        for (TypeDeclaration<?> td : cu.findAll(TypeDeclaration.class)) {
            if (types.length() > 0) types.append(',');
            types.append(type(td, pkg));
        }
        return "{\"path\":" + q(path) + ",\"package\":" + q(pkg) + ",\"complete\":" + complete
                + ",\"imports\":[" + imports + "],\"types\":[" + types + "]}";
    }

    static String fqn(TypeDeclaration<?> td, String pkg) {
        return td.getFullyQualifiedName().orElse(pkg.isEmpty() ? td.getNameAsString() : pkg + "." + td.getNameAsString());
    }

    static String type(TypeDeclaration<?> td, String pkg) {
        String kind;
        boolean isAbstract = false;
        List<ClassOrInterfaceType> ext = new ArrayList<>(), impl = new ArrayList<>();
        Set<String> typeParams = new HashSet<>();
        if (td instanceof ClassOrInterfaceDeclaration) {
            ClassOrInterfaceDeclaration c = (ClassOrInterfaceDeclaration) td;
            kind = c.isInterface() ? "interface" : "class";
            isAbstract = c.isAbstract();
            ext.addAll(c.getExtendedTypes());
            impl.addAll(c.getImplementedTypes());
            for (TypeParameter tp : c.getTypeParameters()) typeParams.add(tp.getNameAsString());
        } else if (td instanceof EnumDeclaration) {
            kind = "enum";
            impl.addAll(((EnumDeclaration) td).getImplementedTypes());
        } else if (td instanceof RecordDeclaration) {
            kind = "record";
            RecordDeclaration r = (RecordDeclaration) td;
            impl.addAll(r.getImplementedTypes());
            for (TypeParameter tp : r.getTypeParameters()) typeParams.add(tp.getNameAsString());
        } else if (td instanceof AnnotationDeclaration) {
            kind = "annotation";
        } else {
            kind = "type";
        }
        // Method-level generics are type parameters too, not references.
        for (MethodDeclaration m : td.getMethods()) for (TypeParameter tp : m.getTypeParameters()) typeParams.add(tp.getNameAsString());

        // Categorise each type reference that belongs to this declaration (not to a nested one).
        IdentityHashMap<ClassOrInterfaceType, String> category = new IdentityHashMap<>();
        mark(category, ext, "extends");
        mark(category, impl, "implements");
        for (BodyDeclaration<?> member : td.getMembers()) {
            if (member instanceof FieldDeclaration) {
                mark(category, member.findAll(ClassOrInterfaceType.class), "field");
            } else if (member instanceof MethodDeclaration) {
                MethodDeclaration m = (MethodDeclaration) member;
                markSignature(category, m.getType(), m.getParameters(), m.getThrownExceptions());
            } else if (member instanceof ConstructorDeclaration) {
                ConstructorDeclaration c = (ConstructorDeclaration) member;
                markSignature(category, null, c.getParameters(), c.getThrownExceptions());
            }
        }
        for (ObjectCreationExpr oc : td.findAll(ObjectCreationExpr.class)) {
            if (owner(oc) == td) category.putIfAbsent(oc.getType(), "instantiates");
        }
        if (td instanceof RecordDeclaration) {
            for (Parameter p : ((RecordDeclaration) td).getParameters()) mark(category, p.findAll(ClassOrInterfaceType.class), "field");
        }

        Map<String, int[]> refs = new TreeMap<>(); // "kind\u0000name" -> {count, firstLine}
        for (ClassOrInterfaceType t : td.findAll(ClassOrInterfaceType.class)) {
            if (owner(t) != td) continue;
            String name = t.getNameWithScope();
            if (typeParams.contains(name)) continue;
            add(refs, category.getOrDefault(t, "uses"), name, line(t));
        }
        for (MethodCallExpr call : td.findAll(MethodCallExpr.class)) {
            if (owner(call) != td || call.getScope().isEmpty() || !(call.getScope().get() instanceof NameExpr)) continue;
            String scope = ((NameExpr) call.getScope().get()).getNameAsString();
            if (!scope.isEmpty() && Character.isUpperCase(scope.charAt(0))) add(refs, "calls", scope, line(call));
        }
        List<String> typeAnnotations = new ArrayList<>();
        for (AnnotationExpr a : td.getAnnotations()) typeAnnotations.add(a.getNameAsString());
        for (AnnotationExpr a : td.findAll(AnnotationExpr.class)) {
            if (owner(a) == td) add(refs, "annotation", a.getNameAsString(), line(a));
        }

        StringBuilder refJson = new StringBuilder();
        for (Map.Entry<String, int[]> e : refs.entrySet()) {
            String[] kn = e.getKey().split("\u0000", 2);
            if (refJson.length() > 0) refJson.append(',');
            refJson.append("{\"k\":").append(q(kn[0])).append(",\"n\":").append(q(kn[1]))
                    .append(",\"c\":").append(e.getValue()[0]).append(",\"l\":").append(e.getValue()[1]).append('}');
        }
        StringBuilder ann = new StringBuilder();
        for (String a : typeAnnotations) {
            if (ann.length() > 0) ann.append(',');
            ann.append(q(a));
        }
        int fields = 0;
        for (FieldDeclaration f : td.getFields()) fields += f.getVariables().size();
        int begin = td.getBegin().map(p -> p.line).orElse(0);
        int end = td.getEnd().map(p -> p.line).orElse(begin);
        String outer = td.getParentNode().filter(p -> p instanceof TypeDeclaration)
                .map(p -> fqn((TypeDeclaration<?>) p, pkg)).orElse("");

        return "{\"fqn\":" + q(fqn(td, pkg)) + ",\"name\":" + q(td.getNameAsString()) + ",\"kind\":" + q(kind)
                + ",\"abstract\":" + isAbstract + ",\"outer\":" + q(outer)
                + ",\"line\":" + begin + ",\"end_line\":" + end
                + ",\"methods\":" + td.getMethods().size() + ",\"fields\":" + fields
                + ",\"constructors\":" + td.getConstructors().size()
                + ",\"annotations\":[" + ann + "],\"refs\":[" + refJson + "]}";
    }

    static void markSignature(IdentityHashMap<ClassOrInterfaceType, String> category, Node returnType,
                              List<Parameter> params, List<ReferenceType> thrown) {
        if (returnType != null) mark(category, returnType.findAll(ClassOrInterfaceType.class), "method");
        for (Parameter p : params) mark(category, p.findAll(ClassOrInterfaceType.class), "method");
        for (ReferenceType t : thrown) mark(category, t.findAll(ClassOrInterfaceType.class), "method");
    }

    static void mark(IdentityHashMap<ClassOrInterfaceType, String> category, List<ClassOrInterfaceType> types, String kind) {
        for (ClassOrInterfaceType t : types) {
            for (ClassOrInterfaceType inner : t.findAll(ClassOrInterfaceType.class)) category.putIfAbsent(inner, kind);
        }
    }

    /** The nearest enclosing type declaration of a node. */
    static Node owner(Node n) {
        return n.findAncestor(TypeDeclaration.class).map(t -> (Node) t).orElse(null);
    }

    static void add(Map<String, int[]> refs, String kind, String name, int line) {
        int[] v = refs.computeIfAbsent(kind + "\u0000" + name, k -> new int[]{0, line});
        v[0]++;
        if (line > 0 && (v[1] == 0 || line < v[1])) v[1] = line;
    }

    static int line(Node n) {
        return n.getBegin().map(p -> p.line).orElse(0);
    }

    static String firstLine(String s) {
        int i = s.indexOf('\n');
        String line = i >= 0 ? s.substring(0, i) : s;
        return line.length() > 300 ? line.substring(0, 300) : line;
    }

    static String q(String s) {
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
