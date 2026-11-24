"""Which Java packages a Maven artifact provides, so class-graph references can be attributed to it.

Maven coordinates do not name Java packages, so this is an explicit, conservative mapping:

1. a curated table for common libraries whose packages do not follow their coordinates
2. derived candidates: ``groupId.<artifactId without the groupId's last word>``
   (``org.apache.commons:commons-lang3`` -> ``org.apache.commons.lang3``,
   ``org.springframework:spring-web`` -> ``org.springframework.web``) and ``groupId.artifactId``
(The bare groupId is never used: ``org.apache.commons`` would wrongly credit commons-lang3 with
``org.apache.commons.logging``.)

A candidate only matters if a type the application references actually starts with it, and a type
is attributed to the component with the longest matching prefix; a tie means "ambiguous" and no
claim is made. So a wrong guess can only fail to find usage, never invent it.
"""

import re
from typing import Dict, Iterable, List, Set, Tuple

CURATED: Dict[Tuple[str, str], List[str]] = {
    ("org.apache.logging.log4j", "log4j-core"): ["org.apache.logging.log4j.core"],
    ("org.apache.logging.log4j", "log4j-api"): ["org.apache.logging.log4j"],
    ("org.apache.logging.log4j", "log4j-slf4j-impl"): ["org.apache.logging.slf4j"],
    ("org.apache.logging.log4j", "log4j-slf4j2-impl"): ["org.apache.logging.slf4j"],
    ("log4j", "log4j"): ["org.apache.log4j"],
    ("com.fasterxml.jackson.core", "jackson-databind"): ["com.fasterxml.jackson.databind"],
    ("com.fasterxml.jackson.core", "jackson-core"): ["com.fasterxml.jackson.core"],
    ("com.fasterxml.jackson.core", "jackson-annotations"): ["com.fasterxml.jackson.annotation"],
    ("com.google.guava", "guava"): ["com.google.common"],
    ("com.google.code.gson", "gson"): ["com.google.gson"],
    ("com.google.protobuf", "protobuf-java"): ["com.google.protobuf"],
    ("commons-io", "commons-io"): ["org.apache.commons.io"],
    ("commons-codec", "commons-codec"): ["org.apache.commons.codec"],
    ("commons-collections", "commons-collections"): ["org.apache.commons.collections"],
    ("commons-beanutils", "commons-beanutils"): ["org.apache.commons.beanutils"],
    ("commons-fileupload", "commons-fileupload"): ["org.apache.commons.fileupload"],
    ("commons-logging", "commons-logging"): ["org.apache.commons.logging"],
    ("org.apache.httpcomponents", "httpclient"): ["org.apache.http"],
    ("org.apache.httpcomponents", "httpcore"): ["org.apache.http"],
    ("org.apache.httpcomponents.client5", "httpclient5"): ["org.apache.hc.client5"],
    ("org.yaml", "snakeyaml"): ["org.yaml.snakeyaml"],
    ("com.thoughtworks.xstream", "xstream"): ["com.thoughtworks.xstream"],
    ("org.codehaus.jackson", "jackson-mapper-asl"): ["org.codehaus.jackson.map"],
    ("com.alibaba", "fastjson"): ["com.alibaba.fastjson"],
    ("org.json", "json"): ["org.json"],
    ("net.minidev", "json-smart"): ["net.minidev.json"],
    ("org.apache.struts", "struts2-core"): ["org.apache.struts2", "com.opensymphony.xwork2"],
    ("org.springframework", "spring-webmvc"): ["org.springframework.web.servlet"],
    ("org.springframework", "spring-web"): ["org.springframework.web", "org.springframework.http"],
    ("org.springframework", "spring-beans"): ["org.springframework.beans"],
    ("org.springframework", "spring-expression"): ["org.springframework.expression"],
    ("org.springframework", "spring-core"): ["org.springframework.core", "org.springframework.util"],
    ("org.springframework", "spring-context"): ["org.springframework.context", "org.springframework.stereotype",
                                               "org.springframework.cache", "org.springframework.validation",
                                               "org.springframework.format", "org.springframework.ui"],
    ("org.springframework", "spring-tx"): ["org.springframework.transaction", "org.springframework.dao"],
    ("org.springframework", "spring-jdbc"): ["org.springframework.jdbc"],
    ("org.springframework.data", "spring-data-jpa"): ["org.springframework.data.jpa"],
    ("org.springframework.data", "spring-data-commons"): ["org.springframework.data"],
    ("org.springframework.boot", "spring-boot"): ["org.springframework.boot"],
    ("org.springframework.boot", "spring-boot-autoconfigure"): ["org.springframework.boot.autoconfigure"],
    ("org.springframework.boot", "spring-boot-test"): ["org.springframework.boot.test"],
    ("org.springframework.security", "spring-security-core"): ["org.springframework.security.core",
                                                               "org.springframework.security.access"],
    ("org.springframework.security", "spring-security-web"): ["org.springframework.security.web"],
    ("org.hibernate.orm", "hibernate-core"): ["org.hibernate"],
    ("org.hibernate", "hibernate-core"): ["org.hibernate"],
    ("org.hibernate.validator", "hibernate-validator"): ["org.hibernate.validator"],
    ("jakarta.persistence", "jakarta.persistence-api"): ["jakarta.persistence"],
    ("jakarta.validation", "jakarta.validation-api"): ["jakarta.validation"],
    ("jakarta.xml.bind", "jakarta.xml.bind-api"): ["jakarta.xml.bind"],
    ("org.junit.jupiter", "junit-jupiter-api"): ["org.junit.jupiter.api"],
    ("junit", "junit"): ["org.junit", "junit.framework"],
    ("org.mockito", "mockito-core"): ["org.mockito"],
    ("org.assertj", "assertj-core"): ["org.assertj.core"],
    ("io.netty", "netty-codec-http"): ["io.netty.handler.codec.http"],
    ("org.bouncycastle", "bcprov-jdk18on"): ["org.bouncycastle"],
    ("org.bouncycastle", "bcprov-jdk15on"): ["org.bouncycastle"],
    ("ch.qos.logback", "logback-classic"): ["ch.qos.logback.classic"],
    ("ch.qos.logback", "logback-core"): ["ch.qos.logback.core"],
    ("org.slf4j", "slf4j-api"): ["org.slf4j"],
    ("com.h2database", "h2"): ["org.h2"],
    ("org.postgresql", "postgresql"): ["org.postgresql"],
    ("com.mysql", "mysql-connector-j"): ["com.mysql"],
    ("org.apache.tomcat.embed", "tomcat-embed-core"): ["org.apache.catalina", "org.apache.coyote", "org.apache.tomcat"],
}

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


def _valid_package(p: str) -> bool:
    return all(_IDENT.match(part) for part in p.split("."))


def candidate_packages(group: str, artifact: str, shared_group: bool) -> List[str]:
    curated = CURATED.get((group, artifact))
    if curated:
        return list(curated)
    out: List[str] = []
    last = group.rsplit(".", 1)[-1]
    stripped = re.sub(rf"^{re.escape(last)}[-_.]?", "", artifact)
    for suffix in (stripped, artifact):
        cand = f"{group}.{suffix.replace('-', '.').replace('_', '.')}".lower()
        cand = re.sub(r"\.(java|core|api|impl)$", "", cand) if suffix == artifact else cand
        if suffix and _valid_package(cand) and cand not in out:
            out.append(cand)
    return out


def package_index(components: Iterable[Tuple[str, str]]) -> Dict[Tuple[str, str], List[str]]:
    """``(groupId, artifactId)`` -> candidate Java package prefixes, for every Maven component."""
    comps = sorted(set(components))
    groups: Dict[str, int] = {}
    for g, _ in comps:
        groups[g] = groups.get(g, 0) + 1
    return {(g, a): candidate_packages(g, a, groups[g] > 1) for g, a in comps}


def attribute(type_fqn: str, index: Dict[Tuple[str, str], List[str]]) -> Set[Tuple[str, str]]:
    """Components whose longest matching package prefix covers ``type_fqn`` (empty = none or ambiguous)."""
    best_len, best = 0, set()
    for comp, prefixes in index.items():
        for p in prefixes:
            if type_fqn.startswith(p + "."):
                if len(p) > best_len:
                    best_len, best = len(p), {comp}
                elif len(p) == best_len:
                    best.add(comp)
    return best if len(best) == 1 else set()
