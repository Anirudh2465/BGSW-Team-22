import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));

export const shortSha = (sha?: string | null, n = 12) => (sha ? `${sha.slice(0, n)}…` : "—");

/** "pkg:npm/express@4.12.4" -> { name: "express", version: "4.12.4", eco: "npm" } */
export function parsePurl(purl: string) {
  const m = /^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:[?#].*)?$/.exec(purl);
  if (!m) return { eco: "", name: purl, version: "" };
  const path = decodeURIComponent(m[2]);
  return { eco: m[1], name: path.split("/").pop() || path, namespace: path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "", version: m[3] ? decodeURIComponent(m[3]) : "" };
}

export const repoName = (url: string) => url.replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\.git$/, "");

export const humanize = (s: string) => s.replace(/_gate$/, "").replace(/_/g, " ");

export function formatTime(iso?: string) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function downloadFile(name: string, content: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
