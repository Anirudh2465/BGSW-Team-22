import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { HealthPill } from "../components/HealthPill";

export const metadata: Metadata = {
  title: "Supply Chain Guardian",
  description: "Sandboxed software supply chain vulnerability detection, verification and remediation",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="flex h-screen flex-col overflow-hidden bg-canvas font-sans text-ink">
        <header className="z-40 flex h-14 shrink-0 items-center justify-between border-b border-line bg-canvas/80 px-4 backdrop-blur sm:px-6">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2.5">
              <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent/15 ring-1 ring-accent/30">
                <svg viewBox="0 0 24 24" className="h-4 w-4 text-accent-soft" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />
                  <path d="M9 12l2 2 4-4" />
                </svg>
              </span>
              <span className="text-sm font-semibold tracking-tight">Supply Chain Guardian</span>
            </Link>
            <nav className="hidden items-center gap-1 text-sm sm:flex">
              <Link href="/" className="rounded-md px-2.5 py-1.5 text-ink-soft transition hover:bg-white/[0.06] hover:text-ink">
                Scans
              </Link>
            </nav>
          </div>
          <HealthPill />
        </header>
        <main className="min-h-0 flex-1">{children}</main>
      </body>
    </html>
  );
}
