"use client";

import React, { useState, useEffect } from "react";
import { fetchRuns, createRun } from "../lib/api";

export default function HomePage() {
  const [repoUrl, setRepoUrl] = useState("https://github.com/example/sample-vulnerable-log4j");
  const [commitSha, setCommitSha] = useState("HEAD");
  const [loading, setLoading] = useState(false);
  const [runs, setRuns] = useState<any[]>([]);

  useEffect(() => {
    fetchRuns().then(setRuns);
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await createRun(repoUrl, commitSha);
      if (res.run_id) {
        window.location.href = `/runs/${res.run_id}`;
      }
    } catch (err) {
      alert("Failed to start pipeline: " + err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Hero / Submission Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-xl">
        <h1 className="text-2xl font-bold text-white mb-2">
          Autonomous Supply Chain Security Audit & Remediation
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl mb-6">
          Execute isolated sandbox clones, dependency tree discovery, offline scanning, deterministic risk scoring,
          pre-approval sandbox verification, and Ed25519 hash-chained auditing.
        </p>

        <form onSubmit={handleStartScan} className="flex flex-col sm:flex-row gap-4">
          <input
            type="text"
            required
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="Repository URL (e.g., https://github.com/org/repo)"
            className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <input
            type="text"
            value={commitSha}
            onChange={(e) => setCommitSha(e.target.value)}
            placeholder="Commit SHA (default: HEAD)"
            className="w-full sm:w-48 bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-3 rounded-xl transition cursor-pointer disabled:opacity-50"
          >
            {loading ? "Running Pipeline..." : "Audit Repository"}
          </button>
        </form>
      </div>

      {/* Active & Past Runs */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg">
        <h2 className="text-lg font-semibold text-white mb-4">Pipeline Execution History</h2>
        {runs.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-sm">
            No active runs. Submit a repository URL above to begin.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Run ID</th>
                  <th className="py-3 px-4">Target Repository</th>
                  <th className="py-3 px-4">Commit</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {runs.map((r) => (
                  <tr key={r.run_id} className="hover:bg-slate-850">
                    <td className="py-3 px-4 font-mono text-blue-400">{r.run_id}</td>
                    <td className="py-3 px-4 truncate max-w-xs">{r.repo_url}</td>
                    <td className="py-3 px-4 font-mono text-xs">{r.commit_sha}</td>
                    <td className="py-3 px-4">
                      <span className="bg-red-950 text-red-300 px-2.5 py-0.5 rounded-full text-xs font-semibold">
                        {r.findings_count} findings
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <a
                        href={`/runs/${r.run_id}`}
                        className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg transition"
                      >
                        View Dashboard →
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
