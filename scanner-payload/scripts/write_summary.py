#!/usr/bin/env python3
"""Write summary.json for the project page's Security Scan section.

Usage:
    python3 write_summary.py --reports-dir REPORTS --out SUMMARY_JSON
                             --version VERSION [--release-asset NAME]

Reads the same scanner outputs as generate_reports.py (Syft SPDX SBOM,
Grype JSON, Semgrep JSON) and writes counts the page can show without
loading the full reports.
"""

import argparse
import datetime
import json
import os
import pathlib


def load_json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return {}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--reports-dir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--release-asset", default="")
    a = p.parse_args()

    rd = pathlib.Path(a.reports_dir)
    sbom = load_json(rd / "sbom-spdx.json")
    grype = load_json(rd / "grype-results.json")
    semgrep = load_json(rd / "semgrep-results.json")

    packages = [x for x in sbom.get("packages", []) if not x.get("name", "").startswith(("/tmp/", "/home/"))]

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    kev = 0
    fixable = 0
    for m in grype.get("matches", []):
        v = m.get("vulnerability", {})
        s = (v.get("severity") or "Unknown").capitalize()
        sev[s if s in sev else "Unknown"] += 1
        if v.get("kev") or v.get("knownExploited"):
            kev += 1
        if (v.get("fix") or {}).get("state") == "fixed":
            fixable += 1

    sast = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for r in semgrep.get("results", []):
        s = (r.get("extra", {}).get("severity") or "INFO").upper()
        sast[s if s in sast else "INFO"] += 1

    def tool(name):
        try:
            return (rd / f"{name}-version.txt").read_text(encoding="utf-8").strip().split()[-1]
        except Exception:
            return "unknown"

    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    summary = {
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": a.version,
        "commit": os.environ.get("GITHUB_SHA", "")[:7],
        "run_url": f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else "",
        "release_asset": a.release_asset,
        "components": len(packages),
        "dependency_findings": sum(sev.values()),
        "by_severity": sev,
        "kev": kev,
        "fixable": fixable,
        "code_findings": sum(sast.values()),
        "code_by_severity": sast,
        "semgrep_errors": len(semgrep.get("errors", [])),
        "tools": {"syft": tool("syft"), "grype": tool("grype"), "semgrep": tool("semgrep")},
    }
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
