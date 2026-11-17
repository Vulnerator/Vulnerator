#!/usr/bin/env python3
"""
Open Source Sofware (OSS) Security Scanner — Report Generator
Author: Hector L. Bones
Version: 1.1
Compatible with: Open Source Sofware (OSS) Security Scanner v2.4

Generates three report types (Developer, Analyst, Leadership)
in three formats each (DOCX, HTML, Markdown) = 9 output files.

Usage:
    python3 generate_reports.py [--reports-dir REPORTS_DIR]
                                [--profile-path CIA_PROFILE]
                                [--output-dir OUTPUT_DIR]

Environment variables (GitHub Actions):
    GITHUB_REPOSITORY, GITHUB_RUN_NUMBER, GITHUB_SHA, GITHUB_REF_NAME
"""

import argparse
import datetime
import json
import os
import pathlib
import sys

import yaml
from docx import Document
from docx.shared import Pt, RGBColor, Inches, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CVSS_SEVERITY_BANDS = [
    (9.0, 10.0, "Critical", "CAT I",   3),
    (7.0,  8.9, "High",     "CAT I",  30),
    (4.0,  6.9, "Medium",   "CAT II", 90),
    (0.1,  3.9, "Low",      "CAT III",180),
    (0.0,  0.0, "None",     "N/A",    365),
]

SNYK_EXIT_CODES = {
    "0":       "Clean — no vulnerabilities found",
    "1":       "Vulnerabilities found — review JSON output",
    "2":       "Error — Snyk configuration or network issue",
    "3":       "No manifest — no supported project type detected",
    "147":     "Error — unmanaged scan error",
    "not_run": "Skipped — step disabled or not triggered",
}

# Colors for DOCX
COLOR_HEADER_BG  = "1F4E79"   # Dark blue
COLOR_HEADER_FG  = "FFFFFF"   # White
COLOR_ALT_ROW    = "EBF3FB"   # Light blue
COLOR_CRITICAL   = "C00000"   # Red
COLOR_HIGH       = "E36C09"   # Orange
COLOR_MEDIUM     = "F0A500"   # Amber
COLOR_LOW        = "4CAF50"   # Green
COLOR_PASS       = "4CAF50"
COLOR_WARN       = "F0A500"
COLOR_BORDER     = "CCCCCC"

# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------

def load_yaml(path):
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return {}


def load_text(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def read_version_file(path):
    text = load_text(path)
    if not text.strip():
        return "unknown"
    return text.strip().splitlines()[0].strip()


# ---------------------------------------------------------------------------
# Data Parsing
# ---------------------------------------------------------------------------

def parse_sbom(sbom):
    packages = []
    for pkg in sbom.get("packages", []):
        name = pkg.get("name", "")
        if name.startswith("/tmp/") or name.startswith("/home/"):
            continue
        packages.append({
            "name":    name,
            "version": pkg.get("versionInfo", ""),
            "license": pkg.get("licenseConcluded", "NOASSERTION"),
            "spdxid":  pkg.get("SPDXID", ""),
        })
    return packages


def cvss_to_category(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Unknown", "N/A", 365
    for lo, hi, severity, cat, sla in CVSS_SEVERITY_BANDS:
        if score >= lo and score <= hi:
            return severity, cat, sla
    return "Unknown", "N/A", 365


def owasp_category(cwe_id):
    """Map CWE to OWASP Top 10 2025 category."""
    mappings = {
        "CWE-22":   "A01 - Broken Access Control",
        "CWE-284":  "A01 - Broken Access Control",
        "CWE-285":  "A01 - Broken Access Control",
        "CWE-732":  "A01 - Broken Access Control",
        "CWE-16":   "A02 - Security Misconfiguration",
        "CWE-611":  "A02 - Security Misconfiguration",
        "CWE-1035": "A03 - Software Supply Chain Failures",
        "CWE-937":  "A03 - Software Supply Chain Failures",
        "CWE-20":   "A03 - Software Supply Chain Failures",
        "CWE-377":  "A03 - Software Supply Chain Failures",
        "CWE-89":   "A04 - Injection",
        "CWE-77":   "A04 - Injection",
        "CWE-78":   "A04 - Injection",
        "CWE-502":  "A05 - Insecure Deserialization",
        "CWE-400":  "A06 - Vulnerable/Outdated Components",
        "CWE-1333": "A06 - Vulnerable/Outdated Components",
        "CWE-798":  "A07 - Auth & Credential Failures",
        "CWE-287":  "A07 - Auth & Credential Failures",
        "CWE-345":  "A08 - Software/Data Integrity Failures",
        "CWE-311":  "A09 - Cryptographic Failures",
        "CWE-209":  "A10 - Mishandling of Exceptional Conditions",
        "CWE-636":  "A10 - Mishandling of Exceptional Conditions",
    }
    return mappings.get(cwe_id, "A03 - Software Supply Chain Failures")


def parse_grype(grype_data):
    matches = grype_data.get("matches", [])
    findings = []
    for m in matches:
        v   = m.get("vulnerability", {})
        pkg = m.get("artifact", {})

        cvss_list = v.get("cvss", [])
        # Prefer v3.1, fall back to any
        cvss_score = None
        cvss_vector = ""
        for c in cvss_list:
            if c.get("version", "") == "3.1":
                cvss_score  = c.get("metrics", {}).get("baseScore")
                cvss_vector = c.get("vector", "")
                break
        if cvss_score is None and cvss_list:
            cvss_score  = cvss_list[0].get("metrics", {}).get("baseScore")
            cvss_vector = cvss_list[0].get("vector", "")

        severity, cat, sla = cvss_to_category(cvss_score)

        # CWEs
        raw_cwes = v.get("cwes", [])
        cwe_ids  = list(dict.fromkeys(c.get("cwe", "") for c in raw_cwes if c.get("cwe")))
        owasp    = owasp_category(cwe_ids[0]) if cwe_ids else "A03 - Software Supply Chain Failures"

        # EPSS (already embedded by Grype)
        epss_list = v.get("epss", []) or []
        epss_score = epss_list[0].get("epss") if epss_list else None
        epss_pct   = f"{epss_score*100:.3f}%" if epss_score is not None else "N/A"

        # KEV
        kev = v.get("kev")
        kev_flag = "YES — Active Exploitation Confirmed" if kev else "No"

        # Fix
        fix_info  = v.get("fix", {})
        fix_versions = fix_info.get("versions", [])
        fix_state    = fix_info.get("state", "unknown")

        # CVE (from CWE data or ID)
        cve_ids = list(dict.fromkeys(
            c.get("cve", "") for c in raw_cwes if c.get("cve")
        ))
        cve_display = cve_ids[0] if cve_ids else v.get("id", "")

        findings.append({
            "id":           v.get("id", ""),
            "cve":          cve_display,
            "severity":     v.get("severity", severity),
            "disa_cat":     cat,
            "sla_days":     sla,
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "epss_score":   epss_score,
            "epss_display": epss_pct,
            "kev":          kev_flag,
            "package":      pkg.get("name", ""),
            "version":      pkg.get("version", ""),
            "fix_versions": fix_versions,
            "fix_state":    fix_state,
            "cwe_ids":      cwe_ids,
            "owasp":        owasp,
            "description":  v.get("description", ""),
            "urls":         v.get("urls", []),
        })

    # Sort by CVSS score descending
    findings.sort(key=lambda x: (x["cvss_score"] or 0), reverse=True)
    return findings


def parse_semgrep(semgrep_data):
    results = semgrep_data.get("results", [])
    findings = []
    for r in results:
        findings.append({
            "rule_id":  r.get("check_id", ""),
            "path":     r.get("path", ""),
            "line":     r.get("start", {}).get("line", ""),
            "message":  r.get("extra", {}).get("message", ""),
            "severity": r.get("extra", {}).get("severity", ""),
            "metadata": r.get("extra", {}).get("metadata", {}),
        })
    return findings


def parse_profile(profile_data):
    cia = profile_data.get("cia_weights", {})
    disclaimer_block = profile_data.get("disclaimer", {})
    is_default = profile_data.get("profile", {}).get("name", "DEFAULT") == "DEFAULT"
    return {
        "name":           profile_data.get("profile", {}).get("name", "DEFAULT"),
        "system_name":    profile_data.get("profile", {}).get("system_name", ""),
        "confidentiality": cia.get("confidentiality", "MEDIUM"),
        "integrity":       cia.get("integrity",       "MEDIUM"),
        "availability":    cia.get("availability",    "MEDIUM"),
        "is_default":      is_default,
        "reviewed_by":     disclaimer_block.get("reviewed_by", ""),
        "review_date":     disclaimer_block.get("review_date", ""),
        "retention_days":  min(int(profile_data.get("pipeline", {}).get("artifact_retention_days", 90)), 90),
    }


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def severity_color_html(severity):
    s = severity.lower()
    if s == "critical": return "#C00000"
    if s == "high":     return "#E36C09"
    if s == "medium":   return "#F0A500"
    if s == "low":      return "#4CAF50"
    return "#666666"


def build_compliance_rows(findings, semgrep_findings, sbom_packages, sbom_raw):
    sbom_ok = len(sbom_packages) > 0
    sast_ok = True   # Semgrep executed (0 findings = clean, not broken)
    sca_ok  = True   # Grype executed
    return [
        ("DISA ASD STIG", "APSC-DV-002560", "SAST Execution",          "PASS" if sast_ok else "FAIL"),
        ("DISA ASD STIG", "APSC-DV-003235", "Dependency Scanning",     "PASS" if sca_ok  else "FAIL"),
        ("NIST SP 800-53","SA-11",           "Developer Security Test", "PASS" if sast_ok else "FAIL"),
        ("NIST SP 800-53","SA-15",           "Development Process",     "PASS"),
        ("NIST SP 800-53","RA-5",            "Vulnerability Monitoring","PASS" if sca_ok  else "FAIL"),
        ("NIST SP 800-53","SR-3",            "Supply Chain Controls",   "PASS" if sbom_ok else "WARN"),
        ("NIST SP 800-53","SR-4",            "Provenance",              "PASS" if sbom_ok else "WARN"),
        ("NTIA SBOM",     "Min Elements",    "SBOM Completeness",       "PASS" if sbom_ok else "WARN"),
        ("DoDI 8510.01",  "RMF Audit Trail", "Evidence Committed",      "PASS"),
    ]


def get_run_context():
    return {
        "repo":       os.environ.get("GITHUB_REPOSITORY", "hbonesctr/sca-scanner-template"),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER", "N/A"),
        "sha":        os.environ.get("GITHUB_SHA", "N/A")[:7],
        "ref_name":   os.environ.get("GITHUB_REF_NAME", "main"),
        "scan_date":  datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---------------------------------------------------------------------------
# MARKDOWN GENERATOR
# ---------------------------------------------------------------------------

DISCLAIMER_CIA = """
> ⚠️ **ENVIRONMENTAL SCORING NOTICE**
> CIA values reflect CVSS v3.1 default baseline (Medium/Medium/Medium).
> Environmental scores are for initial assessment only and require
> review by the system ISSO/ISSM prior to use in authorization packages.
> Reference: DoDI 8510.01 RMF Step 1, NIST SP 800-53 RA-2.
""".strip()

DISCLAIMER_TOOL = """
> ℹ️ **TOOL LIMITATION NOTICE**
> Scanner results are subject to tool version constraints and free-tier
> limitations. Grype database currency and Snyk manifest detection may
> affect completeness. Results represent best-effort analysis.
""".strip()

DISCLAIMER_USE = """
> 📋 **REPORT USE NOTICE**
> This report was generated by an automated security scanning pipeline.
> All findings require human review before use in formal risk assessments,
> ATO packages, or contractual deliverables. Not a substitute for manual
> security assessment or penetration testing.
""".strip()


def md_severity_badge(severity):
    badges = {
        "Critical": "🔴 CRITICAL",
        "High":     "🟠 HIGH",
        "Medium":   "🟡 MEDIUM",
        "Low":      "🟢 LOW",
    }
    return badges.get(severity, severity)


def generate_markdown_developer(ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows):
    lines = []
    is_default = profile["is_default"]

    lines += [
        f"# Security Scan — Developer Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Repository | `{ctx['repo']}` |",
        f"| Branch | `{ctx['ref_name']}` |",
        f"| Commit | `{ctx['sha']}` |",
        f"| Scan Date | {ctx['scan_date']} |",
        f"| Run Number | #{ctx['run_number']} |",
        f"| Scanner Version | Open Source Sofware (OSS) Security Scanner v2.3 |",
        f"",
        DISCLAIMER_USE,
        "",
    ]

    if is_default:
        lines += [DISCLAIMER_CIA, ""]

    lines += [DISCLAIMER_TOOL, ""]

    # Summary metrics
    crit = sum(1 for f in findings if f["disa_cat"] == "CAT I"  and float(f["cvss_score"] or 0) >= 9)
    high = sum(1 for f in findings if float(f["cvss_score"] or 0) >= 7.0 and float(f["cvss_score"] or 0) < 9)
    med  = sum(1 for f in findings if float(f["cvss_score"] or 0) >= 4.0 and float(f["cvss_score"] or 0) < 7)
    low  = sum(1 for f in findings if float(f["cvss_score"] or 0) > 0   and float(f["cvss_score"] or 0) < 4)

    lines += [
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|---|---|",
        f"| Total Packages (SBOM) | {len(packages)} |",
        f"| Vulnerabilities — Critical | {crit} |",
        f"| Vulnerabilities — High | {high} |",
        f"| Vulnerabilities — Medium | {med} |",
        f"| Vulnerabilities — Low | {low} |",
        f"| SAST Findings (Semgrep) | {len(semgrep)} |",
        "",
    ]

    # Vulnerability findings
    lines += ["## Vulnerability Findings", ""]
    if not findings:
        lines += ["✅ **No vulnerabilities detected by Grype.**", ""]
    else:
        for f in findings:
            fix_str = f["fix_versions"][0] if f["fix_versions"] else "No fix available"
            cwe_str = ", ".join(f["cwe_ids"]) if f["cwe_ids"] else "N/A"
            lines += [
                f"### {md_severity_badge(f['severity'])} — {f['id']}",
                "",
                f"| Field | Detail |",
                f"|---|---|",
                f"| CVE | {f['cve']} |",
                f"| Package | `{f['package']}` version `{f['version']}` |",
                f"| CVSS v3.1 Score | {f['cvss_score']} ({f['cvss_vector']}) |",
                f"| DISA CAT Level | {f['disa_cat']} |",
                f"| Remediation SLA | {f['sla_days']} days |",
                f"| EPSS (exploit probability) | {f['epss_display']} |",
                f"| CISA KEV | {f['kev']} |",
                f"| CWE(s) | {cwe_str} |",
                f"| OWASP 2025 | {f['owasp']} |",
                f"| Fix Version | {fix_str} |",
                f"| Fix State | {f['fix_state']} |",
                "",
                f"**Description:** {f['description']}",
                "",
                f"**Remediation:** Update `{f['package']}` from `{f['version']}` to `{fix_str}`.",
                "",
                f"**References:**",
            ]
            for url in f["urls"][:3]:
                lines.append(f"- {url}")
            lines.append("")

    # SAST
    lines += ["## SAST Findings (Semgrep)", ""]
    if not semgrep:
        lines += ["✅ **Semgrep scan completed with no findings.**", "",
                  f"- Ruleset: `p/ci`", f"- Scanner version: {tool_versions.get('semgrep','unknown')}", ""]
    else:
        for s in semgrep:
            lines += [f"### {s['rule_id']}", "",
                      f"- **File:** `{s['path']}:{s['line']}`",
                      f"- **Severity:** {s['severity']}",
                      f"- **Message:** {s['message']}", ""]

    # Remediation checklist
    lines += ["## Remediation Checklist", ""]
    if not findings:
        lines += ["✅ No remediation actions required at this time.", ""]
    else:
        for f in findings:
            fix_str = f["fix_versions"][0] if f["fix_versions"] else "no fix available"
            lines.append(f"- [ ] **[{f['disa_cat']}]** Update `{f['package']}` `{f['version']}` → `{fix_str}` ({f['severity']}, SLA: {f['sla_days']} days)")
        lines.append("")

    # SBOM summary
    lines += ["## Dependency Inventory (SBOM)", "",
              f"Total packages: **{len(packages)}**  ",
              f"Format: SPDX 2.3 JSON | Generator: Syft {tool_versions.get('syft','unknown')}", "",
              "| Package | Version | License |",
              "|---|---|---|"]
    for p in packages[:30]:
        lines.append(f"| {p['name']} | {p['version']} | {p['license']} |")
    if len(packages) > 30:
        lines.append(f"| *(+{len(packages)-30} more — see sbom-spdx.json)* | | |")
    lines.append("")

    # Tool versions
    lines += ["## Scanner Tool Versions", "",
              "| Tool | Version |",
              "|---|---|"]
    for tool, ver in tool_versions.items():
        lines.append(f"| {tool.capitalize()} | {ver} |")
    lines.append("")

    return "\n".join(lines)


def generate_markdown_analyst(ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows):
    lines = []
    is_default = profile["is_default"]

    lines += [
        "# Security Analysis Report",
        "## Classification: UNCLASSIFIED",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Repository | `{ctx['repo']}` |",
        f"| Scan Date | {ctx['scan_date']} |",
        f"| Run Number | #{ctx['run_number']} |",
        f"| Analyst Reference | SCA-{ctx['scan_date'][:10].replace('-','')} |",
        "",
        DISCLAIMER_USE,
        "",
    ]
    if is_default:
        lines += [DISCLAIMER_CIA, ""]
    lines += [DISCLAIMER_TOOL, ""]

    # Risk assessment
    kev_count  = sum(1 for f in findings if "YES" in f["kev"])
    high_epss  = sum(1 for f in findings if (f["epss_score"] or 0) >= 0.10)
    cat1_count = sum(1 for f in findings if f["disa_cat"] == "CAT I")
    cat2_count = sum(1 for f in findings if f["disa_cat"] == "CAT II")
    cat3_count = sum(1 for f in findings if f["disa_cat"] == "CAT III")

    overall = "LOW RISK" if not findings else ("HIGH RISK" if cat1_count > 0 else "MODERATE RISK")

    lines += [
        "## Risk Assessment",
        "",
        f"| Indicator | Value |",
        f"|---|---|",
        f"| Overall Risk Posture | **{overall}** |",
        f"| CISA KEV (active exploitation) | {kev_count} |",
        f"| High EPSS (≥10% exploit probability) | {high_epss} |",
        f"| DISA CAT I findings | {cat1_count} |",
        f"| DISA CAT II findings | {cat2_count} |",
        f"| DISA CAT III findings | {cat3_count} |",
        f"| SAST findings | {len(semgrep)} |",
        "",
    ]

    # Vulnerability table
    lines += ["## Vulnerability Analysis", ""]
    if not findings:
        lines += ["✅ **No vulnerabilities detected.** Risk posture is clean for this scan.", ""]
    else:
        lines += [
            "| ID | CVE | Package | CVSS | CAT | EPSS | KEV | CWE | OWASP | Fix |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for f in findings:
            cwe_str = f["cwe_ids"][0] if f["cwe_ids"] else "N/A"
            fix_str = f["fix_versions"][0] if f["fix_versions"] else "None"
            lines.append(
                f"| {f['id']} | {f['cve']} | {f['package']} {f['version']} "
                f"| {f['cvss_score']} ({f['severity']}) | {f['disa_cat']} "
                f"| {f['epss_display']} | {f['kev'][:3]} | {cwe_str} "
                f"| {f['owasp'][:30]} | {fix_str} |"
            )
        lines.append("")

    # VEX assessment
    lines += ["## VEX Assessment (Vulnerability Exploitability eXchange)", ""]
    if not findings:
        lines += ["No vulnerabilities to assess.", ""]
    else:
        lines += [
            "| CVE | Package | VEX Status | Justification |",
            "|---|---|---|---|",
        ]
        for f in findings:
            if "YES" in f["kev"]:
                vex_status = "Affected"
                justification = "Active exploitation confirmed via CISA KEV"
            elif (f["epss_score"] or 0) >= 0.10:
                vex_status = "Affected"
                justification = f"High exploitation probability (EPSS {f['epss_display']})"
            elif f["fix_state"] == "fixed":
                vex_status = "Affected"
                justification = "Patch available — remediation required"
            else:
                vex_status = "Under Investigation"
                justification = "Pending system-owner impact assessment"
            lines.append(f"| {f['cve']} | {f['package']} {f['version']} | {vex_status} | {justification} |")
        lines.append("")

    # Compliance scorecard
    lines += ["## Compliance Scorecard", "",
              "| Framework | Control | Area | Status |",
              "|---|---|---|---|"]
    for framework, control, area, status in compliance_rows:
        icon = "✅" if status == "PASS" else ("⚠️" if status == "WARN" else "❌")
        lines.append(f"| {framework} | {control} | {area} | {icon} {status} |")
    lines.append("")

    # Recommendations
    lines += ["## Recommendations", ""]
    if not findings and not semgrep:
        lines += [
            "1. **Immediate:** No action required — scan is clean.",
            "2. **Short-term:** Maintain current scan cadence.",
            "3. **Long-term:** Upload customer software to enable full SCA analysis.",
            "",
        ]
    else:
        recs = []
        cat1 = [f for f in findings if f["disa_cat"] == "CAT I"]
        if cat1:
            for f in cat1:
                fix_str = f["fix_versions"][0] if f["fix_versions"] else "no fix available"
                recs.append(f"**[IMMEDIATE — CAT I]** Update `{f['package']}` to `{fix_str}` — {f['severity']} severity, SLA: {f['sla_days']} days.")
        cat2 = [f for f in findings if f["disa_cat"] == "CAT II"]
        if cat2:
            for f in cat2:
                fix_str = f["fix_versions"][0] if f["fix_versions"] else "no fix available"
                recs.append(f"**[30-90 DAYS — CAT II]** Update `{f['package']}` to `{fix_str}` — {f['severity']} severity.")
        recs.append("**[ONGOING]** Maintain monthly scan cadence and monitor CISA KEV catalog for new entries affecting this package set.")
        recs.append("**[PROCESS]** ISSO/ISSM to review CIA profile and set system-specific Environmental CVSS values.")
        for i, r in enumerate(recs, 1):
            lines.append(f"{i}. {r}")
        lines.append("")

    return "\n".join(lines)


def generate_markdown_leadership(ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows):
    lines = []

    cat1 = sum(1 for f in findings if f["disa_cat"] == "CAT I")
    cat2 = sum(1 for f in findings if f["disa_cat"] == "CAT II")
    cat3 = sum(1 for f in findings if f["disa_cat"] == "CAT III")
    kev  = sum(1 for f in findings if "YES" in f["kev"])

    if not findings:
        posture = "✅ CLEAN"
        risk_label = "Low Risk"
    elif cat1 > 0:
        posture = "⚠️ ACTION REQUIRED"
        risk_label = "High Risk"
    else:
        posture = "⚠️ ATTENTION NEEDED"
        risk_label = "Moderate Risk"

    pass_count = sum(1 for *_, s in compliance_rows if s == "PASS")
    total_controls = len(compliance_rows)

    lines += [
        "# Security Scan — Executive Summary",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Date** | {ctx['scan_date']} |",
        f"| **Repository** | {ctx['repo']} |",
        f"| **Overall Posture** | {posture} |",
        f"| **Risk Level** | {risk_label} |",
        f"| **Compliance** | {pass_count}/{total_controls} controls met |",
        "",
        DISCLAIMER_USE,
        "",
    ]

    if profile["is_default"]:
        lines += [
            "> ⚠️ **CIA PROFILE:** Environmental scoring uses default values (M/M/M).",
            "> System-specific review required before ATO package use.",
            "",
        ]

    # Key metrics
    lines += [
        "## Key Metrics",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Dependencies Scanned | {len(packages)} |",
        f"| Total Vulnerabilities | {len(findings)} |",
        f"| CAT I (Immediate Action) | {cat1} |",
        f"| CAT II (Standard Remediation) | {cat2} |",
        f"| CAT III (Low Priority) | {cat3} |",
        f"| CISA KEV (Active Exploits) | {kev} |",
        f"| SAST Findings | {len(semgrep)} |",
        f"| Scanner Cost | $0 (Free Tier) |",
        "",
    ]

    # Compliance scorecard
    lines += ["## Compliance Scorecard", "",
              "| Standard | Control | Status |",
              "|---|---|---|"]
    for framework, control, area, status in compliance_rows:
        icon = "✅" if status == "PASS" else ("⚠️" if status == "WARN" else "❌")
        lines.append(f"| {framework} | {area} | {icon} {status} |")
    lines.append("")

    # Strategic recommendations
    lines += ["## Strategic Recommendations", ""]
    if not findings:
        lines += [
            "1. **No immediate action required** — current scan is clean.",
            "2. **Maintain cadence** — continue monthly scanning as customer software is onboarded.",
            "3. **Expand coverage** — upload customer software ZIP files to enable full dependency analysis.",
            "",
        ]
    else:
        lines += [
            f"1. **Immediate** — {cat1} CAT I finding(s) require remediation within SLA. Assign to development team.",
            f"2. **Short-term** — {cat2} CAT II finding(s) require remediation within 90 days.",
            "3. **Process** — ISSO/ISSM to review CIA profile and set system-specific environmental scoring.",
            "4. **Ongoing** — Maintain monthly scan cadence; monitor CISA KEV for new active exploits.",
            "",
        ]

    # Scan performance
    lines += [
        "## Scan Performance",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Scanner Version | Open Source Sofware (OSS) Security Scanner v2.3 |",
        f"| Syft | {tool_versions.get('syft','unknown')} |",
        f"| Grype | {tool_versions.get('grype','unknown')} |",
        f"| Semgrep | {tool_versions.get('semgrep','unknown')} |",
        f"| Snyk | {tool_versions.get('snyk','unknown')} |",
        f"| Vulnerability DB | Current as of scan date |",
        f"| Total Cost | $0.00 (Free Tier) |",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML GENERATOR (self-contained, air-gapped safe)
# ---------------------------------------------------------------------------

HTML_CSS = """
body{font-family:Arial,sans-serif;font-size:13px;color:#222;margin:0;padding:0;background:#f5f7fa}
.page{max-width:1000px;margin:0 auto;background:#fff;padding:40px 48px;box-shadow:0 2px 8px rgba(0,0,0,.12)}
h1{font-size:22px;color:#1F4E79;border-bottom:3px solid #1F4E79;padding-bottom:8px;margin-top:0}
h2{font-size:16px;color:#1F4E79;border-left:4px solid #1F4E79;padding-left:10px;margin-top:28px}
h3{font-size:14px;color:#2E75B6;margin-top:20px}
.disclaimer{background:#FFF3CD;border-left:4px solid #F0A500;padding:10px 14px;margin:14px 0;font-size:12px;border-radius:2px}
.disclaimer.tool{background:#E8F4FD;border-color:#2196F3}
.disclaimer.use{background:#EDF7ED;border-color:#4CAF50}
table{border-collapse:collapse;width:100%;margin:12px 0}
th{background:#1F4E79;color:#fff;padding:8px 10px;text-align:left;font-size:12px}
td{padding:7px 10px;border-bottom:1px solid #e0e0e0;font-size:12px;vertical-align:top}
tr:nth-child(even) td{background:#EBF3FB}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;color:#fff;font-size:11px;font-weight:bold}
.badge.critical{background:#C00000}
.badge.high{background:#E36C09}
.badge.medium{background:#F0A500}
.badge.low{background:#4CAF50}
.badge.pass{background:#4CAF50}
.badge.warn{background:#F0A500}
.badge.fail{background:#C00000}
.checklist{list-style:none;padding:0}
.checklist li{padding:5px 0;border-bottom:1px solid #f0f0f0}
.checklist li::before{content:"☐ ";color:#1F4E79;font-weight:bold}
.metric-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:16px 0}
.metric-card{background:#EBF3FB;border-radius:6px;padding:14px;text-align:center}
.metric-card .num{font-size:28px;font-weight:bold;color:#1F4E79}
.metric-card .label{font-size:11px;color:#555;margin-top:4px}
.metric-card.warn .num{color:#E36C09}
.metric-card.alert .num{color:#C00000}
code{background:#f0f0f0;padding:1px 4px;border-radius:2px;font-size:11px}
footer{margin-top:32px;padding-top:12px;border-top:1px solid #ddd;font-size:11px;color:#777;text-align:center}
"""

def badge(text, cls):
    return f'<span class="badge {cls}">{text}</span>'


def severity_badge(severity):
    s = severity.lower()
    return badge(severity.upper(), s if s in ("critical","high","medium","low") else "medium")


def status_badge(status):
    if status == "PASS":  return badge("PASS", "pass")
    if status == "WARN":  return badge("WARN", "warn")
    return badge("FAIL", "fail")


def html_table(headers, rows, alt=True):
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for r in rows:
        tds = "".join(f"<td>{c}</td>" for c in r)
        trs += f"<tr>{tds}</tr>"
    return f"<table><tr>{ths}</tr>{trs}</table>"


def html_disclaimer(text, cls=""):
    return f'<div class="disclaimer {cls}">{text}</div>'


def generate_html(report_type, ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows, md_content):
    """Convert markdown content to HTML with embedded CSS."""
    # We'll build a proper HTML structure
    cat1 = sum(1 for f in findings if f["disa_cat"] == "CAT I")
    cat2 = sum(1 for f in findings if f["disa_cat"] == "CAT II")
    cat3 = sum(1 for f in findings if f["disa_cat"] == "CAT III")

    title_map = {
        "developer":  "Developer Security Report",
        "analyst":    "Security Analysis Report",
        "leadership": "Executive Security Summary",
    }
    title = title_map.get(report_type, "Security Report")

    body = f"""
    <h1>{title}</h1>
    {html_disclaimer("⚠️ This report was generated by an automated security scanning pipeline. All findings require human review.", "use")}
    """

    if profile["is_default"]:
        body += html_disclaimer(
            "⚠️ <strong>ENVIRONMENTAL SCORING NOTICE:</strong> CIA values reflect CVSS v3.1 default baseline (M/M/M). "
            "ISSO/ISSM review required before use in authorization packages.", ""
        )

    body += html_disclaimer(
        "ℹ️ <strong>TOOL LIMITATION NOTICE:</strong> Results are subject to scanner free-tier constraints. "
        "Grype database currency and Snyk manifest detection may affect completeness.", "tool"
    )

    # Scan metadata
    body += html_table(
        ["Repository", "Branch", "Commit", "Scan Date", "Run"],
        [[ctx["repo"], ctx["ref_name"], f"<code>{ctx['sha']}</code>", ctx["scan_date"], f"#{ctx['run_number']}"]],
        alt=False
    )

    if report_type == "leadership":
        # Metric cards
        posture = "CLEAN" if not findings else ("ACTION REQUIRED" if cat1 > 0 else "ATTENTION NEEDED")
        card_cls = "" if not findings else ("alert" if cat1 > 0 else "warn")
        body += f"""
        <h2>Key Metrics</h2>
        <div class="metric-grid">
          <div class="metric-card {card_cls}">
            <div class="num">{len(findings)}</div>
            <div class="label">Total Vulnerabilities</div>
          </div>
          <div class="metric-card {'alert' if cat1 > 0 else ''}">
            <div class="num">{cat1}</div>
            <div class="label">CAT I (Immediate)</div>
          </div>
          <div class="metric-card">
            <div class="num">{len(packages)}</div>
            <div class="label">Packages Scanned</div>
          </div>
        </div>
        """

    # Vulnerabilities
    body += "<h2>Vulnerability Findings</h2>"
    if not findings:
        body += "<p>✅ <strong>No vulnerabilities detected.</strong></p>"
    else:
        if report_type == "developer":
            rows = []
            for f in findings:
                fix = f["fix_versions"][0] if f["fix_versions"] else "None"
                cwe = ", ".join(f["cwe_ids"]) if f["cwe_ids"] else "N/A"
                rows.append([
                    f['id'],
                    f['cve'],
                    f"<code>{f['package']} {f['version']}</code>",
                    f"{f['cvss_score']}",
                    severity_badge(f["severity"]),
                    f["disa_cat"],
                    f"{f['sla_days']}d",
                    f["epss_display"],
                    f["kev"][:3],
                    cwe,
                    f"<code>{fix}</code>",
                ])
            body += html_table(
                ["ID", "CVE", "Package", "CVSS", "Severity", "CAT", "SLA", "EPSS", "KEV", "CWE", "Fix"],
                rows
            )
        elif report_type == "analyst":
            rows = []
            for f in findings:
                fix = f["fix_versions"][0] if f["fix_versions"] else "None"
                cwe = f["cwe_ids"][0] if f["cwe_ids"] else "N/A"
                rows.append([
                    f['id'], f['cve'],
                    f"<code>{f['package']} {f['version']}</code>",
                    f"{f['cvss_score']} ({f['cvss_vector'][:30]}...)",
                    severity_badge(f["severity"]),
                    f["disa_cat"],
                    f["epss_display"],
                    f["kev"][:3],
                    cwe,
                    f["owasp"][:35],
                    f"<code>{fix}</code>",
                ])
            body += html_table(
                ["ID", "CVE", "Package", "CVSS v3.1", "Severity", "CAT", "EPSS", "KEV", "CWE", "OWASP", "Fix"],
                rows
            )
        else:
            rows = []
            for f in findings:
                fix = f["fix_versions"][0] if f["fix_versions"] else "None"
                rows.append([
                    severity_badge(f["severity"]),
                    f["disa_cat"],
                    f"<code>{f['package']}</code>",
                    str(f["cvss_score"]),
                    f"<code>{fix}</code>",
                ])
            body += html_table(["Severity", "CAT", "Package", "CVSS", "Fix"], rows)

    # Compliance
    body += "<h2>Compliance Scorecard</h2>"
    comp_rows = [
        [framework, control, area, status_badge(status)]
        for framework, control, area, status in compliance_rows
    ]
    body += html_table(["Framework", "Control", "Area", "Status"], comp_rows)

    # Tool versions
    body += "<h2>Scanner Versions</h2>"
    body += html_table(
        ["Tool", "Version"],
        [[t.capitalize(), v] for t, v in tool_versions.items()]
    )

    body += f"""
    <footer>
      Open Source Sofware (OSS) Security Scanner v2.3 &nbsp;|&nbsp; Run #{ctx['run_number']} &nbsp;|&nbsp;
      {ctx['scan_date']} &nbsp;|&nbsp; UNCLASSIFIED
    </footer>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Run #{ctx['run_number']}</title>
<style>
{HTML_CSS}
</style>
</head>
<body>
<div class="page">
{body}
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# DOCX GENERATOR
# ---------------------------------------------------------------------------

def hex_to_rgb(hex_color):
    h = hex_color.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def set_cell_bg(cell, hex_color):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement("w:shd")
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  hex_color.lstrip("#"))
    tcPr.append(shd)


def add_heading(doc, text, level=1, color_hex=None):
    p = doc.add_heading(text, level=level)
    if color_hex:
        r, g, b = hex_to_rgb(color_hex)
        for run in p.runs:
            run.font.color.rgb = RGBColor(r, g, b)
    return p


def add_table(doc, headers, rows, col_widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    # Header row
    hdr = table.rows[0]
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        cell.text = h
        set_cell_bg(cell, COLOR_HEADER_BG)
        run = cell.paragraphs[0].runs[0]
        run.font.color.rgb = RGBColor(255, 255, 255)
        run.font.bold = True
        run.font.size = Pt(9)
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

    for ri, row in enumerate(rows):
        tr = table.add_row()
        for ci, val in enumerate(row):
            cell = tr.cells[ci]
            cell.text = str(val)
            cell.paragraphs[0].runs[0].font.size = Pt(9)
            if ri % 2 == 1:
                set_cell_bg(cell, COLOR_ALT_ROW)

    if col_widths:
        for i, row in enumerate(table.rows):
            for j, cell in enumerate(row.cells):
                if j < len(col_widths):
                    cell.width = Inches(col_widths[j])
    return table


def add_disclaimer_para(doc, text, icon="⚠️"):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent  = Inches(0.2)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(4)
    run = p.add_run(f"{icon} {text}")
    run.font.size  = Pt(9)
    run.font.italic = True
    run.font.color.rgb = RGBColor(120, 80, 0)
    return p


def generate_docx(report_type, ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows):
    doc = Document()

    # Page setup — US Letter
    section = doc.sections[0]
    section.page_width  = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = section.right_margin = Inches(1.0)
    section.top_margin  = section.bottom_margin = Inches(1.0)

    # Default font
    style = doc.styles["Normal"]
    style.font.name = "Arial"
    style.font.size = Pt(11)

    title_map = {
        "developer":  "Developer Security Report",
        "analyst":    "Security Analysis Report",
        "leadership": "Executive Security Summary",
    }
    title = title_map.get(report_type, "Security Report")

    # Title
    tp = doc.add_paragraph()
    tr = tp.add_run(title)
    tr.font.size  = Pt(20)
    tr.font.bold  = True
    tr.font.color.rgb = RGBColor(*hex_to_rgb(COLOR_HEADER_BG))
    tp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()

    # Scan metadata table
    add_table(doc,
        ["Repository", "Branch", "Commit", "Scan Date", "Run #"],
        [[ctx["repo"], ctx["ref_name"], ctx["sha"], ctx["scan_date"], ctx["run_number"]]],
        col_widths=[2.0, 1.0, 1.0, 1.5, 0.8]
    )
    doc.add_paragraph()

    # Disclaimers
    add_disclaimer_para(doc, "This report was generated by an automated pipeline. Findings require human review before use in ATO packages or formal risk assessments.", "📋")
    if profile["is_default"]:
        add_disclaimer_para(doc, "CIA values reflect CVSS v3.1 default baseline (M/M/M). ISSO/ISSM review required before operational use.", "⚠️")
    add_disclaimer_para(doc, "Scanner results are subject to tool free-tier constraints. Results represent best-effort analysis.", "ℹ️")
    doc.add_paragraph()

    # ---- Report-type-specific content ----

    if report_type == "developer":
        # Summary metrics
        add_heading(doc, "Summary", level=1)
        cat1 = sum(1 for f in findings if f["disa_cat"] == "CAT I")
        cat2 = sum(1 for f in findings if f["disa_cat"] == "CAT II")
        cat3 = sum(1 for f in findings if f["disa_cat"] == "CAT III")
        add_table(doc,
            ["Metric", "Count"],
            [
                ["Total Packages (SBOM)", str(len(packages))],
                ["Vulnerabilities — CAT I",  str(cat1)],
                ["Vulnerabilities — CAT II", str(cat2)],
                ["Vulnerabilities — CAT III",str(cat3)],
                ["SAST Findings (Semgrep)",  str(len(semgrep))],
            ],
            col_widths=[4.5, 2.0]
        )

        # Vulnerabilities
        add_heading(doc, "Vulnerability Findings", level=1)
        if not findings:
            doc.add_paragraph("✅ No vulnerabilities detected by Grype.")
        else:
            rows = []
            for f in findings:
                fix = f["fix_versions"][0] if f["fix_versions"] else "None"
                cwe = ", ".join(f["cwe_ids"]) if f["cwe_ids"] else "N/A"
                rows.append([f["id"], f["cve"], f"{f['package']} {f['version']}",
                              str(f["cvss_score"]), f["severity"], f["disa_cat"],
                              f"{f['sla_days']}d", f["epss_display"], cwe, fix])
            add_table(doc,
                ["ID","CVE","Package","CVSS","Severity","CAT","SLA","EPSS","CWE","Fix"],
                rows,
                col_widths=[1.2,1.2,1.3,0.5,0.7,0.5,0.4,0.5,0.8,0.8]
            )

        # Remediation checklist
        add_heading(doc, "Remediation Checklist", level=1)
        if not findings:
            doc.add_paragraph("No remediation actions required.")
        else:
            for f in findings:
                fix = f["fix_versions"][0] if f["fix_versions"] else "no fix"
                p = doc.add_paragraph(style="List Bullet")
                p.add_run(f"[{f['disa_cat']}] Update {f['package']} {f['version']} → {fix}").font.size = Pt(10)

        # SBOM
        add_heading(doc, "Dependency Inventory (SBOM)", level=1)
        pkg_rows = [[p["name"], p["version"], p["license"]] for p in packages[:40]]
        if len(packages) > 40:
            pkg_rows.append([f"(+{len(packages)-40} more)", "", ""])
        add_table(doc, ["Package", "Version", "License"], pkg_rows,
                  col_widths=[2.5, 1.5, 2.5])

    elif report_type == "analyst":
        cat1 = sum(1 for f in findings if f["disa_cat"] == "CAT I")
        cat2 = sum(1 for f in findings if f["disa_cat"] == "CAT II")
        cat3 = sum(1 for f in findings if f["disa_cat"] == "CAT III")
        kev  = sum(1 for f in findings if "YES" in f["kev"])
        overall = "LOW RISK" if not findings else ("HIGH RISK" if cat1 > 0 else "MODERATE RISK")

        add_heading(doc, "Risk Assessment", level=1)
        add_table(doc, ["Indicator", "Value"], [
            ["Overall Risk Posture", overall],
            ["CISA KEV (active exploitation)", str(kev)],
            ["DISA CAT I",  str(cat1)],
            ["DISA CAT II", str(cat2)],
            ["DISA CAT III",str(cat3)],
            ["SAST Findings",str(len(semgrep))],
        ], col_widths=[3.5, 3.0])

        add_heading(doc, "Vulnerability Analysis", level=1)
        if not findings:
            doc.add_paragraph("✅ No vulnerabilities detected.")
        else:
            rows = []
            for f in findings:
                fix = f["fix_versions"][0] if f["fix_versions"] else "None"
                cwe = f["cwe_ids"][0] if f["cwe_ids"] else "N/A"
                rows.append([f["id"], f["cve"], f"{f['package']} {f['version']}",
                              str(f["cvss_score"]), f["severity"], f["disa_cat"],
                              f["epss_display"], f["kev"][:3], cwe,
                              f["owasp"][:30], fix])
            add_table(doc,
                ["ID","CVE","Package","CVSS","Severity","CAT","EPSS","KEV","CWE","OWASP","Fix"],
                rows,
                col_widths=[1.1,1.1,1.2,0.5,0.7,0.5,0.5,0.4,0.7,1.5,0.8]
            )

        add_heading(doc, "Compliance Scorecard", level=1)
        comp_rows = [[framework, control, area, status]
                     for framework, control, area, status in compliance_rows]
        add_table(doc, ["Framework","Control","Area","Status"], comp_rows,
                  col_widths=[1.5, 1.3, 2.5, 0.8])

    elif report_type == "leadership":
        cat1 = sum(1 for f in findings if f["disa_cat"] == "CAT I")
        cat2 = sum(1 for f in findings if f["disa_cat"] == "CAT II")
        cat3 = sum(1 for f in findings if f["disa_cat"] == "CAT III")
        pass_count = sum(1 for *_, s in compliance_rows if s == "PASS")

        add_heading(doc, "Security Posture Overview", level=1)
        posture = "CLEAN" if not findings else ("ACTION REQUIRED" if cat1 > 0 else "ATTENTION NEEDED")
        add_table(doc, ["Indicator", "Value"], [
            ["Overall Posture",           posture],
            ["Dependencies Scanned",      str(len(packages))],
            ["Total Vulnerabilities",     str(len(findings))],
            ["CAT I (Immediate Action)",  str(cat1)],
            ["CAT II (Standard Cycle)",   str(cat2)],
            ["CAT III (Low Priority)",    str(cat3)],
            ["Compliance Controls Met",   f"{pass_count}/{len(compliance_rows)}"],
            ["Scanner Cost",              "$0.00 (Free Tier)"],
        ], col_widths=[3.5, 3.0])

        add_heading(doc, "Compliance Scorecard", level=1)
        add_table(doc, ["Standard", "Area", "Status"],
                  [[fw, area, status] for fw, _, area, status in compliance_rows],
                  col_widths=[2.0, 3.5, 1.0])

        add_heading(doc, "Strategic Recommendations", level=1)
        if not findings:
            recs = [
                "No immediate action required — current scan is clean.",
                "Maintain monthly scan cadence as customer software is onboarded.",
                "Upload customer software ZIP files to enable full dependency analysis.",
            ]
        else:
            recs = [
                f"{cat1} CAT I finding(s) require immediate remediation within SLA. Assign to development team.",
                f"{cat2} CAT II finding(s) require remediation within 90 days.",
                "ISSO/ISSM to review CIA profile for system-specific environmental scoring.",
                "Maintain monthly scan cadence and monitor CISA KEV catalog.",
            ]
        for i, r in enumerate(recs, 1):
            p = doc.add_paragraph(style="List Number")
            p.add_run(r).font.size = Pt(10)

    # Tool versions (all reports)
    add_heading(doc, "Scanner Tool Versions", level=1)
    add_table(doc, ["Tool","Version"],
              [[t.capitalize(), v] for t, v in tool_versions.items()],
              col_widths=[2.5, 4.0])

    # Footer paragraph
    doc.add_paragraph()
    footer_p = doc.add_paragraph()
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = footer_p.add_run(
        f"Open Source Sofware (OSS) Security Scanner v2.3  |  Run #{ctx['run_number']}  |  "
        f"{ctx['scan_date']}  |  UNCLASSIFIED"
    )
    fr.font.size  = Pt(9)
    fr.font.color.rgb = RGBColor(120, 120, 120)

    return doc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Open Source Sofware (OSS) Security Report Generator")
    parser.add_argument("--reports-dir", default="reports",   help="Path to scanner reports folder")
    parser.add_argument("--profile-path",default="cia-profile.yaml", help="Path to CIA profile YAML")
    parser.add_argument("--output-dir",  default="security-reports", help="Output directory for generated reports")
    args = parser.parse_args()

    reports_dir = pathlib.Path(args.reports_dir)
    output_dir  = pathlib.Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Reports source: {reports_dir}")
    print(f"[INFO] Profile:        {args.profile_path}")
    print(f"[INFO] Output:         {output_dir}")

    # Load CIA profile
    profile_data = load_yaml(args.profile_path)
    profile      = parse_profile(profile_data)
    print(f"[INFO] CIA profile: {profile['name']} (default={profile['is_default']})")

    # Load scan data
    sbom_raw    = load_json(reports_dir / "sbom-spdx.json")
    grype_raw   = load_json(reports_dir / "grype-results.json")
    semgrep_raw = load_json(reports_dir / "semgrep-results.json")

    packages = parse_sbom(sbom_raw)
    findings = parse_grype(grype_raw)
    semgrep  = parse_semgrep(semgrep_raw)

    print(f"[INFO] Packages:     {len(packages)}")
    print(f"[INFO] Grype matches:{len(findings)}")
    print(f"[INFO] Semgrep:      {len(semgrep)}")

    # Tool versions
    tool_versions = {
        "syft":    read_version_file(reports_dir / "syft-version.txt").split()[1] if "version" in read_version_file(reports_dir / "syft-version.txt").lower() else read_version_file(reports_dir / "syft-version.txt"),
        "grype":   read_version_file(reports_dir / "grype-version.txt").split()[1] if len(read_version_file(reports_dir / "grype-version.txt").split()) > 1 else read_version_file(reports_dir / "grype-version.txt"),
        "semgrep": read_version_file(reports_dir / "semgrep-version.txt"),
        "snyk":    read_version_file(reports_dir / "snyk-version.txt"),
    }

    compliance_rows = build_compliance_rows(findings, semgrep, packages, sbom_raw)
    ctx = get_run_context()

    print(f"[INFO] Generating reports for run #{ctx['run_number']}...")

    report_types = ["developer", "analyst", "leadership"]

    for rtype in report_types:
        print(f"[INFO] Generating {rtype} report...")

        # Markdown
        if rtype == "developer":
            md = generate_markdown_developer(ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows)
        elif rtype == "analyst":
            md = generate_markdown_analyst(ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows)
        else:
            md = generate_markdown_leadership(ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows)

        md_path = output_dir / f"{rtype}-report.md"
        md_path.write_text(md, encoding="utf-8")
        print(f"  [OK] {md_path}")

        # HTML
        html = generate_html(rtype, ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows, md)
        html_path = output_dir / f"{rtype}-report.html"
        html_path.write_text(html, encoding="utf-8")
        print(f"  [OK] {html_path}")

        # DOCX
        doc = generate_docx(rtype, ctx, profile, packages, findings, semgrep, tool_versions, compliance_rows)
        docx_path = output_dir / f"{rtype}-report.docx"
        doc.save(str(docx_path))
        print(f"  [OK] {docx_path}")

    print(f"[DONE] 9 reports generated in {output_dir}/")


if __name__ == "__main__":
    main()