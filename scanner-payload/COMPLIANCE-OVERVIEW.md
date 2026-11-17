# Open Source Sofware (OSS) Security Scanner — Compliance Overview

**Project:** Open Source Sofware (OSS) Security Scanner  
**Author:** Hector L. Bones  
**Last Reviewed:** 2026-05-09  
**Version:** 1.0  
**Audience:** Program Managers, Contracting Officers, Reviewing Authorities,
ISSOs, Auditors

-----

## What This Is

The Open Source Sofware (OSS) Security Scanner is an automated inspection system for open source
and customer-provided software. Every time a software package is submitted
for evaluation, the scanner runs a structured series of security checks and
produces documented evidence of those checks — automatically, with no manual
steps required after submission.

The scanner runs entirely inside GitHub Actions, a cloud-based automation
platform. No servers, no local installations, and no elevated system
privileges are required to operate it.

-----

## Why It Exists

Federal policy requires that software used or procured by DoD be inspected
for known vulnerabilities before deployment, and that evidence of those
inspections be retained for audit. Specifically:

- **Executive Order 14028** (May 2021) requires Software Bills of Materials
  for software sold to the federal government and mandates improved software
  supply chain security practices.
- **NIST SP 800-53 Rev 5** controls SA-11, SA-15, RA-5, SR-3, SR-4, and SI-2
  require developer security testing, dependency scanning, provenance
  documentation, and flaw remediation tracking.
- **DISA Application Security and Development STIG** controls APSC-DV-002560
  and APSC-DV-003235 require static application security testing and
  dependency scanning to be performed and documented.

Historically, satisfying these requirements required expensive licensed tools,
dedicated security engineering staff, and days of effort per software package.
This scanner performs equivalent analysis automatically, in under ten minutes,
at zero recurring cost, and produces audit-ready documentation as a direct
output of each scan.

-----

## What Happens During a Scan

When a software package is submitted, the scanner automatically performs
five activities in sequence:

**1. Extraction and Inventory**  
The submitted package is safely unpacked and inventoried. Every file is
catalogued. Every package manifest (the files that declare software
dependencies) is identified and recorded.

**2. Software Bill of Materials Generation**  
A complete inventory of all software components is produced in SPDX 2.3
format — the DoD-preferred standard. This SBOM satisfies all seven NTIA
minimum elements and provides a traceable record of exactly what software
was present at the time of inspection.

**3. Dependency Vulnerability Scanning**  
Every identified software component is checked against current vulnerability
databases including the National Vulnerability Database, GitHub Security
Advisories, and the CISA Known Exploited Vulnerabilities catalog. Two
independent scanning tools (Grype and Snyk) run in parallel for coverage
redundancy.

**4. Static Application Security Testing**  
The source code itself is analyzed for security weaknesses using Semgrep
with the standard CI ruleset, and CodeQL for semantic analysis. This
identifies issues in the code logic, not just in its dependencies.

**5. Results Consolidation and Publication**  
All findings are consolidated into structured output files, committed to
the repository for permanent record, and published as a dated release
archive available for download. Three audience-specific reports are
generated automatically.

-----

## The Three Reports

Each scan produces three versions of the same findings, written for
different readers. All three are generated automatically from the same
scan data.

### Developer Report

Written for software engineers and DevOps teams. Contains specific package
names, version numbers, remediation steps, affected code locations, and
a prioritized checklist of actions. The developer reads this report and
knows exactly what to update and by when.

### Analyst Report

Written for security analysts and compliance officers. Contains CVSS
vulnerability scores, CWE root cause classifications, OWASP category
mappings, exploitability assessments in VEX format, and a full compliance
scorecard mapped to DISA STIG and NIST SP 800-53 controls. The analyst
reads this report and can assess risk posture and compliance gaps.

### Leadership Report

Written for program managers, contracting officers, and reviewing
authorities. Contains one-page posture summary, key metrics, compliance
pass/fail status, strategic recommendations, and resource implications.
No technical detail. The decision-maker reads this report and knows
whether to proceed, what requires action, and at what priority.

-----

## How Risk Is Measured

The scanner uses three independent signals to assess each vulnerability.
No single number is used in isolation.

**Severity — CVSS v3.1**  
Answers: *How bad would this be if it were exploited?*  
The Common Vulnerability Scoring System measures the technical damage
potential of a vulnerability — what an attacker could achieve if they
successfully exploited it. Scores range from 0.0 to 10.0.

**Exploitation Probability — EPSS**  
Answers: *How likely is this to be exploited in the next 30 days?*  
The Exploit Prediction Scoring System is a machine learning model that
predicts real-world exploitation likelihood based on threat intelligence
data. Fewer than 5% of published high-severity vulnerabilities are ever
actually exploited. EPSS separates theoretical risk from active threat,
enabling teams to focus effort where it matters most.

**Confirmed Exploitation — CISA KEV**  
Answers: *Is this being used by attackers right now?*  
The CISA Known Exploited Vulnerabilities catalog lists vulnerabilities
with confirmed, active exploitation in the wild. Binding Operational
Directive 22-01 requires federal agencies to remediate KEV-listed
vulnerabilities on mandatory timelines. Any finding on this list
requires immediate action regardless of its severity score.

These three signals together determine the DISA CAT level assigned to
each finding, which drives the remediation timeline:

|Finding Type           |DISA CAT|Required Action                         |
|-----------------------|--------|----------------------------------------|
|CVSS 9.0+ or KEV-listed|CAT I   |Remediate within 3–30 days              |
|CVSS 4.0–8.9           |CAT II  |Remediate within 90 days                |
|CVSS below 4.0         |CAT III |Schedule for remediation within 180 days|

-----

## What Compliance Evidence Is Produced

The scanner generates documented evidence for nine regulatory controls
on every scan. This evidence is machine-generated, timestamped, tied to
a specific software package and a specific point in time, and retained
in the release archive.

|Standard      |Control                      |Evidence Produced                     |
|--------------|-----------------------------|--------------------------------------|
|DISA ASD STIG |APSC-DV-002560               |Semgrep execution log and findings    |
|DISA ASD STIG |APSC-DV-003235               |Grype and Snyk dependency scan results|
|NIST SP 800-53|SA-11 Developer Testing      |SAST execution records                |
|NIST SP 800-53|SA-15 Development Process    |Workflow audit trail                  |
|NIST SP 800-53|RA-5 Vulnerability Monitoring|Vulnerability scan results            |
|NIST SP 800-53|SR-3 Supply Chain Controls   |SBOM with dependency relationships    |
|NIST SP 800-53|SR-4 Provenance              |SPDX 2.3 SBOM with supplier data      |
|NTIA SBOM     |Minimum Elements             |SPDX 2.3 JSON with all seven elements |
|DoDI 8510.01  |RMF Audit Trail              |Timestamped release archive           |

-----

## What This Does Not Replace

The scanner provides automated evidence of automated testing. It does
not replace:

- Manual code review by a qualified security engineer
- Penetration testing or red team assessment
- System-level security controls and configuration review
- The formal ATO process and ISSO/ISSM risk acceptance decisions
- Classification-level analysis for systems handling sensitive data

The CIA impact values used in Environmental CVSS scoring default to
Medium/Medium/Medium per the CVSS v3.1 specification baseline. These
defaults require review and update by the system ISSO/ISSM before
scanner output is used in formal authorization packages.

-----

## Cost and Resource Model

|Resource               |Monthly Limit|Estimated Use per Scan|Annual Capacity|
|-----------------------|-------------|----------------------|---------------|
|GitHub Actions minutes |2,000        |4–6 minutes           |~400 scans     |
|Snyk open source tests |200          |1–2 tests             |~100–200 scans |
|GitHub artifact storage|500 MB       |5–20 MB               |Sufficient     |
|Recurring cost         |—            |**$0.00**             |**$0.00**      |

At a cadence of one scan per week, the infrastructure operates entirely
within free service tiers at zero recurring cost. For higher-volume
programs, the paid tiers of the same tools would scale the identical
workflow without architectural changes.

-----

## Audit Trail Integrity

Every scan produces a GitHub Release — a dated, immutable archive
containing all scan artifacts, generated reports, and this documentation.
Releases are retained for 90 days by default (configurable to any
duration from 1 to 90 days) and are retrievable on demand.

This means that when an auditor asks whether a specific software package
was scanned on a specific date, the answer is a direct link to a release
archive containing the complete evidence package — scan logs, vulnerability
findings, SBOM, generated reports, and compliance documentation — all
timestamped and tied to an exact repository commit.

-----

*This document should be reviewed when organizational policies, applicable
standards, or scanner tool versions change. Version history is maintained
via git commit log.*
