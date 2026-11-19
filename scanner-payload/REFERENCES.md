# Open Source Software (OSS) Security Scanner — Metrics & Standards References

**Project:** Open Source Software (OSS) Security Scanner  
**Author:** Hector L. Bones  
**Last Reviewed:** 2026-05-09  
**Version:** 1.0

This document provides authoritative sources for every metric, scoring
system, and compliance standard used in the security scanner and its
generated reports. It serves as the citation backbone for audit review
and methodology validation.

---

## Vulnerability Scoring

### CVSS v3.1 — Common Vulnerability Scoring System

The primary severity metric used in all scanner reports.

| Resource | URL |
|---|---|
| FIRST.org Specification | https://www.first.org/cvss/v3-1/specification-document |
| FIRST.org Calculator | https://www.first.org/cvss/calculator/3.1 |
| NVD CVSS Documentation | https://nvd.nist.gov/vuln-metrics/cvss |

**Why v3.1 and not v4.0:** CVSS v4.0 was released November 2023 but is not
yet widely adopted by the toolchain (Grype, Snyk). NVD continues issuing
v3.1 scores as the current standard. OWASP explicitly chose not to use v4.0
for its 2025 Top 10 because the scoring algorithm changed in ways that break
easy comparability. This scanner will migrate to v4.0 when tool support
matures.

**Severity bands used in reports:**

| Score | Severity | DISA CAT | Default SLA |
|---|---|---|---|
| 9.0 – 10.0 | Critical | CAT I | 3 days |
| 7.0 – 8.9 | High | CAT I | 30 days |
| 4.0 – 6.9 | Medium | CAT II | 90 days |
| 0.1 – 3.9 | Low | CAT III | 180 days |

---

### EPSS v4 — Exploit Prediction Scoring System

Measures the probability that a CVE will be exploited in the wild within
30 days. Used alongside CVSS to prioritize remediation.

| Resource | URL |
|---|---|
| FIRST.org EPSS Home | https://www.first.org/epss |
| EPSS v4 Model Paper (March 2025) | https://www.first.org/epss/model |
| EPSS API | https://api.first.org/data/v1/epss |

**Key insight:** Fewer than 5% of published CVEs are ever observed being
exploited. EPSS identifies which ones are actually being targeted, enabling
teams to focus remediation effort where real-world risk is highest rather
than chasing theoretical severity scores.

---

### CISA KEV — Known Exploited Vulnerabilities Catalog

A catalog of CVEs confirmed as actively exploited in the wild. Maintained
by the Cybersecurity and Infrastructure Security Agency.

| Resource | URL |
|---|---|
| KEV Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| KEV JSON Feed | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| BOD 22-01 (Binding Directive) | https://www.cisa.gov/binding-operational-directive-22-01 |

**Binding Operational Directive 22-01** requires federal agencies to
remediate KEV-listed vulnerabilities on mandatory timelines. Any finding
flagged as KEV in scanner reports requires immediate escalation regardless
of CVSS score.

---

## Weakness Classification

### CWE — Common Weakness Enumeration

Classifies the root cause category of a vulnerability. Used in Analyst
and Developer reports to support root cause analysis and code-level fixes.

| Resource | URL |
|---|---|
| CWE List | https://cwe.mitre.org/data/index.html |
| CWE Top 25 Most Dangerous (2024) | https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html |
| CWE/CVE Relationship | https://cwe.mitre.org/about/faq.html |

---

### OWASP Top 10 — 2025

Maps vulnerabilities to the ten most critical software security risk
categories. Used in reports to provide business context for technical findings.

| Resource | URL |
|---|---|
| OWASP Top 10 2025 | https://owasp.org/www-project-top-ten |
| OWASP Software Supply Chain (A03) | https://owasp.org/www-project-top-ten/2025/A03_Software_and_Data_Integrity_Failures |

**Relevance to this scanner:** A03:2025 Software Supply Chain Failures
covers open source dependency risk directly — the primary focus of this
scanner's SCA capability.

---

## Compliance Standards

### DISA Application Security and Development STIG

| Control | Title | Scanner Evidence |
|---|---|---|
| APSC-DV-002560 | SAST tools must be used | Semgrep execution log + findings JSON |
| APSC-DV-003235 | Dependency scanning must be performed | Grype + Snyk results + SBOM |

| Resource | URL |
|---|---|
| STIG Downloads | https://public.cyber.mil/stigs/downloads |
| STIG Viewer | https://public.cyber.mil/stigs/srg-stig-tools |

---

### NIST SP 800-53 Rev 5

| Control | Title | Scanner Evidence |
|---|---|---|
| SA-11 | Developer Security Testing and Evaluation | Semgrep SAST execution |
| SA-15 | Development Process, Standards, and Tools | Workflow audit trail |
| RA-5 | Vulnerability Monitoring and Scanning | Grype + Snyk SCA execution |
| SR-3 | Supply Chain Controls and Processes | SBOM generation |
| SR-4 | Provenance | SPDX 2.3 SBOM with supplier data |
| SI-2 | Flaw Remediation | Findings with fix versions and SLA |

| Resource | URL |
|---|---|
| SP 800-53 Rev 5 Full Text | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final |
| SP 800-53 Control Catalog | https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search |
| NIST RMF Overview | https://csrc.nist.gov/projects/risk-management |

---

### NTIA SBOM Minimum Elements

The SBOM generated by Syft in SPDX 2.3 format satisfies all seven
NTIA minimum elements:

| Element | SPDX 2.3 Field |
|---|---|
| Supplier Name | `supplier` |
| Component Name | `name` |
| Version String | `versionInfo` |
| Other Unique Identifiers | `SPDXID`, `externalRefs` (CPE, PURL) |
| Dependency Relationships | `relationships` |
| Author of SBOM Data | `creationInfo.creators` |
| Timestamp | `creationInfo.created` |

| Resource | URL |
|---|---|
| NTIA Minimum Elements (2021) | https://www.ntia.gov/report/2021/minimum-elements-software-bill-of-materials-sbom |
| SPDX 2.3 Specification | https://spdx.github.io/spdx-spec/v2.3 |
| SPDX ISO/IEC 5962:2021 | https://www.iso.org/standard/81870.html |

---

### DoD Policy References

| Document | Title | Relevance |
|---|---|---|
| EO 14028 (May 2021) | Improving the Nation's Cybersecurity | Mandates SBOM for federal software procurement |
| DoDI 8500.01 | Cybersecurity (updated 2024) | Overarching DoD cybersecurity policy |
| DoDI 8510.01 | RMF for DoD Systems (updated 2023) | Governs ATO process and control implementation |
| CNSSI 1253 | Security Categorization for NSS | CIA impact level definitions |

---

## Exploitability Assessment

### VEX — Vulnerability Exploitability eXchange

Used in Analyst reports to document whether a known vulnerability is
actually exploitable in a specific operational context.

| Resource | URL |
|---|---|
| CISA VEX Use Cases | https://www.cisa.gov/resources-tools/resources/vex-use-cases |
| CISA VEX Justifications | https://www.cisa.gov/sites/default/files/2023-01/VEX_Use_Cases_Appliance_WG_508c.pdf |
| OpenVEX Specification | https://github.com/openvex/spec |

**VEX status values used in reports:**

| Status | Meaning |
|---|---|
| Affected | Vulnerability is present and exploitable |
| Not Affected | Vulnerability present but not exploitable in this context |
| Fixed | Vulnerability was present; patch applied |
| Under Investigation | Impact assessment in progress |

---

## Scanner Tools

| Tool | Purpose | Version Used | Source |
|---|---|---|---|
| Syft | SBOM generation | 1.44.0 | https://github.com/anchore/syft |
| Grype | SCA / vulnerability matching | 0.112.0 | https://github.com/anchore/grype |
| Semgrep | SAST / static analysis | 1.162.0 | https://semgrep.dev |
| Snyk | SCA / dependency analysis | 1.1304.2 | https://snyk.io |
| CodeQL | SAST / semantic analysis | GitHub-managed | https://codeql.github.com |

---

*This document should be reviewed and updated when standards are revised.
Version history is maintained via git commit log.*
