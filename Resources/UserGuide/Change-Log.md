# Vulnerator 2.0 (7.5.0-beta.2)
###### Version 7.5.0 beta 2, November 2026

| Change Description |
| :----------------- |
| Configuration Management > Hardware: Columns... to show or hide columns, including Operating System, Last ACAS Scan, Last Checklist / SCAP, Last Scan, Scan Sources, Groups, Role, Manufacturer, Model, Serial Number, Virtual and Lifecycle Status |
| Dashboards 1.1.0: IAVMs list the finding titles; Coverage shows each device's operating system and treats records with the same short name (W01.Contoso.com and W01.Contoso) as one device, with links and Keep separate under Device matching |


----------

# Vulnerator 2.0 (7.5.0-beta.1)
###### Version 7.5.0 beta 1, November 2026

| Change Description |
| :----------------- |
| Pull from STIG Manager: sign in to your STIG Manager server (browser/CAC or service account), pick a Collection and Assets, and add their checklists to the ingestion list (Ingest > Pull from STIG Manager..., turned on in Settings > STIG Manager) |
| Settings > Integrations no longer has a Licenses box; add-ons are listed with their settings only |


----------

# Vulnerator 2.0 (7.4.0)
###### Version 7.4.0, November 2026

| Change Description |
| :----------------- |
| Includes the free Dashboards add-on (Add-ons\Dashboards, no license needed): severity, top hosts, compliance by control family, POA&M aging, trend, coverage gaps, outdated STIG checklists and active IAVMs |
| Add-on support (menu pages, Settings > Integrations, add-on licenses) and the dashboard data from the 7.4.0 betas are now in a full release |


----------

# Vulnerator 2.0 (7.4.0-beta.3)
###### Version 7.4.0 beta 3, November 2026

| Change Description |
| :----------------- |
| ACAS imports keep the Nessus risk factor, so Critical and High can be told apart (both stay CAT I in reports) |
| Checklist and SCAP imports keep the STIG release each file was submitted with, even when a newer release is loaded |
| Add-ons can read more about findings (severity level, first seen, IAVA/IAVB/IAVT and CVE references, hardware), the STIG releases submitted, the eMASS POA&M items and the STIG library import date |


----------

# Vulnerator 2.0 (7.4.0-beta.2)
###### Version 7.4.0 beta 2, November 2026

| Change Description |
| :----------------- |
| Settings > Integrations: a Licenses box to paste an add-on license key or import a .lic file, and remove one |
| Each add-on shows its license status, and what it says about each entered license |
| Licenses are checked by the add-ons on this computer; nothing is sent anywhere |


----------

# Vulnerator 2.0 (7.4.0-beta.1)
###### Version 7.4.0 beta 1, November 2026

| Change Description |
| :----------------- |
| Add-on support: optional add-ons in the Add-ons folder add menu pages and Settings > Integrations options |
| Add-ons read findings and hardware read-only; a broken or incompatible add-on is skipped and logged |


----------

# Vulnerator 2.0 (7.3.0)
###### Version 7.3.0, November 2026

| Change Description |
| :----------------- |
| Configuration Management > Hardware: every button works (clear, add / update, delete, IP / MAC / group / software / port links) |
| Configuration Management > Software: clear, add / update, delete, add / remove hardware |
| About and Help show the release version (for example 7.3.0) |


----------

# Vulnerator 2.0 (7.2.0)
###### Version 7.2.0, November 2026

| Change Description |
| :----------------- |
| New report: Ports, Protocols & Services (from ACAS / Nessus scans, with the detecting plugins) |
| Nessus port 0 ("general") results are no longer stored as services; existing entries are removed |
| Configuration Management > Ports, Protocols, Services tab lists the services; save name / acronym, delete |


----------

# Vulnerator 2.0 (7.1.0)
###### Version 7.1.0, November 2026

| Change Description |
| :----------------- |
| New report: STIG Details (successor of the Vulnerator 6 STIG Details tab), with a Summary by STIG sheet |
| New report: PDF Summary (printable overview with STIG compliance, top assets and most widespread findings) |


----------

# Vulnerator 2.0 (7.0.0)
###### Version 7.0.0, November 2026

Application rewrite by Hector L. Bones.

| Change Description |
| :----------------- |
| NIST SP 800-53 Rev 5 controls, DISA CCI list and CNSSI 1253 baselines; eMASS assessment procedures from your own IG/AP export |
| eMASS POA&M and hardware / software exports; classification / handling marking on every export |
| STIG Viewer 3 (.cklb) checklists, Evaluate-STIG output (zips and folders, "Previous" folders skipped), STIG baselines |
| ACAS imports from .nessus, CSV, zip files and folders of zips |
| SCAP / SCC XCCDF 1.1 and 1.2 results and the DISA STIG library (zip or extracted benchmark files) |
| Per-host STIG checklist (.ckl) export from the STIG library |
| Runs offline by default; Windows built-in SQLite engine; 64-bit; works where strong-name bypass is disabled |
| Help pages rewritten |


----------

# Version 6.1.7
###### Release Date: 05 January 2017

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Corrects issue with parsing of HP Fortify *.fpr files | GH #75 |


----------

# Version 6.1.6
###### Release Date: 04 January 2017

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Corrects issue with parsing of HP Fortify *.fpr files | GH #73 |


----------

# Version 6.1.5
###### Release Date: 03 January 2017

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Incorporates the ability to ingest HP Fortify *.fpr files | GH #35 |
| Slight UI updates | -- |


----------

# Version 6.1.4
###### Release Date: 26 October 2016

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Updates CKL processing to pull all STIG names from consolidated CKL files | GH #61 |
| Updates RAR to only show “Ongoing” Security Controls | GH #62 |
| Moves "Useful Links" from "About" Flyout to Title Bar | -- |
| Adds Version Indicator and "Download" button to lower right-hand corner of Status Bar | --|


----------

# Version 6.1.3
###### Release Date: 24 October 2016

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Updates RAR report to use the full DoN Template | GH #31 |
| Introduces a “Test Plan” report | GH #32 |
| Incorporates Nessus Scanner Version and Plugin Feed data into reports | GH #33 |
| Corrects SCAP Import issue due to validation attempt while offline | GH #34 |
| Adds DIACAP IA / RMF Controls to “STIG Details & Review” report | GH #37 |
| Corrects issue with IA / RMF Controls missing from POA&M / RAR | GH #43 |
| Introduces automatic conversion of DIACAP IAC to NIST SP 800-53 controls | GH #44 |
| Includes “Risk Statement” and “Recommended Corrective Action” in “STIG Details & Review” report | GH #46 |
| Includes XCCDF data on “STIG Details & Review” Report | GH #47 |
| Updates “STIG ID” to “V-ID” on “STIG Details & Review” report; includes all identifiers in report | GH #50 |
| Updates ACAS host name mapping to use NetBIOS if DNS Name is unavailable | GH #51 |
| Adds “Check Content” to “STIG Details & Review” Page | GH #52 |


----------

# Version 6.1.2
###### Release Date: 17 August 2016

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Enhances error reporting & application logging | GH #26 |
| Corrects error parsing "release" data from CKL files | GH #28 |
| Removes "MAC Level" field from application | GH #29 |
| Corrects SQLite Error when parsing CKL, XCCDF, WASSP files | GH #38 |
| Includes download count in "Releases" list | -- |


----------

# Version 6.1.1 Beta
###### Release Date: 03 June 2016

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Migrated to GitHub | -- |
| Created Wiki pages | -- |
| Created Readme file | -- |
| Migrated issues | -- |
| Upgrades to .NET 4.5.2 | -- |
| Incorporates creation of STIG Details report | GH: #1 / SWF: artf375577 |
| Incorporates asset identifier selection | GH: #2 / SWF: artf377321 |
| Adds CVE numbers from ACAS | GH: #3 / SWF: artf126752 |
| Adds STIG “Comments” / “Finding Details” selection option for mitigations | GH: #6 / SWF: artf377995 |
| Fixes multiple mitigation addition failure | GH: #8 / SWF: artf386780 |
| Incorporates “News” page | GH: #9 |
| Created GitHub project page for Vulnerator | GH: #11 |
| Updates “About” page with GitHub information | GH: #12 |
| CCI Data now importing from STIG correctly | GH: #13 |
| ACAS Output text files now generating properly for large raw-data imports | GH: #20 |
| Corrects “Import Mitigations” button issue | GH: #23 |


----------

# Version 6.1.0 Beta
###### Release Date: 12 May 2016

| Change Description | Associated Issue |
| :----------------- | :--------------: |
| Replaces SQL Compact Edition (CE) with SQLite | -- |
| Migrates vulnerability processing from in-memory to database | artf377210 |
| Enhances “ACAS Output” text file readability | -- |
| Moves from Document Object Model (DOM) to Simple API for XML (SAX) Excel processing | -- |
| Writes Excel Data to Shared String Table instead of in-line | -- |
| Corrects false grouping of STIG findings based on Vuln. ID | artf386371 |
| Corrects processing of *.ckl files generated using DISA STIG Viewer 2.x | -- |