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