# Getting Started

## Install

1. Download the release zip from https://github.com/hbonesctr/Vulnerator/releases and check its SHA-256 against the
   release page (in PowerShell: `Get-FileHash .\Vulnerator-<version>.zip`).
2. If Windows marks the download as coming from the internet, right-click the zip, choose **Properties**, tick
   **Unblock**, then extract it. Extract the whole folder; the program needs the files next to it.
3. Run **Vulnerator.exe** from inside the folder. No installation and no administrator rights are needed; .NET
   Framework 4.8 and 64-bit Windows are required.

## First launch

Choose where the database lives:

* **Portable** - a database file next to the program (or under your local application data when that folder is
  read-only)
* **Persistent** - a database file you pick, for example on a share your team uses

The database uses the SQLite engine built into Windows, so no separate database software is installed.

## One-time setup (Settings in the left menu)

1. **User Information** - your name, email and organization (used on exports).
2. **eMASS Export** - system name, POC / office, default milestone and the other values pre-filled on the eMASS
   POA&M and hardware / software exports, and the **classification / handling marking** printed on every export.
3. **STIG Library** - load the DISA quarterly STIG library zip, or the individual benchmark files (*-xccdf.xml). If the
   zip cannot be brought onto the machine, use **Extract benchmarks from a library zip...** on a machine that has it and
   copy the extracted .xml files over. Reload each quarter; newer releases replace older ones.
4. **Assessment Procedures** - import your eMASS IG/AP export (.xlsx or CSV). If the file carries a sensitivity label
   you are asked to confirm it before it is read.

Without a STIG library, checklists and SCAP results still import, but rules come only from the files themselves;
Vulnerator warns you before such an import.
