# Using the Software

The left menu holds the main pages: **Vulnerability Management**, **Configuration Management**, **Reporting** and
**News**, with **Help**, **Settings**, **Theme** and **About** at the bottom.

## Importing files (Vulnerability Management > Ingest)

1. Pick the **File Type**:
   * **Import ACAS** - .nessus files and ACAS CSV exports (Vulnerability Detail List with Plugin ID, Host / IP and
     Severity columns)
   * **Import CKL / CKLB** - STIG checklists from STIG Viewer 2 (.ckl), STIG Viewer 3 (.cklb) and Evaluate-STIG
   * **Import XCCDF** - SCAP Compliance Checker (SCC) and other XCCDF results (.xml)
   * **Import WASSP** - WASSP .html / .xml results
   * **Import Fortify** - Fortify .fpr files
2. Add the files:
   * **Add Files / Zips...** - pick one or more files, or zip files that contain them
   * **Add Folder...** - pick one or more folders; every subfolder and every zip file inside is searched, including
     zips inside zips. A folder of zip files, each holding a .nessus file, is read in one step.
   * **Pull from STIG Manager...** - download checklists straight from your organization's STIG Manager server (see
     below). They are added as **Import CKL / CKLB** files.
3. Optionally choose an **Ingestion Group** (the system or enclave the files belong to).
4. Select **Execute Ingestion**. The status bar shows progress; the list shows each file's result.

Notes:

* **Evaluate-STIG output:** for checklists, anything under a folder named **Previous** is skipped (Evaluate-STIG keeps
  older results there; the current results are in the **Checklist** folder). A message tells you how many files were
  skipped. To import an older result on purpose, pick that file directly.
* Zip files are extracted to a working folder under your temporary folder; it is cleaned up automatically after a day.
* The same file is only queued once. **Clear List** empties the list.
* A checklist with no host name, FQDN or IP address is imported as a **STIG baseline**: its rules are loaded but no
  findings are recorded. Fill in the asset in STIG Viewer to import it as an assessment.
* **Ports, protocols and services** are collected from every ACAS / Nessus import while *Parse ACAS vulnerability port
  information* is on (the default). Credentialed scans give the fullest list (netstat plugins 14272 / 34220); UDP
  services appear only when the scan covered UDP. Nessus marks guessed service names with "?". Review and name them
  under Configuration Management > Ports, Protocols, Services.
* Without a STIG library you are asked before checklists or SCAP results are imported (see Getting Started).

### Pulling checklists from STIG Manager

Vulnerator can read checklists from a STIG Manager server (NUWCDIVNPT/stig-manager) on your network.

1. In **Settings > STIG Manager**, tick **Allow connections to STIG Manager** (off by default).
2. Under **Vulnerability Management > Ingest**, choose **Pull from STIG Manager...** and fill in what your STIG Manager
   administrator gives you:
   * **API address** - usually `https://<server>/api` (the address of the STIG Manager page plus `/api`)
   * **OIDC provider address** - for Keycloak, `https://<server>/realms/<realm>`
   * **Client ID** - the client registered for Vulnerator in the OIDC provider
   * **Scope** - `openid stig-manager:collection:read` (read-only) unless told otherwise
3. Sign in:
   * **Browser sign-in** - your browser opens the sign-in page (CAC works); when it says sign-in is complete, return
     to Vulnerator. The provider sends you back to `http://127.0.0.1:<port>/` on this computer; if the provider only
     accepts one registered port, enter it as the **Sign-in port**. No administrator rights are needed.
   * **Service account** - enter the client secret. Tick **Remember the secret** to keep it on this computer, encrypted
     for your Windows account; otherwise it is asked for each time.
4. Pick the **Collection** and the **Assets** (all STIGs assigned to each Asset, at their default revisions), then
   **Add to ingestion list**. Choose **Execute Ingestion** as for any other file.

Notes:

* Only the API and OIDC provider addresses you enter are contacted, over HTTPS (plain HTTP only for this computer).
  The server's certificate must be trusted by Windows, and Windows' proxy settings are used.
* Addresses, client ID and scope are remembered after a successful sign-in; the sign-in itself is not kept.
* STIG Manager adds every checklist to one zip. If it could not export some Assets, Vulnerator lists them and asks
  before adding the rest.
* Checklists do not carry STIG Manager's review status (saved, submitted, accepted, rejected): every result is
  imported. STIG Manager writes results it calls Informational, Unknown, Error or Not Selected as Not Reviewed, and
  Fixed as Not a Finding.
* For your administrator: register a public client with the Authorization Code flow and PKCE (S256) and the redirect
  `http://127.0.0.1:<port>/` (if the provider needs an exact match, agree on a port and enter it as the Sign-in port),
  or a confidential client with the client credentials flow for a service account. The account needs the
  `stig-manager:collection:read` scope and a grant to each Collection.

## Reviewing findings

* **Findings** - every finding with its host, status, raw / residual risk and mitigation; filter, edit and approve here.
* **Group Mitigations** - mitigations shared by every finding of a vulnerability within a group.
* **CCI Mapping** - the CCIs and NIST SP 800-53 Rev 5 controls (with DoD assessment procedures) mapped to each
  vulnerability; adjust the mapping when needed.

## Configuration Management

The hardware, software and groups found in the imported files. From **Hardware** you can export a STIG checklist (.ckl)
for a host, built from the STIG library and that host's findings.

**Hardware columns:** choose **Columns...** under the Hardware list to show or hide columns. Besides the names and
scan IP you can show **Operating System** (from ACAS / Nessus scans), **Last ACAS Scan**, **Last Checklist / SCAP**,
**Last Scan**, **Scan Sources** (ACAS, STIG), **Groups**, **Role**, **Manufacturer**, **Model**, **Serial Number**,
**Virtual**, **Lifecycle Status**, **Also Known As** and **ACAS Host ID**. Drag a column header to move it; click it
to sort. Your choice is remembered.

**One record per device.** ACAS and STIG checklists often name the same device differently (for example
**W01.Contoso.com** in a scan and **W01.Contoso** typed into a checklist), so it can appear twice.

* **ACAS host ID:** .nessus files from Tenable Security Center carry a host ID that stays the same when a device's
  name or IP changes. Vulnerator reads it from the host property named under **Vulnerability Management > Ingest >
  ACAS Files > ACAS host ID tag** (**TAG** by default; leave empty to match by name only). A scan of a known ID lands
  on the same record even after a rename; the new name is remembered as an alias.
* **Merge:** tick two or more records that are the same device and choose **Merge Ticked Hardware...**. Pick the
  record to keep (the ACAS record is suggested). Its findings, IP and MAC addresses, groups, software, ports and SCAP
  scores move to it; when both records have the same finding, the newest result is kept, with its POA&M and
  mitigation links. Blank fields (FQDN, OS, ...) are filled from the other records. The other names become aliases
  (shown under **Also Known As**), so later checklists or scans with those names land on the kept record. A merge
  cannot be undone: leave **Back up the database first** ticked to keep a copy of the database file next to it.

## Reporting

Choose the report, the filters (finding type, severity, status, group) and export:

* **eMASS POA&M** - the eMASS POA&M import workbook, with Rev 5 controls and assessment procedures
* **eMASS Hardware / Software** - the eMASS hardware and software list workbooks
* **Risk Assessment Report** - risk workbook of the findings by status and risk level
* **SCAP & STIG Discrepancies** - rules where the SCAP result and the checklist disagree for the same host
* **STIG Details** - every checklist and SCAP rule result, one row per host and rule, with the rule text (discussion,
  check, fix), finding details, comments, Rev 5 controls and CCIs; filter buttons on every column and a
  *Summary by STIG* sheet (hosts, open CAT I / II / III, compliance %)
* **Ports, Protocols & Services** - the ports, protocols and services ACAS / Nessus scans observed, one row per
  port / protocol / service with its hosts, IP addresses, groups and the Nessus plugins that showed it, plus a *By Host*
  sheet; a starting point for the PPSM registration (only the group filter applies)
* **PDF Summary** - a printable overview: totals, open findings by source and severity, results by status, STIG
  compliance, the assets with the most open findings and the most widespread open findings

Each report has its own filters; tick **Use Global Value** to use the Global ones. Generate one report with its button,
or tick several and use **Launch Selected Reports** to save them all to one folder.

Before each export you can accept or change the **marking**; it is printed in the header and footer of every sheet and
stored in the file properties (for the PDF, at the top and bottom of every page). Turn the question off in Settings if you always use the same marking.

## Add-ons
Add-ons are optional extensions (for example dashboards or integrations). To install one,
put its files in the **Add-ons** folder next to Vulnerator.exe (the main file ends in `.AddOn.dll`) and restart
Vulnerator. Its pages appear in the menu and its options under **Settings > Integrations**, which also lists every
add-on found and whether it loaded. An add-on that cannot load is skipped and the reason is logged; Vulnerator keeps
working. If Windows marks the files as downloaded, right-click them, choose **Properties**, tick **Unblock** and restart.
Add-ons can read findings, hardware, the STIG releases submitted and the eMASS POA&M items, but cannot change the database.

### Dashboards (included)
Vulnerator comes with the **Dashboards** add-on (in **Add-ons\Dashboards**). Choose **Dashboards**
in the menu for offline charts of open findings by severity (CAT or Very High to Very Low), top hosts, compliance by
NIST control family, POA&M aging, the open/closed trend, assets with no scan or checklist, outdated STIG checklists and
active IAVMs (with the titles of the findings behind each). Every view carries the classification marking.
**Coverage** counts devices and shows each device's operating system. When ACAS and STIG checklists name the same
device differently (for example **W01.Contoso.com** in a scan and **W01.Contoso** in a checklist), the records with the
same short name count as one device. Under **Coverage > Device matching** you can turn that off, link other records as
one device, or keep a match separate. This only changes the dashboards, not the Hardware list or reports. An ACAS finding the host's newest scan no longer reports is
shown as **Unverified** (neither open nor closed). The trend starts the day Dashboards is first used. To remove it,
close Vulnerator and delete the **Add-ons\Dashboards** folder. Dashboards is part of Vulnerator 2.0 and under the
same MIT license; its source is in the repository (AddOns/Dashboards).

### No licenses
Vulnerator 2.0 is free and open source (MIT). It needs no license key, and future versions will not add one. Anyone
may fork it and carry on their own work.
