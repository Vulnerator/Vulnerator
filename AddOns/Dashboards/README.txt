Vulnerator 2.0 Dashboards add-on
================================

Offline dashboards inside Vulnerator: open findings by severity, top hosts, compliance by
NIST SP 800-53 Rev 5 control family, POA&M aging, open vs. closed trend, assets with no scan
or checklist, STIG checklists submitted (current or outdated) and active IAVMs.
Nothing is sent anywhere; it needs no server. Part of Vulnerator 2.0, under the same MIT license.

Requirements
- Vulnerator 2.0 version 7.4.0 or later (64-bit Windows, .NET Framework 4.8).

Install
- Vulnerator 7.4.0 and later already include it in the "Add-ons" folder: open Dashboards
  in the menu. Settings > Integrations lists it.
- To turn it off, close Vulnerator and move Vulnerator.Dashboards.AddOn.dll out of the
  "Add-ons" folder.
- If you copy the file in yourself from a download, unblock it first: right-click >
  Properties > Unblock, or in PowerShell: Unblock-File .\Vulnerator.Dashboards.AddOn.dll

Notes
- Severity "Very High" (Nessus Critical) and the STIG release each checklist was submitted with
  are recorded by Vulnerator 7.4.0-beta.3 and later. Import older scans and checklists again to
  include them.
- An ACAS finding that the host's newest scan no longer reports is shown as "Unverified". It is
  not counted as open or as closed.
- Coverage counts devices. Hardware records with the same short host name (W01.Contoso.com
  from ACAS and W01.Contoso from a checklist) are one device; you can turn that off, link
  other records by hand, or keep a match separate under Coverage > Device matching. This is
  kept in "Add-on data\dashboards\device-links.json" and does not change the Hardware list.
- The IAVMs view lists the titles of the open findings behind each IAVM.
- The trend starts the first day the add-on is used. Its history is kept in the add-on's data
  folder next to the database ("Add-on data\dashboards\trend.json").

Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the Vulnerator folder).
Source: https://github.com/hbonesctr/Vulnerator (AddOns/Dashboards).
