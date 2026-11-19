#!/usr/bin/env python3
"""
Checks Vulnerator's eMASS exports against the eMASS import templates (POAMImportTemplate_RMF_Standard,
HWSWList_Template) and the template instructions, using the workbooks produced by
Test-ChecklistImport.ps1 from the synthetic test checklists.

The expected headers below are copied from the templates, independently of the C# constants, so a drift
in either place fails the check.
Usage: python verify_emass_exports.py <sample-eMASS-POAM.xlsx> <sample-eMASS-HW-SW-List.xlsx>
"""
import datetime
import os
import sys

import openpyxl

POAM_HEADERS = [
    "POA&M Item ID", "POA&M Status", "Summary", "Vulnerability Description", "Controls / APs", "Security Checks",
    "Date Identified", "POA&M Scheduled Completion Date", "POA&M Requested Risk Accepted Expiration Date",
    "POA&M Completion Date", "Milestone ID", "Milestone Status", "Milestone Description", "Milestone Status Comments",
    "Milestone Scheduled Completion Date", "Milestone Completion Date", "Identification Source",
    "Identification Source Details", "Office/Org", "Comments", "Raw Severity", "Devices Affected", "Mitigations",
    "Severity", "Relevance of Threat", "Likelihood", "Impact", "Impact Description", "Residual Risk Level",
    "Recommendations", "Resources", "Actual Cost",
]
HARDWARE_HEADERS = [
    "#", "Component Type", "Asset Name", "Nickname", "MAC Address", "Asset IP Address", "Public Facing",
    "Public Facing FQDN", "Public Facing IP Address", "Public Facing URL(s)", "Virtual Asset?", "Manufacturer",
    "Model Number", "Serial Number", "Line Item Number", "National Stock Number", "OS/iOS/FW Version",
    "Memory Size / Type", "Location (P/C/S & Building)", "Approval Status", "Critical Information System Asset?",
]
SOFTWARE_HEADERS = [
    "#", "Software Type", "Software Vendor", "Software Name", "Version", "Parent System", "Subsystem", "Network",
    "Hosting Environment", "Software Dependencies", "Cryptographic Hash", "In Service Data", "IT Budget UII",
    "Fiscal Year (FY)", "POP End Date", "License or Contract", "License Term", "Cost per License", "Total Licenses",
    "Total License Cost", "Licenses Used", "License POC", "License Renewal Date", "License Expiration Date",
    "Approval Status", "Approval Date", "Release Date", "Maintenance Date", "Retirement Date",
    "End of Life/Support Date", "Extended End of Life/Support Date", "Critical Information System Asset?",
    "Location", "Purpose",
]
LEVELS = {"Very Low", "Low", "Moderate", "High", "Very High"}
POAM_STATUSES = {"Ongoing", "Risk Accepted", "Completed"}
MILESTONE_STATUSES = {"Open", "In Progress", "Delayed", "Completed", "Archived"}
IDENTIFICATION_SOURCES = {
    "Access Control", "Audit Findings", "Compliance Gaps", "Configuration Management", "Data Protection and Privacy",
    "Decision Condition", "Disaster Recovery / Continuity Planning", "Incident Response", "Management", "Operational",
    "Other (Non-Technical)", "Other (Technical)", "Patch Management", "Risk Assessment Findings",
    "Security Control Deficiencies", "System and Network Monitoring", "Third-Party or Supplier Risk",
    "Training and Awareness", "Vulnerability Management",
}
COL = {name: index + 2 for index, name in enumerate(POAM_HEADERS)}   # header -> column number (B = 2)

failures = []


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)
        if os.environ.get("GITHUB_ACTIONS") == "true" and len(failures) <= 10:
            print("::error::FAIL " + message.replace("%", "%25"))


def text(ws, row, header):
    value = ws.cell(row=row, column=COL[header]).value
    return "" if value is None else str(value)


def date(ws, row, header):
    value = ws.cell(row=row, column=COL[header]).value
    return value if isinstance(value, datetime.datetime) else None


def check_poam(path):
    wb = openpyxl.load_workbook(path)
    check(wb.sheetnames == ["POA&M"], f"POA&M workbook has one sheet named POA&M (got {wb.sheetnames})")
    ws = wb["POA&M"]
    headers = [ws.cell(row=7, column=c).value for c in range(2, 2 + len(POAM_HEADERS))]
    check(headers == POAM_HEADERS, "row 7 headers B:AG match the RMF Standard template")
    check(ws.column_dimensions["A"].hidden, "column A is hidden, as in the template")
    check(ws.row_dimensions[1].hidden, "row 1 is hidden, as in the template")
    labels = {ws["A2"].value, ws["A3"].value, ws["A4"].value, ws["A5"].value, ws["A6"].value}
    check(labels == {"Date Exported:", "Exported By:", "CC/S/A/FA:", "System / Project Name:", "DoW IT Registration No:"},
          "header block labels in A2:A6 match the template")
    check(ws["F5"].value == "Test System" and ws["O4"].value == "Pat Tester", "header block carries system name and POC")
    banner = (ws.oddHeader.center.text or "") + (ws.oddFooter.center.text or "")
    check("UNCLASSIFIED" not in banner, "no classification banner by default (processor ruling R-20)")

    items, row = [], 8
    while row <= ws.max_row:
        status = text(ws, row, "POA&M Status")
        if status:
            item = {"row": row, "status": status, "milestones": []}
            items.append(item)
        if items and text(ws, row, "Milestone Status"):
            items[-1]["milestones"].append(row)
        row += 1
    check(len(items) == 2, f"2 POA&M items: only open findings (POAM-05); passing and not-reviewed checks stay off (got {len(items)})")

    by_key = {}
    for item in items:
        r = item["row"]
        check(item["status"] in POAM_STATUSES, f"row {r}: status '{item['status']}' is an eMASS value")
        check(text(ws, r, "Vulnerability Description") != "", f"row {r}: Vulnerability Description present (required)")
        check(text(ws, r, "Office/Org") == "Test Org, Pat Tester, 555-0100, pat.tester@example.test",
              f"row {r}: Office/Org is 'Org, Name, Phone, Email'")
        check(text(ws, r, "Resources") == "Sustainment funding", f"row {r}: Resources from settings (required)")
        check(text(ws, r, "Identification Source") == "Security Control Deficiencies", f"row {r}: Identification Source default (POAM-15)")
        check(text(ws, r, "Identification Source") in IDENTIFICATION_SOURCES, f"row {r}: Identification Source from the glossary")
        check(" :: Version " in text(ws, r, "Identification Source Details"), f"row {r}: source details 'Title :: Version N, Release' (POAM-16)")
        check(text(ws, r, "Impact") == text(ws, r, "Raw Severity"), f"row {r}: Impact = raw severity (PD-06)")
        check(text(ws, r, "Impact Description") == text(ws, r, "Vulnerability Description"), f"row {r}: Impact Description = Description (POAM-27)")
        check(text(ws, r, "Raw Severity") in LEVELS, f"row {r}: Raw Severity is an eMASS level")
        check(text(ws, r, "POA&M Item ID") == "" and text(ws, r, "Milestone ID") == "", f"row {r}: IDs left for eMASS")
        check(date(ws, r, "Date Identified") is not None, f"row {r}: Date Identified is a real date")
        check(len(item["milestones"]) >= 1, f"row {r}: {item['status']} item has a milestone")
        for m in item["milestones"]:
            check(text(ws, m, "Milestone Status") in MILESTONE_STATUSES, f"row {m}: milestone status is an eMASS value")
            scheduled = date(ws, m, "Milestone Scheduled Completion Date")
            check(scheduled is not None, f"row {m}: milestone scheduled date present")
            if scheduled and date(ws, r, "POA&M Scheduled Completion Date"):
                check(scheduled <= date(ws, r, "POA&M Scheduled Completion Date"),
                      f"row {m}: milestone date does not exceed the item's scheduled date")
        if item["status"] == "Ongoing":
            identified = date(ws, r, "Date Identified")
            expected = identified + datetime.timedelta(days=90) if identified else None
            check(date(ws, r, "POA&M Scheduled Completion Date") == expected, f"row {r}: scheduled = Date Identified + 90 days (setting; POAM-06)")
            check(text(ws, item["milestones"][0], "Milestone Status") == "Open", f"row {r}: Ongoing milestone is Open")
        if item["status"] == "Completed":
            check(date(ws, r, "POA&M Completion Date") is not None, f"row {r}: Completed item has a completion date")
            check(all(text(ws, m, "Milestone Status") in ("Completed", "Archived") for m in item["milestones"]),
                  f"row {r}: Completed item's milestones are all Completed")
        by_key[(text(ws, r, "Security Checks"), item["status"])] = r

    expectations = [
        ("SV-1001r2_rule", "Ongoing", "AC-2(1)", "High", "TESTHOST01"),
        ("SV-1002r1_rule", "Ongoing", "CM-6", "Moderate", "TESTHOST02"),
    ]
    for check_id, status, control, severity, host in expectations:
        r = by_key.get((check_id, status))
        check(r is not None, f"item {check_id} / {status} exists")
        if r is None:
            continue
        check(text(ws, r, "Controls / APs") == control, f"{check_id} / {status}: control {control} (got '{text(ws, r, 'Controls / APs')}')")
        check(text(ws, r, "Raw Severity") == severity, f"{check_id} / {status}: raw severity {severity}")
        check(text(ws, r, "Devices Affected") == host, f"{check_id} / {status}: devices '{host}' (got '{text(ws, r, 'Devices Affected')}')")
    r1, r2 = by_key.get(("SV-1001r2_rule", "Ongoing")), by_key.get(("SV-1002r1_rule", "Ongoing"))
    if r1:
        check(text(ws, r1, "Mitigations") == "Analyst Must Complete", "no justification -> 'Analyst Must Complete' (AD-917)")
        check(text(ws, r1, "Recommendations") == "Configure automated account management.", "Recommendations = Fix Text (POAM-29)")
        check(text(ws, r1, "Comments") == "Account management is manual.\n---\nTicket 42 opened.", "Comments = details --- comments (POAM-19)")
        check(text(ws, r1, "Severity") == "High", "Severity = raw severity without an override")
    if r2:
        check(text(ws, r2, "Mitigations") == "Compensating control in place.", "Mitigations = severity justification (AD-917)")
        check(text(ws, r2, "Severity") == "Low" and text(ws, r2, "Raw Severity") == "Moderate", "Severity honours the override; Raw Severity does not (PD-06a)")
        check(date(ws, r2, "Date Identified") == datetime.datetime(2026, 2, 3), f"Date Identified = CKLB rule date 2026-02-03 (AD-916) (got {date(ws, r2, 'Date Identified')})")
    first_severities = [text(ws, item["row"], "Raw Severity") for item in items]
    order = {"Very High": 0, "High": 1, "Moderate": 2, "Low": 3, "Very Low": 4}
    check(first_severities == sorted(first_severities, key=lambda s: order.get(s, 9)), "items are ordered by severity, CAT I first")


def check_hwsw(path):
    wb = openpyxl.load_workbook(path)
    check(wb.sheetnames == ["Hardware", "Software"], f"HW/SW workbook has Hardware and Software sheets (got {wb.sheetnames})")
    hw, sw = wb["Hardware"], wb["Software"]
    check([hw.cell(row=7, column=c).value for c in range(1, 1 + len(HARDWARE_HEADERS))] == HARDWARE_HEADERS,
          "Hardware row 7 headers match the template")
    check([sw.cell(row=7, column=c).value for c in range(1, 1 + len(SOFTWARE_HEADERS))] == SOFTWARE_HEADERS,
          "Software row 7 headers match the template")
    check(hw["A4"].value == "Information System Owner:" and hw["G4"].value == "POC Name:" and hw["J4"].value == "Date Reviewed / Updated:",
          "Hardware header block labels match the template")
    rows = {hw.cell(row=r, column=3).value: r for r in range(8, hw.max_row + 1) if hw.cell(row=r, column=3).value}
    check(set(rows) == {"TESTHOST01", "TESTHOST02"}, f"Hardware lists both test hosts (got {sorted(rows)})")
    if "TESTHOST01" in rows:
        r = rows["TESTHOST01"]
        check(hw.cell(row=r, column=6).value == "10.1.2.3", "TESTHOST01 IP address")
        check(hw.cell(row=r, column=5).value == "00:11:22:33:44:55", "TESTHOST01 MAC address")
        check(hw.cell(row=r, column=1).value in (None, ""), "Asset ID # left for eMASS")
    banner = (hw.oddHeader.center.text or "") + (sw.oddFooter.center.text or "")
    check("UNCLASSIFIED" not in banner, "no classification banner by default (R-20)")


def main():
    check_poam(sys.argv[1])
    check_hwsw(sys.argv[2])
    print("\nAll export checks passed." if not failures else f"\n{len(failures)} export check(s) failed.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
