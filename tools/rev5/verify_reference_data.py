#!/usr/bin/env python3
"""
Verifies the embedded Rev 5 reference data against Vulnerator's real SQLite schema.

Creates an in-memory database from Resources/DdlFiles/Tables (Create + Insert/Data), then loads
U_CCI_List.xml and the NIST_800-53r5_* files using the same SQL statements DatabaseBuilder.cs runs.
The load is run twice to prove it is idempotent, then the control-ID formatting used by the eMASS
POA&M and Risk Assessment Report queries is checked.

Usage: python3 verify_reference_data.py [repo root]   (exit code 0 = all checks passed)
"""
import glob
import os
import sqlite3
import sys
import xml.etree.ElementTree as ET

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..")
RAW = os.path.join(ROOT, "Resources", "RawData")
DDL = os.path.join(ROOT, "Resources", "DdlFiles", "Tables")
CCI_NS = "{http://iase.disa.mil/cci}"
failures = []


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def read(path):
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


def create_schema(db):
    for path in sorted(glob.glob(os.path.join(DDL, "Create", "*.ddl"))):
        db.executescript(read(path))
    for path in sorted(glob.glob(os.path.join(DDL, "Insert", "Data", "*.ddl"))):
        db.executescript(read(path))


def key_clause(enhancement):
    return ("ControlEnhancement = :Enhancement", ":Enhancement") if enhancement else ("ControlEnhancement IS NULL", "NULL")


def load(db):
    # LoadReferenceData(): clear mappings
    db.executescript("DELETE FROM NIST_ControlsCCIs; DELETE FROM NIST_ControlsConfidentialityLevels; "
                     "DELETE FROM NIST_ControlsIntegrityLevels; DELETE FROM NIST_ControlsAvailabilityLevels; "
                     "UPDATE NIST_Controls SET MonitoringFrequency = NULL;")
    # PopulateCciData() / InsertCciValues()
    root = ET.parse(os.path.join(RAW, "U_CCI_List.xml")).getroot()
    version = root.findtext(f"{CCI_NS}metadata/{CCI_NS}version")
    for item in root.iter(f"{CCI_NS}cci_item"):
        p = {"CCI": item.get("id").replace("CCI-", ""), "Definition": item.findtext(f"{CCI_NS}definition"),
             "Type": item.findtext(f"{CCI_NS}type"), "Status": item.findtext(f"{CCI_NS}status"), "Version": version}
        cur = db.execute("UPDATE CCIs SET CCI_Definition = :Definition, CCI_Type = :Type, CCI_Status = :Status, "
                         "Version = :Version WHERE CCI_Number = :CCI;", p)
        if cur.rowcount == 0:
            db.execute("INSERT INTO CCIs VALUES (NULL, :CCI, :Definition, :Type, :Status, :Version);", p)
    # PopulateNistControls() / InsertNistControls() / MapControlsToCia()
    for control in ET.parse(os.path.join(RAW, "NIST_800-53r5_Controls.xml")).getroot().iter("Control"):
        enh = control.get("enhancement") != "0"
        match, value = key_clause(enh)
        p = {"Family": control.get("family"), "Number": control.get("number"), "Enhancement": control.get("enhancement"),
             "Title": control.findtext("Title"), "Text": control.findtext("Text") or "",
             "SupplementalGuidance": control.findtext("SupplementalGuidance") or ""}
        cur = db.execute("UPDATE NIST_Controls SET ControlTitle = :Title, ControlText = :Text, SupplementalGuidance = "
                         f":SupplementalGuidance WHERE ControlFamily = :Family AND ControlNumber = :Number AND {match};", p)
        if cur.rowcount == 0:
            db.execute(f"INSERT INTO NIST_Controls VALUES (NULL, :Family, :Number, {value}, :Title, :Text, :SupplementalGuidance, NULL);", p)
        cid = db.execute(f"SELECT NIST_Control_ID FROM NIST_Controls WHERE ControlFamily = :Family AND ControlNumber = :Number "
                         f"AND {match} ORDER BY NIST_Control_ID LIMIT 1;", p).fetchone()[0]
        for triad, table, column in (("Confidentiality", "NIST_ControlsConfidentialityLevels", "ConfidentialityLevel"),
                                     ("Integrity", "NIST_ControlsIntegrityLevels", "IntegrityLevel"),
                                     ("Availability", "NIST_ControlsAvailabilityLevels", "AvailabilityLevel")):
            element = control.find(triad)
            for level in ("High", "Moderate", "Low"):
                flag = element.get(level.lower())
                if flag == "false":
                    continue
                db.execute(f"INSERT INTO {table} VALUES (NULL, ?, (SELECT {column}_ID FROM {column}s WHERE {column} = ?), ?);",
                           (cid, level, "True" if flag == "NSS" else "False"))
    # MapControlsToCci()
    for pair in ET.parse(os.path.join(RAW, "NIST_800-53r5_CCI_Mapping.xml")).getroot().iter("Pair"):
        enh = pair.get("enhancement") != "0"
        match, _ = key_clause(enh)
        p = {"Family": pair.get("family"), "Number": pair.get("number"), "Enhancement": pair.get("enhancement"),
             "DoD_AP": pair.get("dod-ap"), "ControlIndicator": pair.get("indicator"), "CCI": pair.get("cci"),
             "ImplementationGuidance": pair.findtext("ImplementationGuidance") or "",
             "AP_Text": pair.findtext("AssessmentProcedures") or ""}
        db.execute("INSERT INTO NIST_ControlsCCIs VALUES (NULL, (SELECT NIST_Control_ID FROM NIST_Controls WHERE "
                   f"ControlFamily = :Family AND ControlNumber = :Number AND {match}), (SELECT CCI_ID FROM CCIs WHERE "
                   "CCI_Number = :CCI), :DoD_AP, :ControlIndicator, :ImplementationGuidance, :AP_Text);", p)
    # MapControlsToMonitoringFrequency()
    for control in ET.parse(os.path.join(RAW, "NIST_800-53r5_MonitoringFrequency.xml")).getroot().iter("Control"):
        match, _ = key_clause(control.get("enhancement") != "0")
        db.execute(f"UPDATE NIST_Controls SET MonitoringFrequency = :Frequency WHERE ControlFamily = :Family AND "
                   f"ControlNumber = :Number AND {match};",
                   {"Frequency": control.findtext("Frequency"), "Family": control.get("family"),
                    "Number": control.get("number"), "Enhancement": control.get("enhancement")})


def counts(db):
    return {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("CCIs", "NIST_Controls", "NIST_ControlsCCIs", "NIST_ControlsConfidentialityLevels")}


def main():
    db = sqlite3.connect(":memory:")
    create_schema(db)
    load(db)
    first = counts(db)
    print("After first load: ", first)
    load(db)
    second = counts(db)
    print("After second load:", second)
    check(first == second, "reloading reference data creates no duplicate rows")

    expected_pairs = sum(1 for _ in ET.parse(os.path.join(RAW, "NIST_800-53r5_CCI_Mapping.xml")).getroot().iter("Pair"))
    check(second["NIST_ControlsCCIs"] == expected_pairs, f"all {expected_pairs} CCI-to-control pairs inserted")
    orphans = db.execute("SELECT COUNT(*) FROM NIST_ControlsCCIs WHERE NIST_Control_ID IS NULL OR CCI_ID IS NULL").fetchone()[0]
    check(orphans == 0, "every pair resolves to an existing control and CCI")
    dupes = db.execute("SELECT COUNT(*) FROM (SELECT CCI_Number FROM CCIs GROUP BY CCI_Number HAVING COUNT(*) > 1)").fetchone()[0]
    check(dupes == 0, "CCI numbers are unique")
    check(db.execute("SELECT COUNT(*) FROM NIST_Controls WHERE ControlFamily IN ('PT','SR')").fetchone()[0] > 0,
          "Rev 5-only families PT and SR are present")

    sql = ("SELECT NC.ControlFamily || '-' || NC.ControlNumber || COALESCE('(' || NC.ControlEnhancement || ')', '') "
           "FROM NIST_ControlsCCIs NCCI JOIN CCIs CI ON NCCI.CCI_ID = CI.CCI_ID "
           "JOIN NIST_Controls NC ON NCCI.NIST_Control_ID = NC.NIST_Control_ID WHERE CI.CCI_Number = ?")
    for cci, expected in (("000015", "AC-2(1)"), ("002107", "AC-1"), ("000366", "CM-6")):
        got = sorted(r[0] for r in db.execute(sql, (cci,)))
        check(expected in got, f"CCI-{cci} reports as {expected} (got {got})")

    nulls = db.execute("SELECT COUNT(*) FROM NIST_Controls WHERE ControlFamily || '-' || ControlNumber || "
                       "COALESCE('(' || ControlEnhancement || ')', '') IS NULL").fetchone()[0]
    check(nulls == 0, "no control renders as NULL in report control column")

    print("\nAll checks passed." if not failures else f"\n{len(failures)} check(s) failed.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
