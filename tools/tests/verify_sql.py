#!/usr/bin/env python3
"""
Compiles every SQL statement Vulnerator ships (Resources/DdlFiles/StoredProcedures) against the schema it
creates (Resources/DdlFiles/Tables/Create), using SQLite's own parser. Catches statements that reference
missing tables or columns, or supply the wrong number of values - errors that otherwise surface only when
a user clicks the feature.

KNOWN_BROKEN lists statements that fail today for a documented reason. A statement not on the list that
fails, or a listed one that now passes (so it can be removed from the list), fails the check.
Usage: python3 verify_sql.py [repo root]
"""
import glob
import os
import sqlite3
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..")
DDL = os.path.join(ROOT, "Resources", "DdlFiles")

KNOWN_BROKEN = {
    # Templates: the code substitutes the column name before running them.
    "Select/ReportUseGlobalValueUserSettings.dml": "COLUMN_NAME placeholder replaced at runtime",
    "Update/ReportUseGlobalValueUserSettings.dml": "COLUMN_NAME placeholder replaced at runtime",
    # Upstream hardware/software-management work left unfinished in Nov 2021 (Configuration Management screens).
    "Insert/HardwareSoftwareMappingWithIds.dml": "unbalanced parentheses (upstream, asset management)",
    "Insert/SoftwareHardwarePortProtocolServiceMappingWithIds.dml": "unbalanced parentheses (upstream, asset management)",
    "Insert/BoundaryHardwareSoftwarePortProtocolServiceMappingWithIds.dml": "unbalanced parentheses (upstream, asset management)",
    "Insert/HardwareVulnerabilitySourceMapping.dml": "table Hardware_VulnerabilitySources no longer exists (upstream)",
    "Delete/GroupContactMappingByGroup.dml": "table GroupsContacts does not exist; method has no callers",
}


def main():
    db = sqlite3.connect(":memory:")
    for path in sorted(glob.glob(os.path.join(DDL, "Tables", "Create", "*.ddl"))):
        with open(path, encoding="utf-8-sig") as f:
            db.executescript(f.read())

    failures = []
    still_broken = set()
    for path in sorted(glob.glob(os.path.join(DDL, "StoredProcedures", "*", "*.dml"))):
        name = os.path.relpath(path, os.path.join(DDL, "StoredProcedures")).replace(os.sep, "/")
        with open(path, encoding="utf-8-sig") as f:
            sql = f.read().strip().rstrip(";")
        error = None
        try:
            db.execute("EXPLAIN " + sql, {})
        except sqlite3.ProgrammingError:
            pass  # unbound parameters: the statement compiled
        except (sqlite3.OperationalError, sqlite3.Warning) as e:
            error = str(e)
        if error and name in KNOWN_BROKEN:
            still_broken.add(name)
        elif error:
            failures.append(f"{name}: {error}")

    for name in sorted(set(KNOWN_BROKEN) - still_broken):
        failures.append(f"{name}: now compiles - remove it from KNOWN_BROKEN")
    print(f"{len(still_broken)} known-broken statement(s) skipped; {len(failures)} problem(s)")
    for failure in failures:
        print("FAIL " + failure)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
