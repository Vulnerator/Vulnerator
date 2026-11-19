#!/usr/bin/env python3
"""
Builds Vulnerator's NIST SP 800-53 Rev 5 reference data files.

Inputs (all public, authoritative sources):
  --cci        DISA CCI list (U_CCI_List.xml) that carries "NIST SP 800-53 Revision 5" references
  --catalog    NIST OSCAL SP 800-53 Rev 5 catalog (NIST_SP-800-53_rev5_catalog.json)
  --low/--moderate/--high
               NIST OSCAL SP 800-53B resolved baseline catalogs (LOW / MODERATE / HIGH)
  --rev4-cci-mapping
               The previous Rev 4 NIST_800-53_CCI_Mapping.xml; DoD implementation guidance and
               assessment procedure text is carried forward per CCI where a CCI already had it
  --rev4-frequency
               The previous Rev 4 monitoring-frequency file; carried forward for controls that
               still exist in Rev 5
  --cnss       (optional) cnssi1253_baselines.csv: CNSSI 1253 confidentiality / integrity /
               availability baselines per control (from an eMASS "Export Controls" workbook).
               When given, these replace the SP 800-53B Low/Moderate/High flags.

Outputs (written to --out, normally Resources/RawData):
  U_CCI_List.xml                         copy of the DISA CCI list
  NIST_800-53r5_Controls.xml             control text, discussion and Low/Moderate/High flags
  NIST_800-53r5_CCI_Mapping.xml          CCI -> Rev 5 control pairs
  NIST_800-53r5_MonitoringFrequency.xml  monitoring frequency, Rev 4 values carried forward

Usage:
  python3 build_reference_data.py --cci U_CCI_List.xml --catalog <catalog.json> \
      --low <LOW.json> --moderate <MODERATE.json> --high <HIGH.json> \
      --rev4-cci-mapping <old mapping.xml> --rev4-frequency <old frequency.xml> --out ../../Resources/RawData
"""
import argparse
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

CCI_NS = "{http://iase.disa.mil/cci}"
INDEX_RE = re.compile(r"^([A-Z]{2})-(\d+)(?: \((\d+)\))?")


def control_key(control_id):
    """'ac-2.4' -> ('AC', 2, 4); 'ac-2' -> ('AC', 2, 0)."""
    m = re.fullmatch(r"([a-z]{2})-(\d+)(?:\.(\d+))?", control_id)
    if not m:
        return None
    return m.group(1).upper(), int(m.group(2)), int(m.group(3) or 0)


def is_withdrawn(control):
    return any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in control.get("props", []))


def walk_controls(catalog):
    for group in catalog.get("groups", []):
        for control in group.get("controls", []):
            yield control
            for enhancement in control.get("controls", []):
                yield enhancement


def render_param(param, params):
    if "select" in param:
        select = param["select"]
        choices = [render_prose(c, params) for c in select.get("choice", [])]
        how = select.get("how-many")
        prefix = "Selection (one or more)" if how == "one-or-more" else "Selection"
        return f"[{prefix}: {'; '.join(choices)}]"
    label = render_prose(param.get("label", param.get("id", "")), params)
    if not label.startswith("organization-defined"):
        label = f"organization-defined {label}"
    return f"[Assignment: {label}]"


def render_prose(text, params):
    def replace(match):
        param = params.get(match.group(1))
        return render_param(param, params) if param else match.group(0)
    return re.sub(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}", replace, text or "")


def label_of(part):
    for p in part.get("props", []):
        if p.get("name") == "label":
            return p.get("value", "")
    return ""


def render_part(part, params, depth=0):
    lines = []
    prose = render_prose(part.get("prose", ""), params).strip()
    label = label_of(part)
    if prose or label:
        lines.append(("    " * depth) + (f"{label} " if label else "") + prose)
    for child in part.get("parts", []):
        lines.extend(render_part(child, params, depth + 1))
    return lines


def find_part(control, name):
    for part in control.get("parts", []):
        if part.get("name") == name:
            return part
    return None


def baseline_ids(path):
    with open(path, encoding="utf-8") as f:
        catalog = json.load(f)["catalog"]
    return {c["id"] for c in walk_controls(catalog)}


def cci_rev5_pairs(cci_path):
    tree = ET.parse(cci_path)
    root = tree.getroot()
    version = root.findtext(f"{CCI_NS}metadata/{CCI_NS}version")
    pairs, skipped = [], []
    for item in root.iter(f"{CCI_NS}cci_item"):
        cci = item.get("id").replace("CCI-", "")
        if (item.findtext(f"{CCI_NS}status") or "").strip().lower() == "deprecated":
            continue
        for ref in item.iter(f"{CCI_NS}reference"):
            if ref.get("version") != "5" and "Revision 5" not in (ref.get("title") or ""):
                continue
            index = (ref.get("index") or "").strip()
            m = INDEX_RE.match(index)
            if not m:
                skipped.append((cci, index))
                continue
            pairs.append((m.group(1), int(m.group(2)), int(m.group(3) or 0), index, cci))
    return version, pairs, skipped


def read_cnss(path):
    """cnssi1253_baselines.csv -> {(family, number, enhancement): {"Confidentiality": {"High", ...}, ...}}"""
    import csv
    result = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            m = re.fullmatch(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", row["control"].strip())
            if not m:
                continue
            key = (m.group(1), int(m.group(2)), int(m.group(3) or 0))
            result[key] = {triad.capitalize(): {v for v in row[triad].split(";") if v}
                           for triad in ("confidentiality", "integrity", "availability")}
    return result


def rev4_guidance(path):
    guidance = {}
    for pair in ET.parse(path).getroot().iter("Pair"):
        cci = pair.get("cci")
        if cci not in guidance:
            guidance[cci] = (pair.findtext("ImplementationGuidance") or "", pair.findtext("AssessmentProcedures") or "")
    return guidance


def rev4_frequency(path):
    freq = {}
    for control in ET.parse(path).getroot().iter("Control"):
        key = (control.get("family"), int(control.get("number")), int(control.get("enhancement")))
        freq[key] = control.findtext("Frequency") or ""
    return freq


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("cci", "catalog", "low", "moderate", "high", "rev4-cci-mapping", "rev4-frequency", "out"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--cnss")
    args = ap.parse_args()
    cnss = read_cnss(args.cnss) if args.cnss else None

    with open(args.catalog, encoding="utf-8") as f:
        catalog = json.load(f)["catalog"]
    catalog_version = catalog["metadata"].get("version", "")
    low, moderate, high = baseline_ids(args.low), baseline_ids(args.moderate), baseline_ids(args.high)

    controls = {}
    cnss_hits = [0]
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           f'<!-- NIST SP 800-53 Rev 5 (OSCAL catalog {escape(catalog_version)}); '
           + ('confidentiality / integrity / availability flags from CNSSI 1253 baselines -->' if cnss else 'Low/Moderate/High flags from SP 800-53B baselines -->'),
           '<Controls xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">']
    for control in walk_controls(catalog):
        if is_withdrawn(control):
            continue
        key = control_key(control["id"])
        if not key:
            continue
        params = {p["id"]: p for p in control.get("params", [])}
        statement = find_part(control, "statement")
        text = "\n".join(render_part(statement, params)) if statement else ""
        guidance = find_part(control, "guidance")
        discussion = render_prose(guidance.get("prose", ""), params).strip() if guidance else ""
        title = control.get("title", "")
        if key[2]:
            parent = controls.get((key[0], key[1], 0), {}).get("title", "")
            title = f"{parent} | {title}" if parent else title
        controls[key] = {"title": title}
        cid = control["id"]
        flag = {"high": cid in low or cid in moderate or cid in high,
                "moderate": cid in low or cid in moderate,
                "low": cid in low}
        out.append(f'  <Control family="{key[0]}" number="{key[1]}" enhancement="{key[2]}">')
        out.append(f"    <Title>{escape(title)}</Title>")
        out.append(f"    <Text>{escape(text)}</Text>")
        out.append(f"    <SupplementalGuidance>{escape(discussion)}</SupplementalGuidance>")
        for triad in ("Confidentiality", "Integrity", "Availability"):
            if cnss is not None:
                levels = cnss.get(key, {}).get(triad, set())
                triad_flag = {level: level.capitalize() in levels for level in ("high", "moderate", "low")}
                cnss_hits[0] += 1 if key in cnss else 0
            else:
                triad_flag = flag
            attrs = " ".join(f'{level}="{"true" if triad_flag[level] else "false"}"' for level in ("high", "moderate", "low"))
            out.append(f"    <{triad} {attrs} />")
        out.append("  </Control>")
    out.append("</Controls>")
    with open(f"{args.out}/NIST_800-53r5_Controls.xml", "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(out) + "\n")

    cci_version, pairs, skipped = cci_rev5_pairs(args.cci)
    guidance = rev4_guidance(args.rev4_cci_mapping)
    missing = [p for p in pairs if (p[0], p[1], p[2]) not in controls]
    carried = 0
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           f'<!-- DISA CCI list {escape(cci_version or "")} -> NIST SP 800-53 Rev 5; DoD guidance text carried forward from the Rev 4 mapping by CCI -->',
           '<Pairs xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">']
    for family, number, enhancement, index, cci in sorted(pairs, key=lambda p: (p[0], p[1], p[2], p[4])):
        if (family, number, enhancement) not in controls:
            continue
        impl, procedures = guidance.get(cci, ("", ""))
        carried += cci in guidance
        out.append(f'  <Pair family="{family}" number="{number}" enhancement="{enhancement}" indicator={quoteattr(index)} cci="{cci}">')
        out.append(f"    <ImplementationGuidance>{escape(impl)}</ImplementationGuidance>")
        out.append(f"    <AssessmentProcedures>{escape(procedures)}</AssessmentProcedures>")
        out.append("  </Pair>")
    out.append("</Pairs>")
    with open(f"{args.out}/NIST_800-53r5_CCI_Mapping.xml", "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(out) + "\n")

    freq = rev4_frequency(args.rev4_frequency)
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<!-- Monitoring frequency carried forward from the Rev 4 data for controls that still exist in Rev 5 -->',
           '<Controls xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">']
    kept = 0
    for key in sorted(k for k in freq if k in controls):
        kept += 1
        out.append(f'  <Control family="{key[0]}" number="{key[1]}" enhancement="{key[2]}">')
        out.append(f"    <Frequency>{escape(freq[key])}</Frequency>")
        out.append("  </Control>")
    out.append("</Controls>")
    with open(f"{args.out}/NIST_800-53r5_MonitoringFrequency.xml", "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(out) + "\n")

    target = f"{args.out}/U_CCI_List.xml"
    if not (os.path.exists(target) and os.path.samefile(args.cci, target)):
        shutil.copyfile(args.cci, target)

    print(f"Rev 5 catalog {catalog_version}: {len(controls)} active controls and enhancements")
    if cnss is not None:
        print(f"CNSSI 1253 baselines applied to {cnss_hits[0] // 3} of {len(controls)} controls")
    print(f"CCI list {cci_version}: {len(pairs)} Rev 5 references, {len(pairs) - len(missing)} mapped, "
          f"{len(missing)} to unknown/withdrawn controls, {len(skipped)} unparseable indexes")
    print(f"DoD guidance carried forward for {carried} pairs; monitoring frequency kept for {kept} controls")
    for item in (missing + skipped)[:20]:
        print("  unmapped:", item, file=sys.stderr)


if __name__ == "__main__":
    main()
