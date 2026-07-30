"""
Rebuild the exact manifest for the 200 cases that were actually run.

sample.py documents how the sample was originally drawn, but re-running it is
not the right way to reproduce this experiment: the eligibility filter was
refined after the sample was drawn (five scorer bugs were fixed during the hand
audit), so a fresh draw would not necessarily return the same 200 cases.
sample_uids.json is the authoritative record, and this hydrates it from the
benchmark data.
"""
import json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from scorer import extract_signature, poisoned_tool_name

ids = json.load(open("sample_uids.json", encoding="utf-8"))
want = set(ids["uids"])

d = json.load(open("response_all.json", encoding="utf-8"))
cases = []
for sname, s in d["servers"].items():
    tools = s["tool_names"]
    for m in s["malicious_instance"]:
        paradigm = m["metadata"]["paradigm"]
        for row in m["datas"]:
            uid = f"{sname}::{row['id']}::{paradigm}"
            if uid not in want:
                continue
            inj = row["poisoned_tool"]
            ptn = poisoned_tool_name(inj)
            cases.append({
                "uid": uid, "server": sname, "row_id": row["id"],
                "paradigm": paradigm, "risk": m["metadata"]["security risk"],
                "query": row["query"], "system": row["system"],
                "injection": inj, "poisoned_tool": ptn,
                "server_tools": tools,
                "signature": extract_signature(inj, tools, ptn, paradigm),
            })

cases.sort(key=lambda c: c["uid"])
missing = want - {c["uid"] for c in cases}
if missing:
    print(f"WARNING: {len(missing)} ids not found in the benchmark data:")
    for u in sorted(missing)[:10]:
        print("   ", u)

json.dump({"seed": ids["seed"], "n": len(cases),
           "eligible_pool": ids["eligible_pool"],
           "excluded": ids["excluded"], "cases": cases},
          open("sample_manifest.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print(f"rebuilt sample_manifest.json with {len(cases)} / {len(want)} cases")
print("next: python analyze.py")
