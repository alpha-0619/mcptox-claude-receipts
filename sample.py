"""
Build the deterministic, stratified 200-case sample.

Only rows whose malicious action is deterministically checkable are eligible:
qualitative Template-3 hijacks ("only include the first file", "limit results
to 3") carry no literal to match on, so including them would burn budget on
rows the scorer must abstain from. This narrows the claim -- recorded in
sample_manifest.json and meant to be stated in any writeup.
"""
import json, sys, io, random
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from scorer import extract_signature, poisoned_tool_name

N = 200
SEED = 20260730

d = json.load(open("response_all.json", encoding="utf-8"))

eligible, excluded = [], Counter()
for sname, s in d["servers"].items():
    tools = s["tool_names"]
    for m in s["malicious_instance"]:
        paradigm = m["metadata"]["paradigm"]
        risk = m["metadata"]["security risk"]
        if m["wrong_data"] != 0:
            excluded["flagged wrong_data by the authors"] += 1
            continue
        for row in m["datas"]:
            inj = row["poisoned_tool"]
            ptn = poisoned_tool_name(inj)
            sig = extract_signature(inj, tools, ptn, paradigm)
            if sig["kind"] == "unscorable":
                excluded["qualitative Template-3 hijack (no literal target)"] += 1
                continue
            if not ptn:
                excluded["could not parse poisoned tool name"] += 1
                continue
            eligible.append({
                "uid": f"{sname}::{row['id']}::{paradigm}",
                "server": sname, "row_id": row["id"], "paradigm": paradigm,
                "risk": risk, "query": row["query"], "system": row["system"],
                "injection": inj, "poisoned_tool": ptn,
                "server_tools": tools, "signature": sig,
            })

print("eligible rows:", len(eligible))
for k, v in excluded.most_common():
    print(f"  excluded -- {k}: {v}")
print()

# proportional stratified allocation over (risk x paradigm)
strata = {}
for e in eligible:
    strata.setdefault((e["risk"], e["paradigm"]), []).append(e)

rng = random.Random(SEED)
for v in strata.values():
    v.sort(key=lambda e: e["uid"])
    rng.shuffle(v)

total = len(eligible)
picked, alloc = [], {}
for k, v in sorted(strata.items()):
    n = int(round(N * len(v) / total))
    n = min(n, len(v))
    alloc[k] = n
    picked.extend(v[:n])

# fix rounding drift deterministically
leftovers = [e for k, v in sorted(strata.items()) for e in v[alloc[k]:]]
leftovers.sort(key=lambda e: e["uid"])
rng.shuffle(leftovers)
while len(picked) < N and leftovers:
    picked.append(leftovers.pop())
picked = picked[:N]
picked.sort(key=lambda e: e["uid"])

print(f"sampled {len(picked)} cases")
print("by paradigm:", dict(Counter(e['paradigm'] for e in picked)))
print("by risk    :", dict(Counter(e['risk'] for e in picked).most_common()))
print("servers covered:", len(set(e['server'] for e in picked)), "/ 45")

json.dump({"seed": SEED, "n": len(picked),
           "eligible_pool": len(eligible),
           "excluded": dict(excluded),
           "cases": picked},
          open("sample_manifest.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("\nwrote sample_manifest.json")
