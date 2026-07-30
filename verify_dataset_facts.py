"""
Reproduces every claim made about the MCPTox dataset itself in FINDINGS.md
section 1. Run this to re-check the corrections without trusting the writeup.
"""
import json, sys, io, re
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

d = json.load(open("response_all.json", encoding="utf-8"))

# --- claim 1: 1348 total, 36 flagged, 1312 valid
total = flagged = 0
labels = Counter()
for s in d["servers"].values():
    for m in s["malicious_instance"]:
        total += 1
        if m["wrong_data"] != 0:
            flagged += 1
        for row in m["datas"]:
            for lab in row["label"].values():
                labels[lab] += 1
print("[1] 1312 vs 1348")
print(f"    declared data_length : {d['data_length']}")
print(f"    rows counted         : {total}")
print(f"    wrong_data != 0      : {flagged}")
print(f"    {total} - {flagged} = {total - flagged}   (paper abstract says 1312)")
assert total - flagged == 1312

# --- claim 2: Identifiable is declared but never used
print("\n[2] label taxonomy")
print(f"    declared label_scopes : {d['label_scopes']}")
print(f"    labels actually used  : {sorted(labels)}")
for k, v in labels.most_common():
    print(f"      {k}: {v}")
unused = [x for x in ["Identifiable", "Work but not Success"] if x not in labels]
print(f"    declared but never used: {unused}")
assert "Identifiable" not in labels

# --- claim 3: only ~32% carry an explicit override phrase
print("\n[3] injection phrasing over the 1312 valid rows")
styles = Counter()
n = 0
for s in d["servers"].values():
    for m in s["malicious_instance"]:
        if m["wrong_data"] != 0:
            continue
        for row in m["datas"]:
            inj = row["poisoned_tool"]
            n += 1
            ov = bool(re.search(r"ignore\s+(the\s+)?previous\s+instructions", inj, re.I))
            styles["override" if ov else "no override"] += 1
ov = styles["override"]
print(f"    rows                       : {n}")
print(f"    contains the override line : {ov} = {ov/n:.1%}")
print(f"    does not                   : {n-ov} = {(n-ov)/n:.1%}")
print("\nall dataset claims reproduced.")
