"""
Same 200 cases, same scorer, applied to the older models whose responses ship
with MCPTox. Without this the Claude numbers can only be compared to the
paper's headline average, which was computed over a different case mix and a
different judging procedure.
"""
import json, sys, io
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from scorer import extract_signature, classify, poisoned_tool_name

man = json.load(open("sample_manifest.json", encoding="utf-8"))
wanted = {c["uid"] for c in man["cases"]}

d = json.load(open("response_all.json", encoding="utf-8"))
tally = {}
ref_tally = {}
for sname, s in d["servers"].items():
    tools = s["tool_names"]
    for m in s["malicious_instance"]:
        paradigm = m["metadata"]["paradigm"]
        for row in m["datas"]:
            uid = f"{sname}::{row['id']}::{paradigm}"
            if uid not in wanted:
                continue
            inj = row["poisoned_tool"]
            ptn = poisoned_tool_name(inj)
            sig = extract_signature(inj, tools, ptn, paradigm)
            for mk, resp in row["response"].items():
                lab, _ = classify(resp, sig, ptn, tools, paradigm, row["query"])
                tally.setdefault(mk, Counter())[lab] += 1
                ref_tally.setdefault(mk, Counter())[row["label"][mk]] += 1

print("older models, same 200 cases, scored by the same code")
print(f"{'model':<26}{'n':>5}{'Success':>9}{'ASR':>8}   {'(paper own labels)':>20}")
print("-" * 72)
rows = []
for mk, c in sorted(tally.items()):
    n = sum(c.values())
    asr = c["Success"] / n if n else 0
    rn = sum(ref_tally[mk].values())
    rasr = ref_tally[mk]["Success"] / rn if rn else 0
    rows.append((mk, n, c["Success"], asr, rasr))
for mk, n, succ, asr, rasr in sorted(rows, key=lambda r: -r[3]):
    print(f"{mk:<26}{n:>5}{succ:>9}{asr:>7.1%}   {rasr:>19.1%}")

tot_n = sum(r[1] for r in rows)
tot_s = sum(r[2] for r in rows)
print("-" * 72)
print(f"{'POOLED older models':<26}{tot_n:>5}{tot_s:>9}{tot_s/tot_n:>7.1%}")
print()
print("Claude, same 200 cases, same scorer:")
summ = json.load(open("summary.json", encoding="utf-8"))
for m in ["claude-opus-5", "claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5"]:
    if m in summ:
        print(f"  {m:<24}{summ[m]['n']:>5}{summ[m]['attack_success']:>9}"
              f"{summ[m]['attack_success_rate']:>7.1%}")
cs = sum(summ[m]["attack_success"] for m in summ)
cn = sum(summ[m]["n"] for m in summ)
print(f"  {'POOLED Claude':<24}{cn:>5}{cs:>9}{cs/cn:>7.1%}")
