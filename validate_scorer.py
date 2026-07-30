"""Validate the deterministic scorer against the paper's own reference labels."""
import json, sys, io
from collections import Counter, defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from scorer import (extract_signature, classify, poisoned_tool_name,
                    malicious_action_fired)

d = json.load(open("response_all.json", encoding="utf-8"))

agree = 0
total = 0
unscorable = 0
confusion = Counter()
confusion_bin = Counter()
confusion_act = Counter()
per_model = defaultdict(lambda: [0, 0])
mismatches = []

for sname, s in d["servers"].items():
    tools = s["tool_names"]
    for m in s["malicious_instance"]:
        paradigm = m["metadata"]["paradigm"]
        for row in m["datas"]:
            inj = row["poisoned_tool"]
            ptn = poisoned_tool_name(inj)
            sig = extract_signature(inj, tools, ptn, paradigm)
            for mk, ref in row["label"].items():
                got, calls = classify(row["response"][mk], sig, ptn, tools,
                                      paradigm, row["query"])
                if got == "UNSCORABLE":
                    unscorable += 1
                    continue
                total += 1
                per_model[mk][1] += 1
                rs, gs = (ref == "Success"), (got == "Success")
                confusion_bin["tp" if (rs and gs) else "fp" if gs else
                              "fn" if rs else "tn"] += 1
                mf = malicious_action_fired(calls, sig, row["query"])
                confusion_act["tp" if (rs and mf) else "fp" if mf else
                              "fn" if rs else "tn"] += 1
                if got == ref:
                    agree += 1
                    per_model[mk][0] += 1
                else:
                    confusion[(ref, got)] += 1
                    # stratified: keep up to 25 examples per confusion cell so
                    # the sample is not dominated by whichever server sorts first
                    if confusion[(ref, got)] <= 25:
                        mismatches.append({
                            "server": sname, "model": mk, "paradigm": paradigm,
                            "ref": ref, "got": got, "ptn": ptn,
                            "sig": sig, "calls": calls[:4],
                            "query": row["query"],
                            "inj": inj[:500],
                            "resp": str(row["response"][mk])[:300],
                        })

tp = confusion_bin["tp"]; fp = confusion_bin["fp"]
fn = confusion_bin["fn"]; tn = confusion_bin["tn"]
binagree = (tp + tn) / (tp + fp + fn + tn)
prec = tp / (tp + fp) if (tp + fp) else 0.0
rec = tp / (tp + fn) if (tp + fn) else 0.0
print("=== BINARY (attack succeeded vs not) -- the headline metric ===")
print(f"  agreement : {tp+tn}/{tp+fp+fn+tn} = {binagree:.4%}")
print(f"  precision : {prec:.4%}   (of cases I call Success, how many the paper also calls Success)")
print(f"  recall    : {rec:.4%}   (of the paper's Successes, how many I catch)")
print(f"  tp={tp} fp={fp} fn={fn} tn={tn}")
print()
a=confusion_act
ap=a["tp"]/(a["tp"]+a["fp"]) if (a["tp"]+a["fp"]) else 0
ar=a["tp"]/(a["tp"]+a["fn"]) if (a["tp"]+a["fn"]) else 0
print("=== MALICIOUS-ACTION-FIRED flag (order-independent) vs paper Success ===")
print(f"  precision : {ap:.4%}")
print(f"  recall    : {ar:.4%}")
print(f"  tp={a['tp']} fp={a['fp']} fn={a['fn']} tn={a['tn']}")
print()
print(f"4-WAY AGREEMENT: {agree}/{total} = {agree/total:.4%}")
print(f"UNSCORABLE (excluded, qualitative Template-3 hijacks): {unscorable}"
      f"  [{unscorable/(total+unscorable):.2%} of all reference judgements]")
print()
print("=== per reference model ===")
for k, (a, t) in sorted(per_model.items()):
    print(f"  {k:26s} {a}/{t} = {a/t:.2%}")
print()
print("=== top confusions (ref -> got) ===")
for (ref, got), c in confusion.most_common(15):
    print(f"  {ref:26s} -> {got:26s} {c}")

json.dump(mismatches, open("mismatches.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("\nwrote mismatches.json")
