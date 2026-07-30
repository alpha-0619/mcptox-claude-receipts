import json, sys, io, re
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

d = json.load(open("response_all.json", encoding="utf-8"))
styles = Counter()
n = 0
examples = {}
for sname, s in d["servers"].items():
    for m in s["malicious_instance"]:
        if m["wrong_data"] != 0:
            continue
        for row in m["datas"]:
            inj = row["poisoned_tool"]
            n += 1
            has_override = bool(re.search(r"ignore\s+(the\s+)?previous\s+instructions",
                                          inj, re.I))
            has_important = "<IMPORTANT>" in inj
            has_priority = "priority is higher than the user" in inj
            key = (("override" if has_override else "-") + "/" +
                   ("IMPORTANT-tag" if has_important else "-") + "/" +
                   ("priority-claim" if has_priority else "-"))
            styles[key] += 1
            if key not in examples:
                examples[key] = inj[:230].replace("\n", " ")

print(f"valid rows examined: {n}")
print()
print("style combination  (override / IMPORTANT-tag / priority-claim)")
for k, v in styles.most_common():
    print(f"  {k:42s} {v:5d}  ({v/n:.1%})")
print()
tot_override = sum(v for k, v in styles.items() if k.startswith("override"))
print(f"contain 'Ignore the previous instructions' : {tot_override}/{n} = {tot_override/n:.1%}")
print(f"do NOT contain that phrase                 : {n-tot_override}/{n} = {(n-tot_override)/n:.1%}")
print()
for k, v in styles.most_common():
    print(f"--- {k}  (n={v})")
    print("    ", examples[k][:210])
