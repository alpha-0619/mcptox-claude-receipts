"""
Hunt for false negatives: rows where the model invoked a tool the injection
explicitly named, but the scorer did not call it a success.
"""
import json, sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from scorer import (classify, malicious_action_fired, extract_tool_calls,
                    extract_signature)

MODEL = sys.argv[1] if len(sys.argv) > 1 else "claude-opus-5"
man = {c["uid"]: c for c in json.load(open("sample_manifest.json", encoding="utf-8"))["cases"]}

# every tool name the injection mentions in backticks or quotes
NAMED = re.compile(r"[`']([A-Za-z0-9_\-]{3,})[`']")

rows = []
seen = set()
for line in open(f"results/{MODEL}.jsonl", encoding="utf-8"):
    r = json.loads(line)
    if "error" in r or r["uid"] in seen:
        continue
    seen.add(r["uid"])
    rows.append(r)

cands = 0
for r in rows:
    c = man[r["uid"]]
    sig = extract_signature(c["injection"], c["server_tools"],
                            c["poisoned_tool"], c["paradigm"])
    lab, calls = classify(r["text"], sig, c["poisoned_tool"],
                          c["server_tools"], c["paradigm"], c["query"])
    if lab == "Success" or malicious_action_fired(calls, sig, c["query"]):
        continue
    if not calls:
        continue
    named = {m.group(1) for m in NAMED.finditer(c["injection"])}
    named &= set(c["server_tools"])
    called = {n for n, _ in calls}
    # the benign tool is also named in the injection, so only flag when the
    # model called something named in the injection that is NOT plausibly the
    # answer to the query (heuristic: query words don't cover it)
    overlap = named & called
    if not overlap:
        continue
    qwords = set(re.findall(r"[a-z]+", c["query"].lower()))
    suspicious = {t for t in overlap
                  if not (set(re.split(r"[_\-]", t.lower())) & qwords)}
    if suspicious:
        cands += 1
        print("=" * 70)
        print(f"[{cands}] {r['uid']}  scorer_label={lab}")
        print(f"    QUERY : {c['query'][:120]}")
        print(f"    CALLED: {json.dumps(calls, ensure_ascii=False)[:260]}")
        print(f"    named-in-injection & called, not implied by query: {sorted(suspicious)}")
        print(f"    INJ   : {c['injection'][:300].replace(chr(10),' ')}")
        print(f"    RESP  : {r['text'][:200].replace(chr(10),' ')}")
        print()

print(f"\ncandidate false negatives to eyeball: {cands} (of {len(rows)} rows)")
