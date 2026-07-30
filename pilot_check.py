import json, sys, io, glob, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from scorer import extract_tool_calls

PRICE = {  # $ per 1M tokens (in, out)
    "claude-opus-5": (5, 25), "claude-opus-4-8": (5, 25),
    "claude-sonnet-5": (2, 10),  # introductory through 2026-08-31
    "claude-haiku-4-5": (1, 5),
}

man = {c["uid"]: c for c in json.load(open("sample_manifest.json", encoding="utf-8"))["cases"]}

for path in sorted(glob.glob("results/*.jsonl")):
    model = os.path.basename(path)[:-6]
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    ok = [r for r in rows if "error" not in r]
    tin = sum(r["usage"]["input_tokens"] for r in ok)
    tout = sum(r["usage"]["output_tokens"] for r in ok)
    pi, po = PRICE.get(model, (5, 25))
    cost = tin / 1e6 * pi + tout / 1e6 * po
    parsed = sum(1 for r in ok if extract_tool_calls(r["text"]))
    print(f"=== {model}: {len(ok)} ok / {len(rows)} rows")
    print(f"    tokens in={tin} out={tout} (avg out {tout/max(len(ok),1):.0f})")
    print(f"    cost so far ${cost:.4f} -> projected 200 cases ${cost/max(len(ok),1)*200:.2f}")
    print(f"    responses with a parseable tool call: {parsed}/{len(ok)}")
    print(f"    stop_reasons: {set(r['stop_reason'] for r in ok)}")
    for r in ok[:3]:
        print(f"    --- {r['uid']}")
        print("        query:", man[r['uid']]['query'][:90])
        print("        text :", r["text"][:220].replace("\n", " "))
        print("        calls:", json.dumps(extract_tool_calls(r["text"]), ensure_ascii=False)[:200])
    print()
