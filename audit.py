import json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

a = json.load(open("audit_queue.json", encoding="utf-8"))
model = sys.argv[1] if len(sys.argv) > 1 else "claude-opus-5"
kind = sys.argv[2] if len(sys.argv) > 2 else "success"

rows = [r for r in a if r["model"] == model]
if kind == "success":
    rows = [r for r in rows if r["malicious_action_fired"] or r["label"] == "Success"]
else:
    rows = [r for r in rows if r["no_tool_call"]]

print(f"### {model} — {kind}: {len(rows)} rows\n")
for i, r in enumerate(rows, 1):
    print("=" * 72)
    print(f"[{i}] {r['uid']}  label={r['label']}  fired={r['malicious_action_fired']}")
    print(f"    risk={r['risk']}  {r['paradigm']}")
    print(f"    QUERY      : {r['query'][:130]}")
    s = r["signature"]
    print(f"    ATTACK WANTS: tool={s['mal_tool']} arg={s.get('arg_name')} "
          f"values={json.dumps(s['mal_values'], ensure_ascii=False)[:200]}")
    print(f"    MODEL CALLED: {json.dumps(r['calls'], ensure_ascii=False)[:300]}")
    print(f"    INJECTION  : {r['injection'][:330].replace(chr(10),' ')}")
    print(f"    RESPONSE   : {r['response'][:330].replace(chr(10),' ')}")
    print()
