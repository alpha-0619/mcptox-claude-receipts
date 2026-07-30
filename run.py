"""
Run the MCPTox sample against Claude models.

Protocol is the benchmark's own: tools are rendered as text inside the system
prompt (not native tool-use), and the model is asked to reply with a JSON
{"tool": ..., "arguments": {...}} object. Keeping that protocol is what makes
the numbers comparable to the paper's 20 models.

Results are cached per (model, case) in results/<model>.jsonl so a re-run never
re-pays for work already done.
"""
import json, os, sys, io, time, threading, argparse, urllib.request, urllib.error

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# Put ANTHROPIC_API_KEY=... in a .env file next to this script.
ENV_CANDIDATES = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
]
URL = "https://api.anthropic.com/v1/messages"
OUT = "results"

# Per-model config. `thinking` reflects each model's DEFAULT deployment state:
# Opus 5 and Sonnet 5 run adaptive thinking when the field is omitted, Opus 4.8
# runs without it, and Haiku 4.5 predates adaptive thinking entirely. Recorded
# per row so the confound is visible rather than buried.
MODELS = {
    "claude-opus-5":     {"thinking": "adaptive-default"},
    "claude-opus-4-8":   {"thinking": "off-default"},
    "claude-sonnet-5":   {"thinking": "adaptive-default"},
    "claude-haiku-4-5":  {"thinking": "off-default"},
}
MAX_TOKENS = 4000


def api_key():
    for path in ENV_CANDIDATES:
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8", errors="replace"):
            if line.startswith("ANTHROPIC_API_KEY"):
                k = line.split("=", 1)[1].strip().strip('"').strip("'")
                if k and "PASTE_YOUR_KEY" not in k:
                    print(f"using key from {path} (...{k[-6:]})")
                    return k
    raise SystemExit("no usable ANTHROPIC_API_KEY found in: " +
                     ", ".join(ENV_CANDIDATES))


KEY = api_key()
_print_lock = threading.Lock()
_file_lock = threading.Lock()


def call(model, system, query, attempt=0):
    body = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": system,
        "messages": [{"role": "user", "content": query}],
    }
    req = urllib.request.Request(
        URL, data=json.dumps(body).encode("utf-8"),
        headers={"x-api-key": KEY, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        if e.code in (429, 500, 502, 503, 529) and attempt < 6:
            time.sleep(min(2 ** attempt * 2, 60))
            return call(model, system, query, attempt + 1)
        return None, f"HTTP {e.code}: {detail}"
    except Exception as e:
        if attempt < 6:
            time.sleep(min(2 ** attempt * 2, 60))
            return call(model, system, query, attempt + 1)
        return None, f"{type(e).__name__}: {e}"


def text_of(resp):
    parts = []
    for b in resp.get("content", []):
        if b.get("type") == "text":
            parts.append(b.get("text", ""))
    return "\n".join(parts)


def worker(model, cases, done, path, counters):
    while True:
        with _file_lock:
            if not cases:
                return
            c = cases.pop()
        if c["uid"] in done:
            continue
        resp, err = call(model, c["system"], c["query"])
        rec = {"uid": c["uid"], "model": model}
        if err:
            rec["error"] = err
        else:
            rec["text"] = text_of(resp)
            rec["stop_reason"] = resp.get("stop_reason")
            rec["usage"] = resp.get("usage")
        with _file_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            counters[0] += 1
            if err:
                counters[1] += 1
            n, e = counters[0], counters[1]
        if n % 10 == 0:
            with _print_lock:
                print(f"  [{model}] {n} done ({e} errors)", flush=True)


def run_model(model, cases, limit=None):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, model.replace("/", "_") + ".jsonl")
    done = set()
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            try:
                r = json.loads(line)
                if "error" not in r:
                    done.add(r["uid"])
            except Exception:
                pass
    todo = [c for c in cases if c["uid"] not in done]
    if limit:
        todo = todo[:limit]
    print(f"{model}: {len(done)} cached, {len(todo)} to run")
    if not todo:
        return
    pool = list(todo)
    counters = [0, 0]
    threads = [threading.Thread(target=worker,
                                args=(model, pool, done, path, counters))
               for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"{model}: finished, {counters[0]} calls, {counters[1]} errors")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default=",".join(MODELS))
    ap.add_argument("--limit", type=int, default=None,
                    help="pilot mode: only run this many cases per model")
    a = ap.parse_args()

    man = json.load(open("sample_manifest.json", encoding="utf-8"))
    cases = man["cases"]
    for model in a.models.split(","):
        model = model.strip()
        if not model:
            continue
        t0 = time.time()
        run_model(model, cases, a.limit)
        print(f"  elapsed {time.time()-t0:.0f}s\n")


if __name__ == "__main__":
    main()
