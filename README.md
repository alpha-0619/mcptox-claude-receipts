# tool-description injection vs Claude 4.x / 5

Receipts for [this post](https://lumebuilds.substack.com/p/i-ran-800-attacks-against-claude): 800 runs of the
[MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark) benchmark
(tool-*description* poisoning, not tool-result injection) against Claude Opus 5,
Opus 4.8, Sonnet 5 and Haiku 4.5.

Headline: the four models land between 3.5% and 6.5% attack success, a spread too
small to rank at n=200. The finding that does hold up is that success depends
heavily on how *blatant* the injection is. Attacks opening with "Ignore the
previous instructions" got through 2 times in 248. Attacks that just calmly state
a fake reason got through 25 times in 248.

## reproduce it

```
pip install pymupdf          # only needed for the system-card checks
python fetch_benchmark.py    # clones MCPTox, copies out its data files
python build_manifest.py     # hydrates the exact 200 cases that were run
python analyze.py            # every number in the post, from the raw responses
```

Two more worth running:

```
python verify_dataset_facts.py   # rechecks every claim the post makes about the dataset
python validate_scorer.py        # scores my scorer against MCPTox's 7,368 human labels
```

`validate_scorer.py` should print 97.1% binary agreement, 97.4% precision, 83.1%
recall. That is the number that decides how much of this you should believe.

To re-run the models themselves you need an Anthropic API key in `.env` as
`ANTHROPIC_API_KEY=...`, then `python run.py`. It caches per (model, case), so a
re-run only pays for what is missing. The full 800 cost $7.06.

## what's here

- `scorer.py` — the deterministic scorer. No LLM judge: it extracts the tool and
  argument values the injection demands, then checks them against the tool call
  the model actually emitted.
- `results/*.jsonl` — all 800 raw model responses, with token usage.
- `sample_uids.json` — the exact 200 case ids, plus the seed and the exclusion counts.
- `analyze.py`, `validate_scorer.py`, `verify_dataset_facts.py` — see above.
- `baseline.py` — scores the 11 older models MCPTox published responses for, on
  the same 200 cases with the same code, so old-vs-new is like for like.
- `audit.py`, `find_fn.py` — the two hand-audit views. `audit.py` lists every case
  flagged as a successful attack; `find_fn.py` sweeps the other direction for
  attacks the scorer may have missed. Both were needed: hand-auditing found five
  real bugs in `scorer.py` and took precision from 79.7% to 97.4%.
- `sample.py` — how the sample was originally drawn. Kept for transparency, but
  use `build_manifest.py` to reproduce: the eligibility filter was refined after
  the draw, so a fresh draw is not guaranteed to return the same 200 cases.

## what's deliberately not here

MCPTox's own data files (`response_all.json`, `pure_tool.json`, `def_tool/`). That
repo ships no licence, so `fetch_benchmark.py` pulls them from the original source
rather than redistributing them here. `sample_manifest.json` is also generated
rather than committed, because it embeds their prompt text.

## known limitations

- The sample only covers cases whose malicious action is checkable by code. 369
  of the 1,312 valid cases are qualitative ("only include the first file"), and
  those are excluded rather than guessed at.
- This is the benchmark's own protocol: tools rendered as text in the system
  prompt, model replies with JSON. That is what makes the numbers comparable to
  the paper's 20 models, but it is not a real MCP client doing native tool calls.
- Each model ran at its own deployment default, so thinking settings differ
  across the four. Realistic, but a confound for cross-model comparison.
- Recall is 83%, so the scorer misses some real hits. One known class: injections
  written as fill-in-the-blank templates, where the model substitutes real values
  and defeats literal matching. Opus 5's count is 13 rather than the 12 the code
  reports because of one such case found by hand.

Found a case scored wrong? Open an issue. Re-running everything is seven dollars.
