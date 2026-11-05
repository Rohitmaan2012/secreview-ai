# SecReview AI

**AI-powered security code review: Find. Fix. Fortify.**

SecReview AI analyzes an application's source code, identifies security vulnerabilities, recommends
secure code fixes, and generates a full security assessment report (Markdown, HTML, JSON and SARIF).
It was built for the CDF CyberSec Hackathon (Intelligent Code Security Challenge) and works on any
codebase: React/TypeScript, Node/Deno backends, SQL / Supabase row-level-security policies, Python,
and more.

```
secreview scan ./my-app            # folder
secreview scan ./my-app.zip        # ZIP archive
secreview scan https://github.com/owner/repo/tree/main/sub/dir   # public GitHub repo / sub-folder
secreview web                      # local web UI at http://127.0.0.1:8000
```

---

## How it works

```
  source (folder / ZIP / GitHub URL)
        │  ingest: safe ZIP extraction, skip deps/builds/lockfiles, code treated as untrusted data
        ▼
  1. Static rule engine ─────────── 34 generic, language-aware rules raise *leads* with exact lines
        │                           (secrets, injection & XSS sinks, missing auth, CORS, RLS policies…)
        ▼
  2. AI detection pass (Claude) ─── whole codebase + leads in one context; cross-file reasoning about
        │                           data flow, auth and DB policies; confirms or dismisses each lead and
        │                           finds what regexes can't; returns schema-validated JSON
        ▼
  3. Evidence grounding ─────────── every quoted code snippet is matched to the real file; line numbers
        │                           corrected; findings with non-existent files/evidence are rejected
        ▼
  4. AI review pass (Claude) ────── independent reviewer re-checks each finding: keep / drop / merge,
        │                           re-rates severity, corrects unsafe fixes, adds missed issues, writes
        │                           the executive summary and overall assessment
        ▼
  5. De-duplication + report ───── one finding per root cause → MD / HTML / JSON / SARIF
```

### Why this design scores well on accuracy

* **Evidence-first:** findings must quote verbatim code; the tool verifies it and fixes line numbers,
  so every reported location is real.
* **Two AI passes:** a detector optimized for recall, then a reviewer optimized for precision
  (false positives and duplicates are dropped or merged, and the reason is logged in the report
  appendix).
* **Root-cause de-duplication:** the same flaw seen in several places is one finding with
  "Other affected locations".
* **Confirmed vs. needs validation:** each finding states whether the code alone proves it, or
  whether it depends on runtime context, and lists the assumptions.
* **Placeholder awareness:** obviously fake demo credentials are reported as an insecure pattern,
  not as a "leaked production key".
* **Generic, not hard-coded:** nothing in the rules or prompts names the sample application; the
  tests include a second, unseen Express + Python app.
* **Prompt-injection resistant:** repository content is wrapped as untrusted data, the system prompt
  tells the model never to follow instructions inside code, docs are excluded from analysis by
  default, and the HTML report escapes all code and model output.

### Use of AI

| Stage | What Claude does |
|---|---|
| Detection | Reviews all files together, follows data from request → query/DOM/DB, links frontend, backend functions and SQL policies, assigns CWE/OWASP, severity, confidence and status |
| Lead triage | Confirms or dismisses each static-rule lead with a reason (shown in Appendix B) |
| Fixes | Writes a code-specific, drop-in secure replacement in the project's own language and libraries |
| Review | Independently validates every finding and its fix, merges duplicates, adjusts severity |
| Reporting | Executive summary, overall risk, posture assessment, prioritized remediation plan |

Model: **`claude-opus-5-5`** (override with `--model`) via the official `anthropic` Python SDK, using
adaptive thinking, structured JSON outputs (`output_config.format` with a JSON schema), streaming,
prompt caching (the code block is cached and reused by the review pass), automatic retries, and
server-side refusal fallback.

---

## Setup

Requirements: Python 3.10+ and **one** AI provider (free options included).

```bash
git clone <this repo> && cd secreview-ai
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .                                        # or: pip install -r requirements.txt
```

Then pick a provider:

| Provider | Cost | Setup | Quality |
|---|---|---|---|
| **Claude** (`anthropic`, default) | Paid API (about $0.50–$1 per scan of the sample app) | Key from [console.anthropic.com](https://console.anthropic.com) → `export ANTHROPIC_API_KEY=...` | Best |
| **Google Gemini** (`gemini`) | **Free tier** (no card) | Key from [aistudio.google.com/apikey](https://aistudio.google.com/apikey) → `export GEMINI_API_KEY=...` | Good |
| **Ollama** (`ollama`) | **Free, fully local** | Install [ollama.com](https://ollama.com), run `ollama pull qwen2.5-coder:14b` | Depends on model/hardware |
| Any OpenAI-compatible server | varies | `--provider openai-compatible --base-url ... --model ...` (key in `OPENAI_API_KEY`) | varies |

With `--provider auto` (the default) the tool uses Claude if `ANTHROPIC_API_KEY` is set, otherwise
Gemini if `GEMINI_API_KEY` is set. On Windows PowerShell set keys with `$env:GEMINI_API_KEY = "..."`.
All providers run the same two-pass pipeline, prompts, JSON schema and evidence grounding. Free-tier
providers may use submitted inputs to improve their products; only scan code you are allowed to share.

No provider at all? `--no-ai` runs the rule engine only (clearly labelled as unverified leads), so the
tool still works on air-gapped or CI machines.

## Usage

### Command line

```bash
# Scan the hackathon sample app and write reports to ./reports
secreview scan path/to/CDF-CyberSec-Hackathon/vulnerable-app -o reports

# Straight from GitHub (public repos; sub-folders via /tree/<ref>/<path>)
secreview scan https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app

# Free: Google Gemini free tier, or a local Ollama model
secreview scan ./my-app --provider gemini
secreview scan ./my-app --provider ollama --model qwen2.5-coder:14b

# All formats, only medium and above, fail the build on high (CI)
secreview scan . -f md,html,json,sarif --min-severity medium --fail-on high
```

| Option | Default | Meaning |
|---|---|---|
| `-o, --output` | `reports` | Output folder |
| `-f, --format` | `md,html,json` | Any of `md`, `html`, `json`, `sarif` |
| `--no-ai` | off | Rules-only mode (no API calls) |
| `--provider` | `auto` | `anthropic`, `gemini`, `ollama`, `openai-compatible` |
| `--model` | per provider | e.g. `claude-opus-5-5`, `gemini-3.8-flash`, `qwen2.5-coder:14b` |
| `--base-url` | per provider | Endpoint for `ollama` / `openai-compatible` |
| `--effort` | `high` | Reasoning effort: `low` … `max` |
| `--min-severity` | `info` | Hide findings below this level |
| `--fail-on` | – | Exit code 1 if a finding at/above this level exists |
| `--batch-chars` | 450000 | Max code characters per AI request (large repos are split; SQL schema is shared across batches) |
| `--include-docs` | off | Also send `.md`/`.txt` files to the model |
| `--no-fallback` | off | Disable server-side model fallback |

The terminal prints a colour summary; the full details are in the report files.

### Web interface

```bash
secreview web            # http://127.0.0.1:8000  (SECREVIEW_PROVIDER=gemini|ollama to pick a provider)
```

Paste a GitHub URL or local folder path, or upload a ZIP, pick AI or rules-only mode, and watch the
scan progress. The HTML report opens in the page with download links for MD / HTML / JSON / SARIF.
It binds to localhost by default; use `--no-local-paths` if you expose it to others.

### Report contents

Assessment information · executive summary · overall risk rating · findings by severity and category
· detailed findings (ID, severity, category, CWE, OWASP, file, line range, status, confidence,
description, vulnerable code, impact, example attack, recommended fix, secure code, other affected
locations, validation notes) · remediation summary · overall assessment with prioritized plan and
positive observations · scope and limitations · methodology with AI usage stats · files reviewed ·
static leads dismissed as false positives · draft findings rejected by the reviewer.

The HTML report is self-contained (no external assets), supports dark mode, severity filters, and
prints cleanly to PDF from any browser.

A sample report generated by the tool for CDF TaskFlow (AI mode, Gemini free tier) is in [`sample-report/`](sample-report/): [Markdown](sample-report/cdf-taskflow-security-report.md), [HTML](sample-report/cdf-taskflow-security-report.html), [JSON](sample-report/cdf-taskflow-security-report.json).

---

## Project layout

```
secreview/
  cli.py        command-line entry point
  web.py        Flask web UI
  scanner.py    pipeline orchestration
  ingest.py     folder / ZIP / GitHub loading with zip-slip and size protections
  rules.py      generic static rule engine (leads)
  ai.py         Claude detection + review passes, batching, caching, fallback
  prompts.py    system prompt, instructions and JSON schemas
  verify.py     evidence grounding, line correction, de-duplication
  offline.py    rules-only findings with remediation templates
  report.py     Markdown, HTML, JSON and SARIF writers
tests/          pytest suite (rules, ingest safety, full pipeline with a mocked Claude client)
```

Run the tests: `pip install -e .[dev] && pytest`

## Third-party components

| Component | Use | License |
|---|---|---|
| [anthropic](https://github.com/anthropics/anthropic-sdk-python) | Claude API SDK | MIT |
| [Flask](https://flask.palletsprojects.com/) | Web UI | BSD-3-Clause |
| [pytest](https://pytest.org/) | Tests (dev only) | MIT |
| Claude (`claude-opus-5-5`) by Anthropic | AI analysis, default provider (external API) | API terms |
| Google Gemini / Ollama models (optional) | Alternative free AI providers | Provider terms / model licenses |

Everything else (rule engine, grounding, reports, UI) was written for this hackathon.

## Responsible use

Only scan code you own or are authorized to review. Source code is sent to the Anthropic API in AI
mode, so don't scan confidential code or real secrets unless your organization approves it. The tool
never executes the code it analyzes.

## Limitations

Static analysis only (no runtime testing); dependency CVEs are not checked (pair with `npm audit` /
`pip-audit`); AI findings can still be wrong, so findings marked *needs validation* should be
confirmed by a developer.

## License

MIT
