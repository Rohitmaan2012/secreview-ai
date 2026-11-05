"""Report writers: Markdown, self-contained HTML, JSON and SARIF 2.1.0."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from .models import SEVERITIES, Finding, ScanResult

SEV_LABEL = {s: s.capitalize() for s in SEVERITIES}
STATUS_LABEL = {"confirmed": "Confirmed", "needs_validation": "Needs validation"}
SOURCE_LABEL = {"ai": "AI analysis", "ai+rules": "AI analysis + static rule", "rules": "Static rule (unverified)"}


def _fence(code: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", code)), default=0)
    return "`" * max(3, longest + 1)


def _loc(f: Finding) -> str:
    return f"line {f.start_line}" if f.start_line == f.end_line else f"lines {f.start_line}-{f.end_line}"


def _lang(f: Finding) -> str:
    ext = f.file.rsplit(".", 1)[-1].lower() if "." in f.file else ""
    return {"ts": "typescript", "tsx": "tsx", "js": "javascript", "jsx": "jsx", "sql": "sql",
            "py": "python"}.get(ext, ext)


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "report"


# ---------------------------------------------------------------- Markdown
def to_markdown(r: ScanResult) -> str:
    c = r.severity_counts()
    total = len(r.findings)
    out: list[str] = []
    w = out.append
    w(f"# Security Assessment Report: {r.target_name}\n")
    w("## 1. Assessment Information\n")
    w(f"| | |\n|---|---|\n| **Application** | {r.target_name} |\n| **Source** | `{r.target_source}` |")
    w(f"| **Assessment type** | {'AI-assisted static code review' if r.mode == 'ai' else 'Rule-based static code review (no AI)'} |")
    w(f"| **Assessment date** | {r.scanned_at} |\n| **Tool** | {r.tool_name} v{r.tool_version} |")
    if r.model:
        w(f"| **AI model** | {r.model} |")
    w(f"| **Files / lines reviewed** | {r.stats.get('files_scanned', len(r.files))} files, {r.stats.get('lines_scanned', 0)} lines |")
    w(f"| **Overall risk rating** | **{r.overall_risk.upper()}** |\n")

    w("## 2. Executive Summary\n")
    w(r.executive_summary.strip() + "\n")
    w("> AI-assisted findings were grounded against the source code and reviewed in a second, "
      "independent AI pass. Items marked *Needs validation* depend on runtime context and should be "
      "confirmed before being treated as exploitable.\n" if r.mode == "ai" else
      "> Rules-only mode: findings are heuristic leads and have not been verified.\n")

    w("## 3. Findings Summary\n")
    w("| Severity | Count |\n|---|---:|")
    for s in SEVERITIES:
        w(f"| {SEV_LABEL[s]} | {c[s]} |")
    w(f"| **Total** | **{total}** |\n")
    if total:
        w("| ID | Severity | Title | Location | Status |\n|---|---|---|---|---|")
        for f in r.findings:
            w(f"| [{f.id}](#{f.id.lower()}) | {SEV_LABEL[f.severity]} | {f.title} | `{f.file}:{f.start_line}` | {STATUS_LABEL.get(f.status, f.status)} |")
        w("")
        cats: dict[str, int] = {}
        for f in r.findings:
            cats[f.category] = cats.get(f.category, 0) + 1
        w("**By category:** " + ", ".join(f"{k} ({v})" for k, v in sorted(cats.items(), key=lambda kv: -kv[1])) + "\n")

    w("## 4. Detailed Findings\n")
    if not total:
        w("No findings at or above the selected severity threshold.\n")
    for f in r.findings:
        w(f'<a id="{f.id.lower()}"></a>\n### {f.id}: {f.title}\n')
        w(f"| | |\n|---|---|\n| **Severity** | {SEV_LABEL[f.severity]} |\n| **Category** | {f.category} |")
        w(f"| **CWE** | {f.cwe} |" + (f"\n| **OWASP** | {f.owasp} |" if f.owasp else ""))
        w(f"| **Affected file** | `{f.file}` |\n| **Code location** | {_loc(f)} |")
        w(f"| **Status** | {STATUS_LABEL.get(f.status, f.status)} |\n| **Confidence** | {f.confidence.capitalize()} |")
        w(f"| **Detected by** | {SOURCE_LABEL.get(f.source, f.source)} |\n")
        w(f"#### Description\n\n{f.description.strip()}\n")
        fence = _fence(f.evidence)
        w(f"#### Vulnerable Code (`{f.file}`, {_loc(f)})\n\n{fence}{_lang(f)}\n{f.evidence}\n{fence}\n")
        w(f"#### Potential Impact\n\n{f.impact.strip()}\n")
        if f.exploit_scenario.strip():
            w(f"#### Example Attack Scenario\n\n{f.exploit_scenario.strip()}\n")
        w(f"#### Recommended Fix\n\n{f.remediation.strip()}\n")
        if f.secure_code.strip():
            fence = _fence(f.secure_code)
            w(f"#### Secure Code Example\n\n{fence}{f.secure_code_language or _lang(f)}\n{f.secure_code.rstrip()}\n{fence}\n")
        if f.related_locations:
            w("#### Other Affected Locations\n")
            for rl in f.related_locations:
                w(f"- `{rl.file}:{rl.line}` {('- ' + rl.note) if rl.note else ''}")
            w("")
        notes = " ".join(x for x in [f.assumptions.strip(), f.review_note.strip()] if x)
        if notes:
            w(f"#### Validation Notes\n\n{notes}\n")
        w("---\n")

    w("## 5. Remediation Summary\n")
    w("| Finding | Severity | File | Recommended Action |\n|---|---|---|---|")
    for f in r.findings:
        action = f.remediation.strip().split(". ")[0].replace("|", "\\|").replace("\n", " ")
        w(f"| {f.id} | {SEV_LABEL[f.severity]} | `{f.file}` | {action.rstrip('.')}. |")
    w("")

    w("## 6. Overall Assessment\n")
    w(f"**Overall risk rating: {r.overall_risk.upper()}**\n")
    w(r.overall_assessment.strip() + "\n")
    if r.prioritized_actions:
        w("### Prioritized Remediation Plan\n")
        for i, a in enumerate(r.prioritized_actions, 1):
            w(f"{i}. {a}")
        w("")
    if r.positive_observations:
        w("### Positive Observations\n")
        for p in r.positive_observations:
            w(f"- {p}")
        w("")

    w("## 7. Scope and Limitations\n")
    for lim in r.limitations:
        w(f"- {lim}")
    w("")

    w("## 8. Methodology\n")
    w(_methodology(r) + "\n")

    w("## Appendix A: Files Reviewed\n")
    w("\n".join(f"- `{f.path}` ({f.language}, {len(f.lines)} lines)" for f in r.files) + "\n")
    if r.dismissed_signals:
        w("## Appendix B: Static Leads Dismissed by AI (false-positive filtering)\n")
        sig = {s.id: s for s in r.signals}
        w("| Lead | Rule | Location | Reason dismissed |\n|---|---|---|---|")
        for d in r.dismissed_signals:
            s = sig.get(d.get("signal_id", ""))
            loc = f"`{s.file}:{s.line}`" if s else ""
            w(f"| {d.get('signal_id')} | {s.rule_id if s else ''} | {loc} | {d.get('reason', '').replace('|', '/')} |")
        w("")
    dropped = r.stats.get("findings_dropped_by_review") or []
    if dropped:
        w("## Appendix C: Draft Findings Rejected by the Review Pass\n")
        for d in dropped:
            w(f"- **{d['title']}** (`{d['file']}`): {d['reason']}")
        w("")
    w(f"\n---\n*Generated by {r.tool_name} v{r.tool_version}. This is an automated, AI-assisted "
      "source-code assessment, not a complete penetration test. Validate findings and re-test after "
      "remediation.*\n")
    return "\n".join(out)


def _methodology(r: ScanResult) -> str:
    st = r.stats
    if r.mode != "ai":
        return (f"The deterministic rule engine ran {st.get('signals', 0)} pattern matches over "
                f"{st.get('files_scanned', 0)} files. No AI verification was performed.")
    u = st.get("ai_usage", {})
    return (
        "1. **Ingestion**: supported source files were collected (dependencies, build output and lock "
        "files excluded) and treated strictly as untrusted data.\n"
        f"2. **Static rule engine**: {st.get('signals', 0)} heuristic leads were raised by language-aware "
        "rules (secrets, injection sinks, XSS sinks, auth checks, CORS, RLS policies, etc.).\n"
        f"3. **AI detection pass**: the full codebase (with line numbers) and the leads were analyzed by "
        f"{r.model} in {st.get('batches', 1)} context batch(es), reasoning across files about data flow, "
        "authentication and database policies. The model confirmed or dismissed each lead and looked for "
        "issues the rules cannot express.\n"
        "4. **Evidence grounding**: every finding's quoted code was matched against the real source to "
        f"correct line numbers; {len(st.get('findings_rejected_by_grounding', []))} unsupported finding(s) were discarded.\n"
        "5. **AI review pass**: an independent second pass re-checked each finding for false positives, "
        f"duplicates, severity and fix correctness ({len(st.get('findings_dropped_by_review', []))} dropped), "
        "and wrote the summary and overall assessment.\n"
        f"6. **Result**: {st.get('signals_confirmed', 0)} of {st.get('signals', 0)} leads were confirmed and "
        f"{st.get('signals_dismissed', 0)} dismissed as false positives. API usage: {u.get('requests', 0)} "
        f"requests, {u.get('input_tokens', 0) + u.get('cache_read_tokens', 0) + u.get('cache_write_tokens', 0):,} input tokens "
        f"({u.get('cache_read_tokens', 0):,} from prompt cache), {u.get('output_tokens', 0):,} output tokens."
    )


# ---------------------------------------------------------------- HTML
_CSS = """
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--muted:#5d6678;--line:#e2e5eb;--code:#f2f4f7;
--critical:#8b1a1a;--high:#c2410c;--medium:#b45309;--low:#2563eb;--info:#64748b;--ok:#15803d}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1218;--card:#171b23;--fg:#e6e8ec;
--muted:#9aa3b2;--line:#2a303c;--code:#11151c;--critical:#f87171;--high:#fb923c;--medium:#fbbf24;--low:#60a5fa;--info:#94a3b8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px;
padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:17px;margin:0}h4{font-size:14px;margin:18px 0 6px;text-transform:uppercase;
letter-spacing:.04em;color:var(--muted)}.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.kpi{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:12px 14px}.kpi b{display:block;font-size:26px}.kpi span{color:var(--muted);font-size:13px}
.sev{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;text-transform:uppercase;letter-spacing:.03em}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.tag{display:inline-block;padding:1px 8px;border:1px solid var(--line);border-radius:999px;font-size:12px;color:var(--muted);margin-right:4px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td:first-child a{white-space:nowrap}.tbl{overflow-x:auto}pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:13px;line-height:1.45}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}.bar{height:10px;border-radius:5px;background:var(--line);overflow:hidden;display:flex}
.bar i{display:block;height:100%}details.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:10px;margin:12px 0;padding:0}
details.finding[data-sev=critical]{border-left-color:var(--critical)}details.finding[data-sev=high]{border-left-color:var(--high)}
details.finding[data-sev=medium]{border-left-color:var(--medium)}details.finding[data-sev=low]{border-left-color:var(--low)}
details.finding>summary{cursor:pointer;padding:14px 16px;list-style:none;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.finding>summary::-webkit-details-marker{display:none}.fbody{padding:0 16px 16px}.meta td:first-child{width:160px;color:var(--muted)}
.filters button{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:999px;padding:4px 12px;margin:0 6px 6px 0;cursor:pointer}
.filters button.on{outline:2px solid var(--fg)}.risk{font-size:18px;font-weight:700;text-transform:uppercase}
.secure pre{border-color:var(--ok)}@media print{details.finding{break-inside:avoid}.filters{display:none}details.finding:not([open]) .fbody{display:block}}
"""

_JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
const s=b.dataset.sev;document.querySelectorAll('details.finding').forEach(d=>{d.style.display=(s==='all'||d.dataset.sev===s)?'':'none'})}));
document.getElementById('expand').addEventListener('click',()=>document.querySelectorAll('details.finding').forEach(d=>d.open=true));
window.addEventListener('beforeprint',()=>document.querySelectorAll('details.finding').forEach(d=>d.open=true));
"""


def _p(text: str) -> str:
    """Escape and render paragraphs plus minimal `code` spans."""
    esc = html.escape(text.strip())
    esc = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
    esc = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", esc)
    return "".join(f"<p>{para.replace(chr(10), '<br>')}</p>" for para in esc.split("\n\n") if para.strip())


def to_html(r: ScanResult) -> str:
    e = html.escape
    c = r.severity_counts()
    total = len(r.findings) or 1
    colors = {"critical": "var(--critical)", "high": "var(--high)", "medium": "var(--medium)", "low": "var(--low)", "info": "var(--info)"}
    bar = "".join(f'<i style="width:{c[s] * 100 / total:.1f}%;background:{colors[s]}" title="{s}: {c[s]}"></i>' for s in SEVERITIES)
    kpis = "".join(f'<div class="kpi"><b style="color:{colors[s]}">{c[s]}</b><span>{SEV_LABEL[s]}</span></div>' for s in SEVERITIES)
    rows = "".join(
        f'<tr><td><a href="#{e(f.id.lower())}">{e(f.id)}</a></td><td><span class="sev {f.severity}">{f.severity}</span></td>'
        f'<td>{e(f.title)}</td><td><code>{e(f.file)}:{f.start_line}</code></td><td>{e(STATUS_LABEL.get(f.status, f.status))}</td></tr>'
        for f in r.findings)
    cards = []
    for f in r.findings:
        rel = "".join(f"<li><code>{e(x.file)}:{x.line}</code> {e(x.note)}</li>" for x in f.related_locations)
        notes = " ".join(x for x in [f.assumptions.strip(), f.review_note.strip()] if x)
        cards.append(f"""
<details class="finding" data-sev="{f.severity}" id="{e(f.id.lower())}" open>
<summary><span class="sev {f.severity}">{f.severity}</span><h3>{e(f.id)}: {e(f.title)}</h3>
<span class="tag">{e(f.cwe)}</span><span class="tag">{e(STATUS_LABEL.get(f.status, f.status))}</span><span class="tag">confidence: {e(f.confidence)}</span></summary>
<div class="fbody">
<table class="meta"><tr><td>Category</td><td>{e(f.category)}{(' &middot; ' + e(f.owasp)) if f.owasp else ''}</td></tr>
<tr><td>Location</td><td><code>{e(f.file)}</code>, {e(_loc(f))}</td></tr>
<tr><td>Detected by</td><td>{e(SOURCE_LABEL.get(f.source, f.source))}</td></tr></table>
<h4>What is wrong</h4>{_p(f.description)}
<h4>Vulnerable code</h4><pre><code>{e(f.evidence)}</code></pre>
<h4>Why it matters</h4>{_p(f.impact)}
{('<h4>Example attack</h4>' + _p(f.exploit_scenario)) if f.exploit_scenario.strip() else ''}
<h4>How to fix</h4>{_p(f.remediation)}
{('<div class="secure"><h4>Secure code</h4><pre><code>' + e(f.secure_code.rstrip()) + '</code></pre></div>') if f.secure_code.strip() else ''}
{('<h4>Other affected locations</h4><ul>' + rel + '</ul>') if rel else ''}
{('<h4>Validation notes</h4>' + _p(notes)) if notes else ''}
</div></details>""")
    actions = "".join(f"<li>{e(a)}</li>" for a in r.prioritized_actions)
    positives = "".join(f"<li>{e(a)}</li>" for a in r.positive_observations)
    lims = "".join(f"<li>{e(a)}</li>" for a in r.limitations)
    files = "".join(f"<li><code>{e(f.path)}</code> <span class='muted'>({e(f.language)}, {len(f.lines)} lines)</span></li>" for f in r.files)
    sig = {s.id: s for s in r.signals}
    dismissed = "".join(
        f"<tr><td>{e(d.get('signal_id', ''))}</td><td>{e(sig[d['signal_id']].rule_id) if d.get('signal_id') in sig else ''}</td>"
        f"<td><code>{e(sig[d['signal_id']].file) + ':' + str(sig[d['signal_id']].line) if d.get('signal_id') in sig else ''}</code></td><td>{e(d.get('reason', ''))}</td></tr>"
        for d in r.dismissed_signals)
    dropped = "".join(f"<li><b>{e(d['title'])}</b> (<code>{e(d['file'])}</code>): {e(d['reason'])}</li>"
                      for d in r.stats.get("findings_dropped_by_review") or [])
    method = _p(_methodology(r).replace("\n", "\n\n"))
    filters = '<button class="on" data-sev="all">All</button>' + "".join(
        f'<button data-sev="{s}">{SEV_LABEL[s]} ({c[s]})</button>' for s in SEVERITIES if c[s])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report: {e(r.target_name)}</title><style>{_CSS}</style></head><body><div class="wrap">
<p class="muted">{e(r.tool_name)} v{e(r.tool_version)} &middot; {e(r.scanned_at)}</p>
<h1>Security Assessment Report: {e(r.target_name)}</h1>
<p class="muted">Source: <code>{e(r.target_source)}</code> &middot; {'AI-assisted static code review' if r.mode == 'ai' else 'Rule-based static review (no AI)'}{(' &middot; model ' + e(r.model)) if r.model else ''}
&middot; {r.stats.get('files_scanned', 0)} files, {r.stats.get('lines_scanned', 0)} lines</p>
<div class="card"><div class="muted">Overall risk rating</div><div class="risk" style="color:{colors.get(r.overall_risk, 'var(--fg)')}">{e(r.overall_risk)}</div></div>
<h2>Executive summary</h2><div class="card">{_p(r.executive_summary)}</div>
<h2>Findings summary</h2><div class="grid">{kpis}<div class="kpi"><b>{len(r.findings)}</b><span>Total</span></div></div>
<div class="card"><div class="bar">{bar}</div></div>
<div class="tbl"><table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Location</th><th>Status</th></tr>{rows}</table></div>
<h2>Detailed findings</h2><div class="filters">{filters}<button id="expand">Expand all</button></div>
{''.join(cards) or '<p>No findings.</p>'}
<h2>Overall assessment</h2><div class="card">{_p(r.overall_assessment)}</div>
{('<h3>Prioritized remediation plan</h3><ol>' + actions + '</ol>') if actions else ''}
{('<h3>Positive observations</h3><ul>' + positives + '</ul>') if positives else ''}
<h2>Scope and limitations</h2><ul>{lims}</ul>
<h2>Methodology</h2><div class="card">{method}</div>
<h2>Appendix A: files reviewed</h2><ul>{files}</ul>
{('<h2>Appendix B: static leads dismissed by AI</h2><table><tr><th>Lead</th><th>Rule</th><th>Location</th><th>Reason</th></tr>' + dismissed + '</table>') if dismissed else ''}
{('<h2>Appendix C: draft findings rejected in review</h2><ul>' + dropped + '</ul>') if dropped else ''}
<p class="muted" style="margin-top:40px">Automated AI-assisted source-code assessment; not a complete penetration test. Validate findings and re-test after remediation.</p>
</div><script>{_JS}</script></body></html>"""


# ---------------------------------------------------------------- SARIF
def to_sarif(r: ScanResult) -> dict:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    score = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
    rules, results, seen = [], [], set()
    for f in r.findings:
        rid = f.cwe or f.category
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "name": f.category, "shortDescription": {"text": f.category},
                          "properties": {"tags": ["security", f.cwe]}})
        results.append({
            "ruleId": rid, "level": level[f.severity],
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                "region": {"startLine": f.start_line, "endLine": f.end_line}}}],
            "fixes": [{"description": {"text": f.remediation}}] if f.remediation else [],
            "properties": {"id": f.id, "severity": f.severity, "security-severity": score[f.severity],
                           "confidence": f.confidence, "status": f.status, "secureCode": f.secure_code},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": r.tool_name, "version": r.tool_version, "rules": rules}},
                      "results": results}]}


def write_reports(r: ScanResult, out_dir: Path, formats: list[str], basename: str | None = None) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = basename or f"security-report-{_slug(r.target_name.split(' ')[0])}"
    written: dict[str, Path] = {}
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt in ("md", "markdown"):
            p = out_dir / f"{base}.md"; p.write_text(to_markdown(r), encoding="utf-8")
        elif fmt == "html":
            p = out_dir / f"{base}.html"; p.write_text(to_html(r), encoding="utf-8")
        elif fmt == "json":
            p = out_dir / f"{base}.json"; p.write_text(json.dumps(r.to_dict(), indent=2), encoding="utf-8")
        elif fmt == "sarif":
            p = out_dir / f"{base}.sarif"; p.write_text(json.dumps(to_sarif(r), indent=2), encoding="utf-8")
        else:
            raise ValueError(f"Unknown report format: {fmt}")
        written[fmt] = p
    return written
