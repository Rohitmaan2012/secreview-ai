"""End-to-end orchestration: ingest -> rules -> AI detect -> AI review -> ground -> report."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

from . import __version__
from .ingest import Workspace, collect_files, project_name
from .models import SEVERITY_RANK, ScanResult
from .offline import signals_to_findings
from .rules import run_rules
from .verify import dedupe, finalize, ground_findings

TOOL_NAME = "SecReview AI"

LIMITATIONS = [
    "Static source-code review only: no code was executed, and no runtime or penetration testing was performed.",
    "Deployment configuration, infrastructure, and third-party services outside the scanned files were not assessed.",
    "Dependency versions were not checked against vulnerability databases (use npm audit / pip-audit alongside this tool).",
    "Findings marked 'needs validation' depend on runtime context and should be confirmed by a developer.",
    "No automated tool finds every vulnerability; absence of a finding is not proof of security.",
]


def scan(target: str, *, use_ai: bool = True, model: str | None = None, effort: str = "high",
         batch_chars: int | None = None, include_docs: bool = False, min_severity: str = "info",
         use_fallbacks: bool = True, provider: str | None = None,
         base_url: str | None = None, progress: Callable[[str], None] | None = None,
         analyzer=None) -> ScanResult:
    say = progress or (lambda m: None)
    t0 = time.time()
    with Workspace(target) as ws:
        assert ws.root is not None
        files = collect_files(ws.root, include_docs=include_docs)
        name = project_name(ws.root, ws.name)
        if ws.name and ws.name != name and "/" in ws.name:
            name = f"{name} ({ws.name})"
    if not files:
        raise ValueError("No supported source files found in target")
    say(f"Loaded {len(files)} source file(s) from {target}")

    signals = run_rules(files)
    say(f"Static rule engine raised {len(signals)} lead(s)")

    result = ScanResult(
        target_name=name, target_source=target,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tool_name=TOOL_NAME, tool_version=__version__,
        mode="ai" if use_ai else "rules-only", model="", files=files, signals=signals, findings=[],
        limitations=list(LIMITATIONS),
    )

    rejected: list[dict[str, str]] = []
    dropped: list[dict[str, str]] = []
    if use_ai:
        from .ai import apply_review, make_analyzer

        ai = analyzer or make_analyzer(provider, model=model, effort=effort, batch_chars=batch_chars,
                                       use_fallbacks=use_fallbacks, base_url=base_url, progress=say)
        result.model = ai.model
        drafts, dismissed, meta = ai.analyze(name, files, signals)
        drafts, rejected = ground_findings(drafts, files)
        drafts = dedupe(drafts)
        say(f"{len(drafts)} grounded draft finding(s); {len(rejected)} rejected by evidence check")
        used_ids = {sid for d in drafts for sid in d.signal_ids}
        dismissed_ids = {d.get("signal_id") for d in dismissed}
        unaccounted = [s for s in signals if s.id not in used_ids and s.id not in dismissed_ids
                       and SEVERITY_RANK[s.severity] <= SEVERITY_RANK["medium"]]
        if unaccounted:
            say(f"{len(unaccounted)} static lead(s) not addressed by the first pass; sending to review")
        review = ai.review(name, files, signals, drafts, meta["batch_files"], unaccounted)
        dismissed = dismissed + list(review.get("dismissed_signals", []) or [])
        findings, dropped = apply_review(drafts, review)
        findings, rejected2 = ground_findings(findings, files)
        rejected += rejected2
        findings = dedupe(findings)
        result.dismissed_signals = dismissed
        result.executive_summary = review.get("executive_summary", "")
        result.overall_risk = review.get("overall_risk", "")
        result.overall_assessment = review.get("overall_assessment", "")
        result.positive_observations = review.get("positive_observations", [])
        result.prioritized_actions = review.get("prioritized_actions", [])
        result.stats["ai_usage"] = ai.usage.to_dict()
        result.stats["batches"] = meta["batches"]
        if ai.usage.models:
            result.model = ", ".join(sorted(ai.usage.models))
    else:
        findings = dedupe(signals_to_findings(signals, files))
        result.limitations.insert(0, "Rules-only mode: findings are unverified heuristic matches. "
                                     "Run with AI enabled for verified findings and code-specific fixes.")
        result.executive_summary = _rules_summary(name, findings, len(files))
        result.overall_risk = _risk_from(findings)
        result.overall_assessment = ("This report was produced by the deterministic rule engine only. "
                                     "Each item is a pattern that commonly indicates a vulnerability and "
                                     "must be reviewed by a developer to confirm exploitability.")

    threshold = SEVERITY_RANK.get(min_severity, 4)
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= threshold]
    result.findings = finalize(findings)
    used = {sid for f in result.findings for sid in f.signal_ids}
    dismissed_ids = {d.get("signal_id") for d in result.dismissed_signals}
    result.stats.update({
        "files_scanned": len(files),
        "lines_scanned": sum(len(f.lines) for f in files),
        "signals": len(signals),
        "signals_confirmed": len(used),
        "signals_dismissed": len(dismissed_ids),
        "findings_rejected_by_grounding": rejected,
        "findings_dropped_by_review": dropped,
        "duration_seconds": round(time.time() - t0, 1),
    })
    if not result.overall_risk:
        result.overall_risk = _risk_from(result.findings)
    say(f"Done: {len(result.findings)} finding(s) in {result.stats['duration_seconds']}s")
    return result


def _risk_from(findings) -> str:
    if not findings:
        return "low"
    top = min(SEVERITY_RANK[f.severity] for f in findings)
    return ["critical", "high", "medium", "low", "low"][top]


def _rules_summary(name: str, findings, nfiles: int) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: SEVERITY_RANK[kv[0]]))
    return (f"{nfiles} source files of {name} were scanned with the rule engine, which flagged "
            f"{len(findings)} potential issue(s) ({parts or 'none'}). These are unverified leads.")
