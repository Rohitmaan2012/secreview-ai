"""Deterministic post-processing of AI findings.

The model is good at reasoning but can mis-number lines or paraphrase code. This module grounds
every finding against the real source: it resolves the file, locates the quoted evidence, corrects
line numbers, drops findings whose file does not exist, flags findings whose evidence cannot be
found, and removes duplicates.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from .models import SEVERITY_RANK, Finding, RelatedLocation, SourceFile

_LINE_PREFIX = re.compile(r"^\s*\d+\s*\|\s?")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _resolve_file(path: str, by_path: dict[str, SourceFile]) -> SourceFile | None:
    p = path.strip().lstrip("./").replace("\\", "/")
    if p in by_path:
        return by_path[p]
    candidates = [f for k, f in by_path.items() if k.endswith("/" + p) or p.endswith("/" + k)]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _locate(evidence: str, f: SourceFile, hint_line: int) -> tuple[int, int] | None:
    ev_lines = [_LINE_PREFIX.sub("", l) for l in evidence.splitlines()]
    ev_lines = [l for l in ev_lines if _norm(l) and _norm(l) not in {"...", "…"}]
    if not ev_lines:
        return None
    src = [_norm(l) for l in f.lines]
    first = _norm(ev_lines[0])
    last = _norm(ev_lines[-1])

    def matches(target: str, line: str) -> bool:
        if not target:
            return False
        if target == line or (len(target) >= 6 and target in line) or (len(line) >= 6 and line in target):
            return True
        return len(target) > 10 and SequenceMatcher(None, target, line).ratio() > 0.85

    starts = [i for i, l in enumerate(src) if matches(first, l)]
    if not starts:
        # try any evidence line
        for ev in ev_lines[1:]:
            starts = [i for i, l in enumerate(src) if matches(_norm(ev), l)]
            if starts:
                break
        if not starts:
            return None
    start = min(starts, key=lambda i: abs((i + 1) - (hint_line or i + 1)))
    end = start
    span = len(ev_lines)
    for j in range(start, min(len(src), start + span + 5)):
        if matches(last, src[j]):
            end = j
            break
    else:
        end = min(len(src) - 1, start + span - 1)
    return start + 1, max(start, end) + 1


def ground_findings(findings: list[Finding], files: list[SourceFile]) -> tuple[list[Finding], list[dict[str, str]]]:
    by_path = {f.path: f for f in files}
    out: list[Finding] = []
    rejected: list[dict[str, str]] = []
    for fd in findings:
        sf = _resolve_file(fd.file, by_path)
        if sf is None:
            rejected.append({"title": fd.title, "file": fd.file, "reason": "Referenced file does not exist in the scanned code"})
            continue
        fd.file = sf.path
        loc = _locate(fd.evidence, sf, fd.start_line)
        n = len(sf.lines)
        if loc:
            fd.start_line, fd.end_line = loc
            fd.grounded = True
            # Replace evidence with the exact source lines so the report quotes real code.
            fd.evidence = "\n".join(sf.lines[fd.start_line - 1: fd.end_line])
        elif 1 <= fd.start_line <= n:
            fd.end_line = min(max(fd.end_line, fd.start_line), n)
            fd.grounded = False
            fd.evidence = "\n".join(sf.lines[fd.start_line - 1: fd.end_line])
            fd.confidence = "low"
            fd.status = "needs_validation"
            fd.review_note = (fd.review_note + " " if fd.review_note else "") + \
                "Quoted evidence could not be matched exactly; location taken from the model."
        else:
            rejected.append({"title": fd.title, "file": fd.file, "reason": "Evidence not found and line numbers out of range"})
            continue
        # Clamp related locations.
        rel = []
        for r in fd.related_locations:
            rf = _resolve_file(r.file, by_path)
            if rf and 1 <= r.line <= len(rf.lines):
                rel.append(RelatedLocation(rf.path, r.line, r.note))
        fd.related_locations = rel
        if fd.severity not in SEVERITY_RANK:
            fd.severity = "medium"
        out.append(fd)
    return out, rejected


def _overlap(a: Finding, b: Finding, slack: int = 2) -> bool:
    return a.file == b.file and a.start_line <= b.end_line + slack and b.start_line <= a.end_line + slack


def _similar_title(a: str, b: str) -> bool:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio() > 0.8


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings that describe the same weakness at the same place."""
    result: list[Finding] = []
    for f in sorted(findings, key=lambda x: (SEVERITY_RANK[x.severity], x.file, x.start_line)):
        dup = next((r for r in result if _overlap(r, f) and (r.cwe == f.cwe or _similar_title(r.title, f.title))), None)
        if dup is None:
            result.append(f)
            continue
        dup.signal_ids = sorted(set(dup.signal_ids) | set(f.signal_ids))
        known = {(x.file, x.line) for x in dup.related_locations}
        for r in f.related_locations:
            if (r.file, r.line) not in known:
                dup.related_locations.append(r)
    return result


def finalize(findings: list[Finding], prefix: str = "SR") -> list[Finding]:
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (SEVERITY_RANK[x.severity], conf_rank.get(x.confidence, 3), x.file, x.start_line))
    for i, f in enumerate(findings, 1):
        f.id = f"{prefix}-{i:03d}"
    return findings
