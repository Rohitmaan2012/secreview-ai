"""Command-line interface: ``secreview scan <target>`` and ``secreview web``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .models import SEVERITIES, SEVERITY_RANK

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
          "low": "\033[1;34m", "info": "\033[2m"}
RESET = "\033[0m"


def _c(text: str, sev: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{COLORS.get(sev, '')}{text}{RESET}"


def _print_result(result, written) -> None:
    counts = result.severity_counts()
    print()
    print(f"  {result.tool_name} | {result.target_name} | mode: {result.mode}"
          + (f" | model: {result.model}" if result.model else ""))
    print(f"  Overall risk: {_c(result.overall_risk.upper(), result.overall_risk)}")
    print("  " + "  ".join(_c(f"{s.upper()}: {counts[s]}", s) for s in SEVERITIES))
    print()
    for f in result.findings:
        sev = _c(f"{f.severity.upper():<8}", f.severity)
        print(f"  {f.id}  {sev}  {f.title}")
        print(f"          {f.file}:{f.start_line}  [{f.cwe}, {f.status.replace('_', ' ')}, confidence {f.confidence}]")
    print()
    for fmt, path in written.items():
        print(f"  {fmt.upper():<6} report: {path}")
    print()


def cmd_scan(args) -> int:
    from .ingest import IngestError
    from .report import write_reports
    from .scanner import scan

    def progress(msg: str) -> None:
        if not args.quiet:
            print(f"[secreview] {msg}", file=sys.stderr, flush=True)

    try:
        result = scan(args.target, use_ai=not args.no_ai, model=args.model, effort=args.effort,
                      batch_chars=args.batch_chars, include_docs=args.include_docs,
                      min_severity=args.min_severity, use_fallbacks=not args.no_fallback,
                      provider=args.provider, base_url=args.base_url,
                      progress=progress)
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # surface AI/config errors cleanly
        from .ai import AIError
        if isinstance(exc, AIError):
            print(f"error: {exc}", file=sys.stderr)
            return 3
        raise
    written = write_reports(result, Path(args.output), args.format.split(","), args.name)
    _print_result(result, written)
    if args.fail_on:
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] <= limit for f in result.findings):
            return 1
    return 0


def cmd_web(args) -> int:
    from .web import create_app

    app = create_app(output_dir=Path(args.output), allow_local_paths=not args.no_local_paths)
    print(f"SecReview AI web UI on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secreview", description="AI-powered security code review (Find. Fix. Fortify.)")
    p.add_argument("--version", action="version", version=f"secreview {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a folder, .zip file or GitHub URL")
    s.add_argument("target", help="Local folder, path to a .zip, or https://github.com/owner/repo[/tree/ref/subdir]")
    s.add_argument("-o", "--output", default="reports", help="Output directory (default: reports)")
    s.add_argument("-f", "--format", default="md,html,json", help="Comma list of md,html,json,sarif (default: md,html,json)")
    s.add_argument("-n", "--name", help="Base filename for the reports")
    s.add_argument("--no-ai", action="store_true", help="Rules-only mode (no API key needed; unverified leads)")
    s.add_argument("--provider", default="auto", choices=["auto", "anthropic", "gemini", "ollama", "openai-compatible"],
                   help="AI provider (default: auto = Claude if ANTHROPIC_API_KEY is set, else Gemini if GEMINI_API_KEY is set)")
    s.add_argument("--model", default=None, help="Model id (defaults: claude-opus-5-5 / gemini-3.8-flash / qwen2.5-coder:14b)")
    s.add_argument("--base-url", default=None, help="Base URL for ollama / openai-compatible providers")
    s.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"], help="Reasoning effort (default: high)")
    s.add_argument("--batch-chars", type=int, default=None, help="Max characters of code per AI request")
    s.add_argument("--min-severity", default="info", choices=SEVERITIES, help="Hide findings below this severity")
    s.add_argument("--fail-on", choices=SEVERITIES, help="Exit with code 1 if any finding at/above this severity (CI use)")
    s.add_argument("--include-docs", action="store_true", help="Also send .md/.txt files to the model")
    s.add_argument("--no-fallback", action="store_true", help="Disable server-side model fallback on refusals")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("web", help="Start the local web interface")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("-o", "--output", default="reports")
    w.add_argument("--no-local-paths", action="store_true", help="Disallow scanning server-side folder paths")
    w.set_defaults(func=cmd_web)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
