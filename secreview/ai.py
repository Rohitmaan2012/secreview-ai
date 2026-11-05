"""Claude-powered analysis: a detection pass followed by an independent review pass."""

from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from .models import Finding, RelatedLocation, Signal, SourceFile
from .prompts import (ANALYSIS_INSTRUCTIONS, ANALYSIS_SCHEMA, REVIEW_INSTRUCTIONS, REVIEW_SCHEMA,
                      SYSTEM_PROMPT, UNACCOUNTED_INSTRUCTIONS)

log = logging.getLogger("secreview.ai")

DEFAULT_MODEL = "claude-opus-5-5"
# Characters of numbered source per request. Opus has a 1M-token context; we stay well below it
# so that output, thinking and the review pass have headroom.
DEFAULT_BATCH_CHARS = 450_000
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AIError(Exception):
    pass


@dataclass
class Usage:
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    models: set[str] = field(default_factory=set)

    def add(self, u: Any, model: str) -> None:
        self.requests += 1
        self.input_tokens += getattr(u, "input_tokens", 0) or 0
        self.output_tokens += getattr(u, "output_tokens", 0) or 0
        self.cache_read_tokens += getattr(u, "cache_read_input_tokens", 0) or 0
        self.cache_write_tokens += getattr(u, "cache_creation_input_tokens", 0) or 0
        if model:
            self.models.add(model)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests, "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens, "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens, "models_served": sorted(self.models),
        }


def render_codebase(files: list[SourceFile], all_paths: list[str]) -> str:
    tree = "\n".join(all_paths)
    parts = [f"<codebase>\n<file_tree>\n{tree}\n</file_tree>"]
    for f in files:
        parts.append(f'<file path="{f.path}" language="{f.language}">\n{f.numbered()}\n</file>')
    parts.append("</codebase>")
    return "\n".join(parts)


def render_signals(signals: list[Signal]) -> str:
    rows = [
        {"id": s.id, "rule": s.rule_id, "title": s.title, "cwe": s.cwe, "file": s.file,
         "line": s.line, "code": s.snippet, "hint": s.hint}
        for s in signals
    ]
    return "<static_signals>\n" + json.dumps(rows, indent=1) + "\n</static_signals>"


def make_batches(files: list[SourceFile], budget: int) -> list[list[SourceFile]]:
    """Group files into batches under ``budget`` characters, keeping directories together.

    Schema/policy files (SQL, ORM schemas) are added to every batch because access-control
    reasoning in application code depends on them.
    """
    shared = [f for f in files if f.language in {"sql", "prisma"}]
    shared_size = sum(len(f.numbered()) for f in shared)
    if shared_size > budget // 3:
        shared = []
        shared_size = 0
    rest = sorted((f for f in files if f not in shared), key=lambda f: f.path)
    total = sum(len(f.numbered()) for f in rest) + shared_size
    if total <= budget:
        return [shared + rest]
    batches: list[list[SourceFile]] = []
    current: list[SourceFile] = []
    size = shared_size
    for f in rest:
        n = len(f.numbered())
        if current and size + n > budget:
            batches.append(shared + current)
            current, size = [], shared_size
        current.append(f)
        size += n
    if current:
        batches.append(shared + current)
    return batches


def _finding_from_json(d: dict[str, Any], source: str = "ai") -> Finding:
    rel = [RelatedLocation(r.get("file", ""), int(r.get("line", 0) or 0), r.get("note", ""))
           for r in d.get("related_locations", []) or []]
    f = Finding(
        title=d.get("title", "").strip(), severity=d.get("severity", "medium"),
        category=d.get("category", ""), cwe=d.get("cwe", ""), file=d.get("file", ""),
        start_line=int(d.get("start_line", 0) or 0), end_line=int(d.get("end_line", 0) or 0),
        evidence=d.get("evidence", ""), description=d.get("description", ""),
        impact=d.get("impact", ""), remediation=d.get("remediation", ""),
        secure_code=d.get("secure_code", ""), secure_code_language=d.get("secure_code_language", ""),
        owasp=d.get("owasp", ""), exploit_scenario=d.get("exploit_scenario", ""),
        confidence=d.get("confidence", "medium"), status=d.get("status", "needs_validation"),
        assumptions=d.get("assumptions", ""), related_locations=rel,
        signal_ids=list(d.get("signal_ids", []) or []), source=source,
    )
    if f.signal_ids:
        f.source = "ai+rules"
    return f


class ClaudeAnalyzer:
    def __init__(self, model: str = DEFAULT_MODEL, effort: str = "high",
                 batch_chars: int = DEFAULT_BATCH_CHARS, use_fallbacks: bool = True,
                 progress: Callable[[str], None] | None = None, client: Any = None):
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover
                raise AIError("The 'anthropic' package is not installed (pip install anthropic)") from exc
            if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
                raise AIError(
                    "No Anthropic credentials found. Set ANTHROPIC_API_KEY (see README), "
                    "or run with --no-ai for the rules-only mode."
                )
            client = anthropic.Anthropic(max_retries=4)
        self.client = client
        self.model = model
        self.effort = effort
        self.batch_chars = batch_chars
        self.use_fallbacks = use_fallbacks
        self.progress = progress or (lambda msg: None)
        self.usage = Usage()

    # -- low-level call ----------------------------------------------------
    def _call(self, content: list[dict[str, Any]], schema: dict[str, Any], max_tokens: int = 64000) -> dict[str, Any]:
        params: dict[str, Any] = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": content}],
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        if self.use_fallbacks:
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        try:
            msg = self._stream(params)
        except Exception as exc:  # retry once without the fallback beta if the endpoint rejects it
            if self.use_fallbacks and getattr(exc, "status_code", None) == 400 and "fallback" in str(exc).lower():
                log.warning("Server-side fallback not accepted by this endpoint; retrying without it")
                self.use_fallbacks = False
                params.pop("betas", None)
                params.pop("fallbacks", None)
                msg = self._stream(params)
            elif getattr(exc, "status_code", None) == 400 and re.search(r"schema|output_config|format", str(exc), re.I):
                # Structured-output schema not accepted by this endpoint/model: fall back to
                # instructing the model to emit raw JSON and parse it ourselves.
                log.warning("Structured output not accepted (%s); falling back to prompted JSON", exc)
                params["output_config"] = {"effort": self.effort}
                params["messages"][0]["content"] = content + [{"type": "text", "text":
                    "Respond with ONLY a JSON object (no prose, no code fences) matching this JSON schema:\n"
                    + json.dumps(schema)}]
                msg = self._stream(params)
            else:
                raise
        self.usage.add(msg.usage, getattr(msg, "model", self.model))
        if msg.stop_reason == "refusal":
            details = getattr(msg, "stop_details", None)
            raise AIError(f"The model declined the request ({getattr(details, 'category', 'unknown')}).")
        if msg.stop_reason == "max_tokens":
            raise AIError("Model output hit max_tokens; try a smaller --batch-chars value.")
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    pass
            raise AIError("Model returned invalid JSON")

    def _stream(self, params: dict[str, Any]):
        with self.client.beta.messages.stream(**params) as stream:
            return stream.get_final_message()

    # -- passes --------------------------------------------------------------
    def analyze(self, name: str, files: list[SourceFile], signals: list[Signal]) -> tuple[list[Finding], list[dict[str, str]], dict[str, Any]]:
        all_paths = [f.path for f in files]
        batches = make_batches(files, self.batch_chars)
        self.progress(f"AI detection pass: {len(batches)} batch(es) to {self.model}")

        def run_batch(i_batch: tuple[int, list[SourceFile]]):
            i, batch = i_batch
            paths = {f.path for f in batch}
            sigs = [s for s in signals if s.file in paths]
            note = "" if len(batches) == 1 else (
                f" (batch {i + 1} of {len(batches)}; other files exist and are listed in the file "
                "tree, but only report issues you can evidence in the files shown)")
            content = [
                {"type": "text", "text": render_codebase(batch, all_paths), "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": render_signals(sigs)},
                {"type": "text", "text": ANALYSIS_INSTRUCTIONS.format(name=name, file_count=len(batch), batch_note=note)},
            ]
            data = self._call(content, ANALYSIS_SCHEMA)
            self.progress(f"  batch {i + 1}/{len(batches)}: {len(data.get('findings', []))} draft finding(s)")
            return data

        with ThreadPoolExecutor(max_workers=min(4, len(batches))) as pool:
            results = list(pool.map(run_batch, enumerate(batches)))

        findings: list[Finding] = []
        dismissed: list[dict[str, str]] = []
        for data in results:
            findings.extend(_finding_from_json(d) for d in data.get("findings", []))
            dismissed.extend(data.get("dismissed_signals", []))
        return findings, dismissed, {"batches": len(batches), "single_context": len(batches) == 1, "batch_files": batches}

    def review(self, name: str, files: list[SourceFile], signals: list[Signal], drafts: list[Finding],
               batches: list[list[SourceFile]], unaccounted: list[Signal] | None = None) -> dict[str, Any]:
        self.progress(f"AI review pass: validating {len(drafts)} draft finding(s)")
        if len(batches) == 1:
            ctx_files = batches[0]  # identical prefix -> prompt-cache hit
        else:
            wanted = {d.file for d in drafts} | {r.file for d in drafts for r in d.related_locations}
            ctx_files = [f for f in files if f.path in wanted or f.language == "sql"]
            ctx_files = make_batches(ctx_files, self.batch_chars)[0]
        draft_json = json.dumps(
            [dict(index=i, **{k: v for k, v in d.to_dict().items()
                              if k not in {"id", "grounded", "review_note", "source"}})
             for i, d in enumerate(drafts)], indent=1)
        sigs = [s for s in signals if s.file in {f.path for f in ctx_files}]
        content = [
            {"type": "text", "text": render_codebase(ctx_files, [f.path for f in files]), "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": render_signals(sigs)},
            {"type": "text", "text": REVIEW_INSTRUCTIONS.format(draft=draft_json, unaccounted=(
                UNACCOUNTED_INSTRUCTIONS.format(signals=json.dumps(
                    [{"id": x.id, "rule": x.rule_id, "title": x.title, "file": x.file, "line": x.line,
                      "code": x.snippet, "hint": x.hint} for x in unaccounted], indent=1))
                if unaccounted else ""))},
        ]
        return self._call(content, REVIEW_SCHEMA)


def apply_review(drafts: list[Finding], review: dict[str, Any]) -> tuple[list[Finding], list[dict[str, str]]]:
    """Apply keep/drop/merge decisions. Returns (findings, dropped_log)."""
    decisions = {d["index"]: d for d in review.get("decisions", []) if isinstance(d.get("index"), int)}
    kept: dict[int, Finding] = {}
    merges: list[tuple[int, int]] = []
    dropped: list[dict[str, str]] = []
    for i, f in enumerate(drafts):
        d = decisions.get(i)
        if d is None:
            kept[i] = f  # reviewer silent -> keep, but flag
            f.review_note = "Not explicitly reviewed in second pass."
            continue
        if d["action"] == "drop":
            dropped.append({"title": f.title, "file": f.file, "reason": d.get("reason", "")})
            continue
        f.severity = d.get("severity", f.severity)
        f.confidence = d.get("confidence", f.confidence)
        f.status = d.get("status", f.status)
        if d.get("corrected_secure_code", "").strip():
            f.secure_code = d["corrected_secure_code"]
        f.review_note = d.get("reason", "")
        if d["action"] == "merge" and d.get("merge_into", -1) not in (-1, i):
            merges.append((i, d["merge_into"]))
        kept[i] = f
    for src, dst in merges:
        if src in kept and dst in kept:
            s, t = kept.pop(src), kept[dst]
            t.related_locations.append(RelatedLocation(s.file, s.start_line, f"Same root cause: {s.title}"))
            t.signal_ids = sorted(set(t.signal_ids) | set(s.signal_ids))
    result = list(kept.values())
    result.extend(_finding_from_json(d) for d in review.get("additional_findings", []))
    return result, dropped


# ---------------------------------------------------------------------------
# Free / alternative providers via the OpenAI-compatible Chat Completions API
# (Google Gemini free tier, local Ollama, or any compatible server).
# ---------------------------------------------------------------------------

PROVIDERS = {
    "gemini": {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
               "model": "gemini-3.8-flash", "key_env": "GEMINI_API_KEY",
               "fallback_models": ["gemini-flash-latest", "gemini-3.8-flash-lite", "gemini-flash-lite-latest"]},
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "qwen2.5-coder:14b", "key_env": ""},
    "openai-compatible": {"base_url": "", "model": "", "key_env": "OPENAI_API_KEY"},
}


class OpenAICompatAnalyzer(ClaudeAnalyzer):
    """Same two-pass pipeline and prompts as the Claude analyzer, different transport."""

    def __init__(self, provider: str, model: str | None = None, base_url: str | None = None,
                 batch_chars: int = DEFAULT_BATCH_CHARS, progress: Callable[[str], None] | None = None,
                 timeout: int = 900, http_post: Callable[..., dict] | None = None):
        cfg = PROVIDERS.get(provider, PROVIDERS["openai-compatible"])
        self.provider = provider
        self.base_url = (base_url or os.environ.get("SECREVIEW_BASE_URL") or cfg["base_url"]).rstrip("/")
        if not self.base_url:
            raise AIError("--base-url is required for the openai-compatible provider")
        self.api_key = os.environ.get(cfg["key_env"], "") if cfg["key_env"] else ""
        if provider == "gemini" and not self.api_key:
            raise AIError("GEMINI_API_KEY is not set. Get a free key at https://aistudio.google.com/apikey")
        self.model = model or cfg["model"]
        if not self.model:
            raise AIError("--model is required for the openai-compatible provider")
        self.effort = "n/a"
        self.batch_chars = batch_chars
        self.use_fallbacks = False
        self.progress = progress or (lambda msg: None)
        self.usage = Usage()
        self.timeout = timeout
        self._post = http_post or self._http_post
        self._format_mode = "json_schema"  # degrades to json_object, then prompt-only
        # If the chosen model is overloaded, try these (free-tier) models in order.
        self._fallback_models = [m for m in cfg.get("fallback_models", []) if m != self.model]
        self._discovered = http_post is not None  # skip live discovery in tests

    def _discover_models(self) -> list[str]:
        """List text models this key can use (newest flash/pro first)."""
        import urllib.request

        try:
            req = urllib.request.Request(f"{self.base_url}/models",
                                         headers={"Authorization": f"Bearer {self.api_key}"})
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                ids = [m.get("id", "").split("/")[-1] for m in json.loads(resp.read().decode()).get("data", [])]
        except Exception:  # discovery is best effort
            return []
        bad = ("image", "tts", "embedding", "live", "audio", "vision", "aqa", "learnlm", "gemma", "veo", "imagen")
        ids = [i for i in ids if i.startswith("gemini") and not any(b in i for b in bad)]

        def key(i: str):
            ver = re.findall(r"\d+(?:\.\d+)?", i)
            # free-tier friendly order: flash, then flash-lite, then anything else; newest first
            tier = 0 if "flash" in i and "lite" not in i else 1 if "lite" in i else 2
            return (tier, "preview" in i or "exp" in i, -(float(ver[0]) if ver else 0))
        found = sorted(set(ids), key=key)
        if found:
            self.progress(f"  models available to this key: {', '.join(found[:6])}")
        return found

    def _http_post(self, url: str, body: dict) -> dict:
        import time
        import urllib.error
        import urllib.request

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = json.dumps(body).encode()
        delay = 5
        for attempt in range(4):
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                text = exc.read().decode(errors="replace")[:500]
                if exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                    self.progress(f"  provider returned {exc.code}; retrying in {delay}s")
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
                    continue
                err = AIError(f"{self.provider} API error {exc.code}: {text}")
                err.status_code = exc.code  # type: ignore[attr-defined]
                raise err from exc
            except urllib.error.URLError as exc:
                hint = " Is Ollama running (ollama serve)?" if self.provider == "ollama" else ""
                raise AIError(f"Could not reach {url}: {exc.reason}.{hint}") from exc
        raise AIError("Provider kept failing after retries")

    def _call(self, content: list[dict[str, Any]], schema: dict[str, Any], max_tokens: int = 64000) -> dict[str, Any]:
        user_text = "\n\n".join(c["text"] for c in content)
        schema_hint = ("\n\nRespond with ONLY a JSON object (no prose, no code fences) matching this JSON schema:\n"
                       + json.dumps(schema))
        while True:
            body: dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": user_text + ("" if self._format_mode == "json_schema" else schema_hint)}],
            }
            if self._format_mode == "json_schema":
                body["response_format"] = {"type": "json_schema",
                                           "json_schema": {"name": "result", "schema": schema}}
            elif self._format_mode == "json_object":
                body["response_format"] = {"type": "json_object"}
            try:
                resp = self._post(f"{self.base_url}/chat/completions", body)
                break
            except AIError as exc:
                code = getattr(exc, "status_code", None)
                if code in (404, 429, 500, 503) and self.provider == "gemini" and not self._discovered:
                    self._discovered = True
                    self._fallback_models = self._discover_models() + self._fallback_models
                    self._fallback_models = [m for i, m in enumerate(self._fallback_models)
                                             if m != self.model and m not in self._fallback_models[:i]]
                if code in (404, 429, 500, 503) and self._fallback_models:
                    nxt = self._fallback_models.pop(0)
                    self.progress(f"  {self.model} unavailable ({code}); switching to {nxt}")
                    self.model = nxt
                    continue
                if code == 400 and self._format_mode != "prompt":
                    self._format_mode = {"json_schema": "json_object", "json_object": "prompt"}[self._format_mode]
                    log.warning("Provider rejected response_format; retrying with %s", self._format_mode)
                    continue
                raise
        u = resp.get("usage") or {}
        self.usage.requests += 1
        self.usage.input_tokens += u.get("prompt_tokens", 0) or 0
        self.usage.output_tokens += u.get("completion_tokens", 0) or 0
        self.usage.models.add(resp.get("model") or self.model)
        choice = (resp.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content") or "").strip()
        if choice.get("finish_reason") == "length":
            raise AIError("Model output was truncated; try a smaller --batch-chars value.")
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            try:
                data = json.loads(text[start:end + 1]) if start != -1 else None
            except json.JSONDecodeError:
                data = None
            if data is None:
                raise AIError("Model returned invalid JSON")
        # Smaller models sometimes omit keys; fill defaults so the pipeline keeps going.
        for key, spec in schema.get("properties", {}).items():
            if key not in data:
                data[key] = [] if spec.get("type") == "array" else ("" if spec.get("type") == "string" else data.get(key))
        return data


def make_analyzer(provider: str | None, model: str | None = None, effort: str = "high",
                  batch_chars: int | None = None, use_fallbacks: bool = True, base_url: str | None = None,
                  progress: Callable[[str], None] | None = None):
    """Pick a provider: explicit choice, else whichever API key is configured."""
    if not provider or provider == "auto":
        if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            provider = "anthropic"
        elif os.environ.get("GEMINI_API_KEY"):
            provider = "gemini"
        else:
            raise AIError(
                "No AI provider configured. Set ANTHROPIC_API_KEY (Claude), or GEMINI_API_KEY for the free "
                "Gemini tier (https://aistudio.google.com/apikey), or use --provider ollama for a local model, "
                "or --no-ai for rules only.")
    if provider == "anthropic":
        return ClaudeAnalyzer(model=model or DEFAULT_MODEL, effort=effort,
                              batch_chars=batch_chars or DEFAULT_BATCH_CHARS,
                              use_fallbacks=use_fallbacks, progress=progress)
    if provider == "ollama" and not batch_chars:
        batch_chars = 60_000  # local models have much smaller context windows
    return OpenAICompatAnalyzer(provider, model=model, base_url=base_url,
                                batch_chars=batch_chars or DEFAULT_BATCH_CHARS, progress=progress)
