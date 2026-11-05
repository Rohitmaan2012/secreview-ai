import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from secreview.ai import AIError, OpenAICompatAnalyzer, make_analyzer
from secreview.scanner import scan

FIX = Path(__file__).parent / "fixtures" / "unseen-app"

ANALYSIS = {"findings": [{
    "title": "Command injection in /ping", "severity": "critical", "category": "Command Injection", "cwe": "CWE-78",
    "owasp": "A03:2021 Injection", "file": "server/app.js", "start_line": 16, "end_line": 16,
    "evidence": "exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));", "description": "d", "impact": "i",
    "exploit_scenario": "", "remediation": "Use execFile.", "secure_code": "execFile('ping', ['-c', '1', host]);",
    "secure_code_language": "javascript", "confidence": "high", "status": "confirmed", "assumptions": "",
    "related_locations": [], "signal_ids": []}], "dismissed_signals": []}
REVIEW = {"decisions": [], "additional_findings": [], "executive_summary": "S", "overall_risk": "critical",
          "overall_assessment": "A", "positive_observations": [], "prioritized_actions": []}


def test_openai_compat_degrades_response_format(monkeypatch):
    calls = []
    payloads = [ANALYSIS, REVIEW]

    def post(url, body):
        calls.append(body)
        if body.get("response_format", {}).get("type") == "json_schema":
            err = AIError("400 schema unsupported"); err.status_code = 400
            raise err
        return {"model": "m", "usage": {"prompt_tokens": 5, "completion_tokens": 3},
                "choices": [{"finish_reason": "stop", "message": {"content": "```json\n" + json.dumps(payloads.pop(0)) + "\n```"}}]}

    ai = OpenAICompatAnalyzer("ollama", http_post=post)
    result = scan(str(FIX), analyzer=ai)
    assert calls[0]["response_format"]["type"] == "json_schema"
    assert calls[1]["response_format"]["type"] == "json_object"
    assert calls[0]["messages"][0]["role"] == "system"
    assert result.findings[0].cwe == "CWE-78" and result.findings[0].start_line == 16


def test_openai_compat_real_http_roundtrip():
    payloads = [ANALYSIS, REVIEW]
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["auth"] = self.headers.get("Authorization")
            seen["path"] = self.path
            out = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payloads.pop(0))}}],
                              "usage": {}, "model": body["model"]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ai = OpenAICompatAnalyzer("ollama", base_url=f"http://127.0.0.1:{srv.server_port}/v1")
        result = scan(str(FIX), analyzer=ai)
    finally:
        srv.shutdown()
    assert seen["path"] == "/v1/chat/completions" and seen["auth"] is None
    assert result.findings and result.model == "qwen2.5-coder:14b"


def test_auto_provider_selection(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(AIError, match="GEMINI_API_KEY"):
        make_analyzer("auto")
    monkeypatch.setenv("GEMINI_API_KEY", "test")
    ai = make_analyzer("auto")
    assert isinstance(ai, OpenAICompatAnalyzer) and ai.provider == "gemini"
    assert ai.base_url.startswith("https://generativelanguage.googleapis.com")


def test_gemini_switches_model_when_overloaded(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    models = []
    payloads = [ANALYSIS, REVIEW]

    def post(url, body):
        models.append(body["model"])
        if body["model"] == "gemini-3.8-flash":
            err = AIError("503 overloaded"); err.status_code = 503
            raise err
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payloads.pop(0))}}], "usage": {}}

    result = scan(str(FIX), analyzer=OpenAICompatAnalyzer("gemini", http_post=post))
    assert models[:2] == ["gemini-3.8-flash", "gemini-flash-latest"] and result.findings
