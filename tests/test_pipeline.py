import json
from pathlib import Path

from secreview.ai import ClaudeAnalyzer
from secreview.report import to_html, to_markdown, to_sarif, write_reports
from secreview.scanner import scan

FIX = Path(__file__).parent / "fixtures" / "unseen-app"


def finding(**kw):
    base = dict(title="SQL injection in /users", severity="critical", category="SQL Injection", cwe="CWE-89",
                owasp="A03:2021 Injection", file="server/app.js", start_line=99, end_line=99,
                evidence='  const rows = await db.query("SELECT * FROM users WHERE name = \'" + req.query.name + "\'");',
                description="d", impact="i", exploit_scenario="e", remediation="Use parameters.",
                secure_code='await db.query("SELECT * FROM users WHERE name = $1", [req.query.name]);',
                secure_code_language="javascript", confidence="high", status="confirmed", assumptions="",
                related_locations=[], signal_ids=[])
    base.update(kw)
    return base


def test_full_ai_pipeline_with_fake_client(fake_client_factory, tmp_path):
    analysis = {"findings": [
        finding(),
        finding(title="Duplicate SQLi", start_line=11, end_line=11),           # duplicate -> merged by dedupe
        finding(title="Hallucinated", file="server/nope.js"),                   # bad file -> rejected
        finding(title="Command injection via host", cwe="CWE-78", category="Command Injection", start_line=16,
                end_line=16, evidence="exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));"),
        finding(title="Speculative issue", cwe="CWE-000", severity="low", start_line=21, end_line=21, evidence="app.listen(3000);"),
    ], "dismissed_signals": [{"signal_id": "S001", "reason": "noise"}]}
    review = {"decisions": [
        {"index": 0, "action": "keep", "merge_into": -1, "severity": "critical", "confidence": "high", "status": "confirmed", "corrected_secure_code": "", "reason": "ok"},
        {"index": 1, "action": "keep", "merge_into": -1, "severity": "high", "confidence": "high", "status": "confirmed", "corrected_secure_code": "", "reason": "ok"},
        {"index": 2, "action": "drop", "merge_into": -1, "severity": "low", "confidence": "low", "status": "needs_validation", "corrected_secure_code": "", "reason": "speculative"},
    ], "additional_findings": [], "executive_summary": "Summary.", "overall_risk": "critical",
        "overall_assessment": "Assessment.", "positive_observations": [], "prioritized_actions": ["Fix SQLi"]}
    client = fake_client_factory([analysis, review])
    ai = ClaudeAnalyzer(client=client)
    result = scan(str(FIX), analyzer=ai)

    titles = [f.title for f in result.findings]
    assert "Hallucinated" not in titles
    assert "Speculative issue" not in titles
    assert titles.count("SQL injection in /users") == 1 and "Duplicate SQLi" not in titles
    sqli = next(f for f in result.findings if f.cwe == "CWE-89")
    assert sqli.start_line == 11 and sqli.grounded          # line number corrected from 99
    assert result.findings[0].id == "SR-001" and result.findings[0].severity == "critical"
    assert result.overall_risk == "critical"

    # Requests: structured output, adaptive thinking, cached code, untrusted-data system prompt
    first = client.calls[0]
    assert first["model"] == "claude-opus-5-5"
    assert first["output_config"]["format"]["type"] == "json_schema"
    assert first["thinking"] == {"type": "adaptive"}
    assert first["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert "untrusted" in first["system"][0]["text"].lower()
    # Review pass reuses the identical code block (prompt cache hit)
    assert client.calls[1]["messages"][0]["content"][0]["text"] == first["messages"][0]["content"][0]["text"]

    # Leads the detector ignored are forwarded to the reviewer
    assert "unaddressed_static_signals" in client.calls[1]["messages"][0]["content"][2]["text"]

    paths = write_reports(result, tmp_path, ["md", "html", "json", "sarif"])
    md = paths["md"].read_text()
    for section in ["Executive Summary", "Findings Summary", "Detailed Findings", "Secure Code Example",
                    "Remediation Summary", "Overall Assessment", "Scope and Limitations"]:
        assert section in md
    assert json.loads(paths["sarif"].read_text())["version"] == "2.1.0"
    assert json.loads(paths["json"].read_text())["severity_counts"]["critical"] >= 1


def test_html_report_escapes_untrusted_code(fake_client_factory):
    payload = finding(evidence="x", description="<script>alert(1)</script>", file="server/app.js", start_line=7, end_line=7)
    client = fake_client_factory([{"findings": [payload], "dismissed_signals": []},
                                  {"decisions": [], "additional_findings": [], "executive_summary": "<img src=x onerror=alert(1)>",
                                   "overall_risk": "high", "overall_assessment": "", "positive_observations": [], "prioritized_actions": []}])
    result = scan(str(FIX), analyzer=ClaudeAnalyzer(client=client))
    page = to_html(result)
    assert "<script>alert(1)</script>" not in page
    assert "<img src=x" not in page


def test_rules_only_mode():
    result = scan(str(FIX), use_ai=False)
    assert result.mode == "rules-only"
    assert result.findings and all(f.source == "rules" for f in result.findings)
    assert "Detailed Findings" in to_markdown(result)
    assert to_sarif(result)["runs"][0]["results"]
