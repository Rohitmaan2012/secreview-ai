"""Minimal local web interface (Flask). Run with ``secreview web``."""

from __future__ import annotations

import os
import tempfile
import threading
import uuid
from pathlib import Path

from flask import Flask, abort, redirect, render_template_string, request, send_file, url_for

from .report import write_reports
from .scanner import scan

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecReview AI</title>{% if refresh %}<meta http-equiv="refresh" content="3">{% endif %}
<style>
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--muted:#5d6678;--line:#e2e5eb;--acc:#1f4fd1}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e6e8ec;--muted:#9aa3b2;--line:#2a303c;--acc:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:28px 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}
h1{margin:0}label{display:block;font-weight:600;margin:14px 0 6px}input[type=text],input[type=file],select{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-weight:600;cursor:pointer;margin-top:16px}
.muted{color:var(--muted)}code{font-family:ui-monospace,monospace}pre{white-space:pre-wrap;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:13px}
a{color:var(--acc)}iframe{width:100%;height:80vh;border:1px solid var(--line);border-radius:12px;background:#fff}.row{display:flex;gap:12px;flex-wrap:wrap}.row>*{flex:1;min-width:200px}
</style></head><body><div class="wrap">
<h1>SecReview AI</h1><p class="muted">AI-powered security code review: Find. Fix. Fortify.</p>
{% if page == 'home' %}
<form class="card" method="post" action="{{ url_for('start') }}" enctype="multipart/form-data">
<label>GitHub URL{% if allow_local %} or local folder path{% endif %}</label>
<input type="text" name="target" placeholder="https://github.com/owner/repo  {% if allow_local %}or /path/to/project{% endif %}">
<label>…or upload a ZIP of the source code</label><input type="file" name="zipfile" accept=".zip">
<div class="row"><div><label>Analysis mode</label><select name="mode"><option value="ai">AI (Claude) + rules</option><option value="rules">Rules only (no API key)</option></select></div>
<div><label>Minimum severity</label><select name="min_severity">{% for s in sevs %}<option value="{{s}}" {% if s=='info' %}selected{% endif %}>{{s}}</option>{% endfor %}</select></div></div>
<button type="submit">Scan code</button>
<p class="muted">{% if has_key %}AI provider key detected.{% else %}No ANTHROPIC_API_KEY or GEMINI_API_KEY set: only rules-only mode will work (or start with SECREVIEW_PROVIDER=ollama).{% endif %}</p>
</form>
{% if jobs %}<div class="card"><b>Recent scans</b><ul>{% for j in jobs %}<li><a href="{{ url_for('job', job_id=j.id) }}">{{ j.target }}</a> <span class="muted">({{ j.state }})</span></li>{% endfor %}</ul></div>{% endif %}
{% elif page == 'job' %}
<div class="card"><b>Target:</b> <code>{{ j.target }}</code><br><b>Status:</b> {{ j.state }}
{% if j.state == 'running' %}<pre>{{ j.log|join('\n') }}</pre>{% endif %}
{% if j.state == 'failed' %}<pre>{{ j.error }}</pre>{% endif %}
{% if j.state == 'done' %}<p>{{ j.summary }}</p><p>Download: {% for fmt in j.files %}<a href="{{ url_for('download', job_id=j.id, fmt=fmt) }}">{{ fmt|upper }}</a> {% endfor %}</p>{% endif %}
<p><a href="{{ url_for('home') }}">New scan</a></p></div>
{% if j.state == 'done' %}<iframe src="{{ url_for('download', job_id=j.id, fmt='html') }}?inline=1" sandbox="allow-scripts"></iframe>{% endif %}
{% endif %}
</div></body></html>"""


def create_app(output_dir: Path = Path("reports"), allow_local_paths: bool = True) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
    jobs: dict[str, dict] = {}
    upload_dir = Path(tempfile.mkdtemp(prefix="secreview-uploads-"))

    def run_job(job: dict, target: str, use_ai: bool, min_sev: str) -> None:
        try:
            result = scan(target, use_ai=use_ai, min_severity=min_sev, provider=os.environ.get("SECREVIEW_PROVIDER"),
                          progress=job["log"].append)
            files = write_reports(result, output_dir / job["id"], ["html", "md", "json", "sarif"])
            counts = result.severity_counts()
            job["files"] = {k: str(v) for k, v in files.items()}
            job["summary"] = (f"{len(result.findings)} findings (overall risk {result.overall_risk.upper()}): "
                              + ", ".join(f"{v} {k}" for k, v in counts.items() if v))
            job["state"] = "done"
        except Exception as exc:  # show error to the local user
            job["state"] = "failed"
            job["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if job.get("upload"):
                Path(job["upload"]).unlink(missing_ok=True)

    @app.get("/")
    def home():
        return render_template_string(PAGE, page="home", allow_local=allow_local_paths, sevs=["critical", "high", "medium", "low", "info"],
                                      has_key=bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("GEMINI_API_KEY")),
                                      jobs=list(reversed(jobs.values()))[:10], refresh=False)

    @app.post("/scan")
    def start():
        target = (request.form.get("target") or "").strip()
        upload = request.files.get("zipfile")
        job_id = uuid.uuid4().hex[:12]
        saved = None
        if upload and upload.filename:
            if not upload.filename.lower().endswith(".zip"):
                abort(400, "Only .zip uploads are supported")
            saved = upload_dir / f"{job_id}.zip"
            upload.save(saved)
            target = str(saved)
            label = upload.filename
        else:
            if not target:
                abort(400, "Provide a GitHub URL, folder path, or ZIP")
            if not target.startswith(("http://", "https://")) and not allow_local_paths:
                abort(400, "Local paths are disabled on this server")
            label = target
        min_sev = request.form.get("min_severity", "info")
        job = {"id": job_id, "target": label, "state": "running", "log": [], "files": {}, "upload": str(saved) if saved else None}
        jobs[job_id] = job
        threading.Thread(target=run_job, args=(job, target, request.form.get("mode") != "rules", min_sev), daemon=True).start()
        return redirect(url_for("job", job_id=job_id))

    @app.get("/job/<job_id>")
    def job(job_id: str):
        j = jobs.get(job_id) or abort(404)
        return render_template_string(PAGE, page="job", j=j, refresh=j["state"] == "running")

    @app.get("/job/<job_id>/report.<fmt>")
    def download(job_id: str, fmt: str):
        j = jobs.get(job_id) or abort(404)
        path = j.get("files", {}).get(fmt) or abort(404)
        inline = request.args.get("inline") == "1" and fmt == "html"
        return send_file(path, as_attachment=not inline, download_name=Path(path).name)

    return app
