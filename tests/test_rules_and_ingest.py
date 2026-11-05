import io
import zipfile
from pathlib import Path

import pytest

from secreview.ingest import IngestError, Workspace, collect_files, safe_extract_zip
from secreview.rules import run_rules

FIX = Path(__file__).parent / "fixtures"


def rules_for(path):
    return {(s.rule_id, s.file) for s in run_rules(collect_files(path))}


def test_unseen_app_rules_generalize():
    hits = rules_for(FIX / "unseen-app")
    assert ("SQLI-CONCAT", "server/app.js") in hits
    assert ("CMD-INJECTION", "server/app.js") in hits
    assert ("SECRET-ASSIGN", "server/app.js") in hits
    assert ("OPEN-REDIRECT", "server/app.js") in hits
    assert ("AUTH-MISSING-HANDLER", "server/app.js") in hits
    assert ("PY-DESERIALIZE", "api/views.py") in hits
    assert ("SQLI-PY-FORMAT", "api/views.py") in hits


def test_tagged_sql_template_not_flagged(tmp_path):
    (tmp_path / "q.ts").write_text("const r = await sql`\n  SELECT * FROM t\n  WHERE id = ${id}\n`;\n")
    assert not any(r == "SQLI-TEMPLATE" for r, _ in rules_for(tmp_path))


def test_untagged_sql_template_flagged(tmp_path):
    (tmp_path / "q.ts").write_text("const q = `\n  SELECT * FROM t\n  WHERE name = '${name}'\n`;\nawait db.unsafe(q);\n")
    assert ("SQLI-TEMPLATE", "q.ts") in rules_for(tmp_path)


def test_env_var_name_not_a_secret(tmp_path):
    (tmp_path / "a.ts").write_text('const apiKey = Deno.env.get("API_KEY");\nconst token_name = "ACCESS_TOKEN_NAME";\n')
    assert not any(r.startswith("SECRET") for r, _ in rules_for(tmp_path))


def test_rls_rules(tmp_path):
    (tmp_path / "s.sql").write_text(
        "CREATE TABLE public.p (id uuid, role text);\n"
        "CREATE TABLE public.open (id uuid);\n"
        "ALTER TABLE public.p ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY \"x\" ON public.p FOR SELECT USING (true);\n"
        "CREATE POLICY \"u\" ON public.p FOR UPDATE USING (id = auth.uid()) WITH CHECK (id = auth.uid());\n")
    hits = {r for r, _ in rules_for(tmp_path)}
    assert {"RLS-PERMISSIVE", "RLS-UPDATE-PRIV-COLUMN", "RLS-NOT-ENABLED"} <= hits


def test_skips_node_modules_and_lockfiles(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "i.js").write_text("eval(x)")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "a.js").write_text("console.log(1)")
    assert [f.path for f in collect_files(tmp_path)] == ["a.js"]


def test_zip_slip_is_blocked(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.txt", "x")
        z.writestr("proj/ok.js", "eval(a)")
    root = safe_extract_zip(buf.getvalue(), tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()
    assert (root / "ok.js").exists()


def test_workspace_zip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("proj/a.js", "document.write(x)")
    zp = tmp_path / "p.zip"
    zp.write_bytes(buf.getvalue())
    with Workspace(str(zp)) as ws:
        assert [f.path for f in collect_files(ws.root)] == ["a.js"]


def test_missing_target():
    with pytest.raises(IngestError):
        with Workspace("/does/not/exist"):
            pass
