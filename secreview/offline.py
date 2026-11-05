"""Rules-only mode (``--no-ai``): turn static signals into report findings.

This mode exists so the tool still works without an API key (CI, air-gapped review, judging
machines). Findings are clearly labelled as unverified heuristic leads; the AI mode is what
confirms exploitability, removes false positives, and writes code-specific fixes.
"""

from __future__ import annotations

from collections import OrderedDict

from .models import SEVERITY_RANK, Finding, RelatedLocation, Signal, SourceFile

T = {
    "SECRET-ASSIGN": (
        "Move the value out of source code. Load it from server-side configuration (environment "
        "variables or a secrets manager) and rotate it if it was ever real. Never ship private keys "
        "in frontend bundles; proxy calls that need them through a backend.",
        "typescript",
        "// Server-side only: read from the environment, fail closed if missing\n"
        "const apiKey = process.env.ANALYTICS_API_KEY;\n"
        "if (!apiKey) throw new Error(\"ANALYTICS_API_KEY is not configured\");",
    ),
    "SECRET-PATTERN": (
        "Revoke and rotate this credential immediately, remove it from the repository history, and "
        "load it from a secrets manager or environment variable at runtime.",
        "bash", "git rm --cached <file>  # then rotate the key with the provider and purge history",
    ),
    "XSS-REACT-DANGEROUS": (
        "Render user content as text (React escapes it automatically). If rich text is required, "
        "sanitize it with a vetted library such as DOMPurify using a strict allowlist.",
        "tsx",
        "// Safe default: render as text\n<div className=\"comment-text\">{comment.text}</div>\n\n"
        "// Only if HTML is required:\nimport DOMPurify from \"dompurify\";\n"
        "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.text, { USE_PROFILES: { html: true } }) }} />",
    ),
    "XSS-DOM-SINK": (
        "Use textContent / createTextNode for untrusted data, or sanitize with DOMPurify before "
        "writing HTML.", "javascript", "element.textContent = userInput;",
    ),
    "CODE-EVAL": ("Remove dynamic evaluation; parse data with JSON.parse or use a lookup table of allowed functions.",
                  "javascript", "const handlers = { add, remove };\nconst fn = handlers[action];\nif (!fn) throw new Error(\"Unsupported action\");\nfn(args);"),
    "SQLI-TEMPLATE": (
        "Never build SQL by interpolating input. Use the driver's parameterized/tagged query API so "
        "values are sent separately from the SQL text, and escape LIKE wildcards.",
        "typescript",
        "const pattern = `%${searchTerm.replace(/[\\\\%_]/g, \"\\\\$&\")}%`;\n"
        "const tasks = await sql`\n  SELECT id, title, description, status\n  FROM public.tasks\n"
        "  WHERE title ILIKE ${pattern}\n  ORDER BY created_at DESC\n  LIMIT 25\n`;",
    ),
    "SQLI-CONCAT": ("Use bound parameters instead of string concatenation.", "typescript",
                    "await db.query(\"SELECT * FROM users WHERE email = $1\", [email]);"),
    "SQLI-RAW-API": ("Avoid raw/unsafe query APIs with dynamic strings; use parameterized queries.", "typescript",
                     "const rows = await sql`SELECT ... WHERE id = ${id}`; // tagged template = parameterized"),
    "SQLI-PY-FORMAT": ("Pass values as parameters to execute().", "python",
                       "cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))"),
    "CMD-INJECTION": ("Avoid the shell. Pass arguments as an array to execFile/spawn (or subprocess.run([...]) without shell=True) and validate them against an allowlist.",
                      "javascript", "execFile(\"convert\", [inputPath, outputPath], callback);"),
    "PY-DESERIALIZE": ("Use safe formats (JSON) or yaml.safe_load; never unpickle untrusted data.", "python", "data = yaml.safe_load(stream)"),
    "PATH-TRAVERSAL": ("Map user input to an allowlist, or resolve the path and verify it stays within the base directory.",
                       "typescript", "const full = path.resolve(BASE, name);\nif (!full.startsWith(BASE + path.sep)) throw new Error(\"Invalid path\");"),
    "OPEN-REDIRECT": ("Only redirect to relative paths or an allowlist of hosts.", "typescript",
                      "const next = url.startsWith(\"/\") && !url.startsWith(\"//\") ? url : \"/\";"),
    "PRIV-SERVICE-ROLE": (
        "Do not use the privileged key for user requests. Create the client with the caller's JWT so "
        "row-level security applies, verify the user, and enforce ownership in the query.",
        "typescript",
        "const authHeader = request.headers.get(\"Authorization\");\n"
        "if (!authHeader) return Response.json({ error: \"Unauthorized\" }, { status: 401 });\n"
        "const supabase = createClient(Deno.env.get(\"SUPABASE_URL\")!, Deno.env.get(\"SUPABASE_ANON_KEY\")!, {\n"
        "  global: { headers: { Authorization: authHeader } },\n});\n"
        "const { data: { user }, error } = await supabase.auth.getUser();\n"
        "if (error || !user) return Response.json({ error: \"Unauthorized\" }, { status: 401 });",
    ),
    "MASS-ASSIGN": (
        "Validate the request body and copy only an explicit allowlist of editable fields; never let "
        "clients set ownership, role or identifier columns.",
        "typescript",
        "const ALLOWED = [\"title\", \"description\", \"status\"] as const;\n"
        "const updates = Object.fromEntries(\n  Object.entries(body.changes ?? {}).filter(([k]) => (ALLOWED as readonly string[]).includes(k)),\n);",
    ),
    "IDOR-PARAM": ("Derive the user from the verified session, and scope queries by owner (e.g. .eq(\"owner_id\", user.id)) instead of trusting a client-supplied ID.",
                   "typescript", ".eq(\"id\", taskId)\n.eq(\"owner_id\", user.id)"),
    "CORS-WILDCARD": ("Allow only the application's own origins.", "typescript",
                      "const ALLOWED_ORIGINS = new Set([\"https://app.example.com\"]);\n"
                      "const origin = request.headers.get(\"Origin\") ?? \"\";\n"
                      "const corsHeaders = ALLOWED_ORIGINS.has(origin) ? { \"Access-Control-Allow-Origin\": origin, Vary: \"Origin\" } : {};"),
    "ERROR-LEAK": ("Log the detailed error server-side and return a generic message with a correlation id.", "typescript",
                   "const errorId = crypto.randomUUID();\nconsole.error(errorId, error);\n"
                   "return Response.json({ error: \"Internal error\", errorId }, { status: 500 });"),
    "SELECT-STAR-RESPONSE": ("Select only the columns the caller needs.", "typescript", ".select(\"id, full_name, bio\")"),
    "TOKEN-STORAGE": ("Prefer HttpOnly, Secure, SameSite cookies for session tokens.", "", ""),
    "WEAK-RANDOM": ("Use a CSPRNG.", "javascript", "const token = crypto.randomUUID();"),
    "WEAK-HASH": ("Use a password hashing function such as argon2id or bcrypt.", "javascript", "const hash = await argon2.hash(password);"),
    "JWT-NO-VERIFY": ("Verify the signature with a fixed algorithm list before using claims.", "javascript",
                      "jwt.verify(token, publicKey, { algorithms: [\"RS256\"] });"),
    "TLS-DISABLED": ("Keep certificate verification enabled; add the internal CA to the trust store if needed.", "", ""),
    "DEBUG-ENABLED": ("Drive debug/logging settings from the environment and default them off in production builds.", "typescript",
                      "debug: { enabled: import.meta.env.DEV, logLevel: import.meta.env.DEV ? \"verbose\" : \"warn\" }"),
    "CLEARTEXT-HTTP": ("Use https:// endpoints.", "", ""),
    "RLS-PERMISSIVE": ("Scope the policy to the rows the caller should see (owner, team or project membership).", "sql",
                       "CREATE POLICY \"Users can view own tasks\"\nON public.tasks FOR SELECT TO authenticated\nUSING (owner_id = auth.uid());"),
    "RLS-UNSCOPED-POLICY": ("Reference the requesting user in the policy condition, e.g. via ownership or membership of the parent row.", "sql",
                            "USING (EXISTS (SELECT 1 FROM public.tasks t WHERE t.id = task_comments.task_id AND t.owner_id = auth.uid()))"),
    "RLS-UPDATE-PRIV-COLUMN": ("Restrict which columns users may update (column-level GRANTs or a trigger that rejects changes to privileged columns).", "sql",
                               "REVOKE UPDATE ON public.profiles FROM authenticated;\nGRANT UPDATE (full_name, bio) ON public.profiles TO authenticated;"),
    "RLS-NOT-ENABLED": ("Enable row level security and add explicit policies.", "sql", "ALTER TABLE public.my_table ENABLE ROW LEVEL SECURITY;"),
    "SQL-GRANT-PUBLIC": ("Grant only the minimum privileges to authenticated roles.", "sql", "REVOKE ALL ON public.my_table FROM anon;"),
    "SQL-SECDEF": ("Set a fixed search_path and check auth.uid() inside the function, or use SECURITY INVOKER.", "sql",
                   "ALTER FUNCTION public.fn() SET search_path = public, pg_temp;"),
    "SQL-DISABLE-RLS": ("Keep RLS enabled.", "sql", "ALTER TABLE public.my_table ENABLE ROW LEVEL SECURITY;"),
    "AUTH-MISSING-HANDLER": (
        "Require and verify authentication at the start of the handler; reject unauthenticated requests with 401.",
        "typescript",
        "const authHeader = request.headers.get(\"Authorization\");\n"
        "if (!authHeader) return Response.json({ error: \"Unauthorized\" }, { status: 401 });\n"
        "// verify the token with your auth provider and use the resulting user id",
    ),
}


def signals_to_findings(signals: list[Signal], files: list[SourceFile]) -> list[Finding]:
    by_path = {f.path: f for f in files}
    groups: "OrderedDict[tuple[str, str], list[Signal]]" = OrderedDict()
    for s in signals:
        # One finding per weakness class (CWE) per file, to avoid duplicate root causes.
        groups.setdefault((s.cwe, s.file), []).append(s)
    findings = []
    for (_cwe, path), sigs in groups.items():
        sigs.sort(key=lambda x: (SEVERITY_RANK[x.severity], x.line))
        first = sigs[0]
        rule_id = first.rule_id
        src = by_path[path]
        start = max(1, first.line - 1)
        end = min(len(src.lines), first.line + 1)
        remediation, lang, code = T.get(rule_id, ("Review and remediate.", "", ""))
        findings.append(Finding(
            title=first.title, severity=first.severity, category=first.category, cwe=first.cwe,
            file=path, start_line=first.line, end_line=first.line,
            evidence="\n".join(src.lines[start - 1:end]),
            description=first.hint, impact=first.hint, remediation=remediation,
            secure_code=code, secure_code_language=lang,
            confidence="low" if first.confidence == "low" else "medium", status="needs_validation",
            assumptions="Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.",
            related_locations=[RelatedLocation(s.file, s.line, f"{s.title}: {s.snippet[:80]}") for s in sigs[1:]],
            signal_ids=[s.id for s in sigs], source="rules",
        ))
    return findings
