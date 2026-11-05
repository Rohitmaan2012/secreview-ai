"""Deterministic, language-aware heuristic rules.

These rules are deliberately generic (nothing here is specific to any one
application). They produce *signals*: leads with a precise file/line that the
AI stage then confirms, rejects as a false positive, or merges into a root
cause finding. In ``--no-ai`` mode they are reported directly, clearly marked
as unverified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .models import Signal, SourceFile

JS_LANGS = {"typescript", "tsx", "javascript", "jsx", "vue", "svelte", "html"}
PY = {"python"}
SQL = {"sql"}
CONFIG = {"json", "yaml", "toml", "dotenv", "ini", "config", "xml", "terraform"}
ALL = None  # any language

PLACEHOLDER_RE = re.compile(
    r"(not[_-]?real|dummy|example|sample|placeholder|changeme|change[_-]me|your[_-]|xxx+|"
    r"fake|demo|test|<.*>|\*\*\*)",
    re.I,
)


@dataclass
class LineRule:
    id: str
    title: str
    category: str
    cwe: str
    severity: str
    pattern: re.Pattern[str]
    hint: str
    languages: set[str] | None = ALL
    confidence: str = "medium"
    # Optional refinement: return None to drop, or (severity, confidence, hint_suffix)
    refine: Callable[[SourceFile, int, re.Match[str]], tuple[str, str, str] | None] | None = None


def _ctx(f: SourceFile, idx: int, before: int = 6, after: int = 6) -> str:
    lines = f.lines
    return "\n".join(lines[max(0, idx - before): idx + after + 1])


def _refine_secret(f: SourceFile, idx: int, m: re.Match[str]):
    value = m.group("val")
    if len(value) < 8 or value.lower() in {"password", "secret", "token"}:
        return None
    if re.fullmatch(r"[A-Z0-9_]+", value) and "_" in value and len(value) < 40:
        # Looks like an env var NAME, not a value.
        return None
    if re.match(r"^(https?://|/|\.|process\.env|Deno\.env|import\.meta)", value):
        return None
    if PLACEHOLDER_RE.search(value):
        return ("medium", "medium",
                " The value looks like a placeholder/demo value; report the insecure *pattern* "
                "(secret embedded in source/client bundle) without claiming a leaked live credential.")
    return None if f.path.endswith((".test.ts", ".spec.ts")) else ("high", "medium", "")


def _refine_html_sink(f: SourceFile, idx: int, m: re.Match[str]):
    ctx = _ctx(f, idx, 4, 4)
    if re.search(r"DOMPurify|sanitize|xss\(|escapeHtml|he\.encode", ctx, re.I):
        return ("low", "low", " A sanitizer appears nearby; verify it covers this sink.")
    return ("high", "medium", "")


def _refine_sql_interp(f: SourceFile, idx: int, m: re.Match[str]):
    # Tagged templates like sql`...${x}` are parameterized in postgres.js / slonik etc.
    # Walk back to the line that opened the template literal.
    for j in range(idx, max(-1, idx - 40), -1):
        line = f.lines[j]
        if "`" in line:
            if re.search(r"\b(sql|db|tx|query|Prisma\.sql)\s*`", line) and "unsafe" not in line:
                return None  # tagged template => driver parameterizes ${} values
            break
    return ("high", "medium", "")


def _refine_cors(f: SourceFile, idx: int, m: re.Match[str]):
    ctx = _ctx(f, idx, 30, 30)
    if re.search(r"credentials['\"]?\s*[:=]\s*['\"]?true", ctx, re.I):
        return ("high", "high", " Wildcard/reflected origin combined with credentials.")
    if re.search(r"authorization", ctx, re.I):
        return ("medium", "medium",
                " Endpoint accepts Authorization headers from any origin; risk depends on how "
                "auth is carried (bearer tokens vs cookies) and whether the endpoint is state-changing.")
    return ("low", "medium", "")


def _refine_debug(f: SourceFile, idx: int, m: re.Match[str]):
    return ("low", "low", "")


LINE_RULES: list[LineRule] = [
    # --- Secrets -----------------------------------------------------------
    LineRule(
        "SECRET-ASSIGN", "Hardcoded secret-like value", "Hardcoded Secrets", "CWE-798", "high",
        re.compile(
            r"(?i)(?P<key>[\w-]*(?:api[_-]?key|secret|passw(?:or)?d|pwd|token|private[_-]?key|"
            r"client[_-]?secret|access[_-]?key|auth[_-]?key|service[_-]?role)[\w-]*)['\"]?\s*[:=]\s*"
            r"['\"`](?P<val>[^'\"`\s]{6,})['\"`]"
        ),
        "A credential-like key is assigned a string literal in source code. Secrets in source end up "
        "in version control and, for frontend code, in the shipped JS bundle.",
        refine=_refine_secret,
    ),
    LineRule(
        "SECRET-PATTERN", "Known credential format in source", "Hardcoded Secrets", "CWE-798", "critical",
        re.compile(
            r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
            r"sk-(?:ant-|proj-|live_)?[A-Za-z0-9_-]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
            r"AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
        ),
        "String matches the format of a real credential (cloud key, token, private key or JWT).",
        confidence="high",
    ),
    # --- XSS / DOM sinks ----------------------------------------------------
    LineRule(
        "XSS-REACT-DANGEROUS", "dangerouslySetInnerHTML renders raw HTML", "Cross-Site Scripting (XSS)",
        "CWE-79", "high", re.compile(r"dangerouslySetInnerHTML"),
        "React's escape hatch injects raw HTML. If the value can contain user-controlled content, "
        "this is stored/reflected XSS.", JS_LANGS, refine=_refine_html_sink,
    ),
    LineRule(
        "XSS-DOM-SINK", "Raw HTML DOM sink", "Cross-Site Scripting (XSS)", "CWE-79", "high",
        re.compile(r"\.(innerHTML|outerHTML)\s*[+]?=|insertAdjacentHTML\(|document\.write(ln)?\(|v-html\s*=|\{@html\s"),
        "Writing strings into a raw HTML sink executes embedded markup/script.", JS_LANGS,
        refine=_refine_html_sink,
    ),
    LineRule(
        "CODE-EVAL", "Dynamic code evaluation", "Code Injection", "CWE-95", "high",
        re.compile(r"(?<![\w.])(eval|new\s+Function)\s*\(|set(Timeout|Interval)\(\s*['\"`]"),
        "Evaluating strings as code allows code injection if any part is attacker-influenced.", JS_LANGS,
    ),
    # --- Injection ----------------------------------------------------------
    LineRule(
        "SQLI-TEMPLATE", "SQL built with string interpolation", "SQL Injection", "CWE-89", "high",
        re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY|VALUES|LIMIT|ILIKE|LIKE)\b.*\$\{[^}]+\}"),
        "SQL text contains template interpolation; unless the value is a bound parameter, input is "
        "concatenated into the query.", JS_LANGS, refine=_refine_sql_interp,
    ),
    LineRule(
        "SQLI-CONCAT", "SQL built with string concatenation", "SQL Injection", "CWE-89", "high",
        re.compile(r"(?i)['\"`]\s*(SELECT|INSERT|UPDATE|DELETE)\b.*['\"`]\s*\+\s*[\w(]|"
                   r"\b(WHERE|AND|OR)\b[^'\"`]*['\"`]\s*\+\s*\w"),
        "SQL text is concatenated with a variable.", JS_LANGS | PY,
    ),
    LineRule(
        "SQLI-RAW-API", "Raw/unsafe query API", "SQL Injection", "CWE-89", "medium",
        re.compile(r"\.(unsafe|\$queryRawUnsafe|\$executeRawUnsafe|raw)\s*\(|knex\.raw\(|sequelize\.query\("),
        "The driver's raw query API bypasses automatic parameterization; check what string is passed.",
        JS_LANGS,
    ),
    LineRule(
        "SQLI-PY-FORMAT", "SQL built with Python string formatting", "SQL Injection", "CWE-89", "high",
        re.compile(r"(?i)\.execute\(\s*(f['\"]|['\"].*['\"]\s*%\s*|['\"].*['\"]\.format\()"),
        "A query passed to execute() is built with f-strings/%/format instead of bound parameters.", PY,
    ),
    LineRule(
        "CMD-INJECTION", "Shell command built from variables", "Command Injection", "CWE-78", "high",
        re.compile(r"(child_process|\bexec|execSync|spawn)\s*\(\s*[`'\"].*(\$\{|\+)|"
                   r"subprocess\.\w+\(.*shell\s*=\s*True|os\.system\(|os\.popen\("),
        "A shell command includes dynamic data; shell metacharacters in that data run arbitrary commands.",
        JS_LANGS | PY,
    ),
    LineRule(
        "PY-DESERIALIZE", "Unsafe deserialization", "Insecure Deserialization", "CWE-502", "high",
        re.compile(r"pickle\.loads?\(|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|marshal\.loads\("),
        "Deserializing untrusted data with these APIs can execute code.", PY,
    ),
    LineRule(
        "PATH-TRAVERSAL", "File path built from request data", "Path Traversal", "CWE-22", "high",
        re.compile(r"(readFile|readFileSync|createReadStream|sendFile|open)\s*\(.*(req\.|params|query|body|searchParams)"),
        "File system access uses a path derived from request data.", JS_LANGS | PY,
    ),
    LineRule(
        "OPEN-REDIRECT", "Redirect to request-controlled URL", "Open Redirect", "CWE-601", "medium",
        re.compile(r"(redirect|location\.href\s*=|window\.location\s*=).*(req\.|query|params|searchParams)"),
        "Redirect target taken from request data.", JS_LANGS | PY,
    ),
    # --- Access control / backend ------------------------------------------
    LineRule(
        "PRIV-SERVICE-ROLE", "Privileged service-role / admin credential used in request handler",
        "Broken Access Control", "CWE-250", "medium",
        re.compile(r"(?i)service_role|SERVICE_ROLE_KEY|supabaseAdmin|firebase-admin|admin\.firestore\("),
        "A privileged key bypasses database row-level security. Every query made with it must enforce "
        "authorization in code (verify caller identity and ownership) or it exposes all rows.",
        JS_LANGS | PY,
    ),
    LineRule(
        "MASS-ASSIGN", "Request body passed directly to a database write", "Mass Assignment",
        "CWE-915", "medium",
        re.compile(r"\.(update|insert|upsert|create|save)\(\s*(req\.body|body|changes|data|payload|input|params)\b\s*[,)]|"
                   r"\.(update|insert|upsert|create)\(\s*\{\s*\.\.\.(req\.body|body)"),
        "Writing a client-supplied object directly lets callers set any column (owner, role, status...).",
        JS_LANGS | PY,
    ),
    LineRule(
        "IDOR-PARAM", "Record looked up by client-supplied identifier", "Insecure Direct Object Reference",
        "CWE-639", "medium",
        re.compile(r"\.eq\(\s*['\"](id|user_?id|owner_?id|account_?id)['\"]\s*,\s*\w+|"
                   r"WHERE\s+\w*id\s*=\s*\$\{"),
        "A record is fetched/modified by an ID from the request. Confirm the handler checks that the "
        "caller is allowed to access that specific record.", JS_LANGS,
    ),
    LineRule(
        "CORS-WILDCARD", "Permissive CORS policy", "Security Misconfiguration", "CWE-942", "low",
        re.compile(r"(?i)Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|origin\s*:\s*(['\"]\*['\"]|true)\b|cors\(\s*\)"),
        "Any website can call this endpoint from a victim's browser.", JS_LANGS | PY | CONFIG,
        refine=_refine_cors,
    ),
    LineRule(
        "ERROR-LEAK", "Internal error details returned to client", "Information Disclosure", "CWE-209", "low",
        re.compile(r"(?i)(details|error|message|stack)['\"]?\s*:\s*(String\((err|error|e)\)|(err|error|e)\.(message|stack)|"
                   r"(err|error|e)\s*[,}])|traceback\.format_exc\(\)"),
        "Raw exception text can reveal schema names, SQL, stack traces or infrastructure details.",
        JS_LANGS | PY,
    ),
    LineRule(
        "SELECT-STAR-RESPONSE", "All columns selected for an API response", "Sensitive Data Exposure",
        "CWE-213", "low", re.compile(r"\.select\(\s*['\"]\*['\"]\s*\)"),
        "Selecting every column may return sensitive fields to the caller; prefer an explicit allowlist.",
        JS_LANGS,
    ),
    LineRule(
        "TOKEN-STORAGE", "Sensitive token in web storage", "Sensitive Data Storage", "CWE-922", "medium",
        re.compile(r"(?i)(localStorage|sessionStorage)\.setItem\(\s*['\"][^'\"]*(token|jwt|secret|session|password)"),
        "Web storage is readable by any script on the origin, so XSS can steal the token.", JS_LANGS,
    ),
    LineRule(
        "WEAK-RANDOM", "Non-cryptographic randomness for a security value", "Weak Randomness", "CWE-338",
        "medium", re.compile(r"(?i)(token|secret|password|otp|nonce|salt|session)\w*\s*=.*Math\.random\(|"
                             r"(token|secret|password|otp|nonce|salt)\w*\s*=.*random\.(random|randint)\("),
        "Math.random/random are predictable; use crypto.randomUUID/getRandomValues or secrets.", JS_LANGS | PY,
    ),
    LineRule(
        "WEAK-HASH", "Weak hash for passwords", "Weak Cryptography", "CWE-327", "medium",
        re.compile(r"(?i)(md5|sha1)\s*\(.*pass|createHash\(\s*['\"](md5|sha1)['\"]\)|hashlib\.(md5|sha1)\("),
        "MD5/SHA-1 are unsuitable for passwords or integrity; use bcrypt/argon2/scrypt or SHA-256+.",
        JS_LANGS | PY,
    ),
    LineRule(
        "JWT-NO-VERIFY", "JWT decoded or verified insecurely", "Broken Authentication", "CWE-347", "high",
        re.compile(r"jwt\.decode\((?!.*verify)|algorithms\s*[:=]\s*\[?\s*['\"]none['\"]|verify_signature['\"]?\s*:\s*False"),
        "Tokens must be signature-verified with a fixed algorithm before trusting claims.", JS_LANGS | PY,
    ),
    LineRule(
        "TLS-DISABLED", "TLS certificate verification disabled", "Security Misconfiguration", "CWE-295", "high",
        re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
        "Disabling certificate checks allows man-in-the-middle attacks.", JS_LANGS | PY | CONFIG,
    ),
    LineRule(
        "DEBUG-ENABLED", "Debug / verbose mode enabled in configuration", "Security Misconfiguration",
        "CWE-489", "low",
        re.compile(r"(?i)\b(debug|DEBUG)\b['\"]?\s*[:=]\s*(true|True|1|\{\s*$)|logLevel['\"]?\s*:\s*['\"](verbose|debug|trace)"),
        "Debug settings shipped to production can leak internals; ensure they are environment-driven.",
        refine=_refine_debug,
    ),
    LineRule(
        "CLEARTEXT-HTTP", "Cleartext HTTP endpoint", "Cleartext Transmission", "CWE-319", "low",
        re.compile(r"['\"`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.|www\.w3\.org)[\w.-]+"),
        "Traffic to this endpoint is unencrypted.", JS_LANGS | PY | CONFIG, confidence="low",
    ),
    # --- SQL / database access control ------------------------------------
    LineRule(
        "RLS-PERMISSIVE", "Row-level security policy allows every row", "Database Access Control",
        "CWE-284", "high", re.compile(r"(?i)\b(USING|WITH\s+CHECK)\s*\(\s*true\s*\)"),
        "A policy with USING (true)/WITH CHECK (true) grants the role access to every row, regardless of owner.",
        SQL,
    ),
    LineRule(
        "SQL-GRANT-PUBLIC", "Broad privileges granted to anonymous/public role", "Database Access Control",
        "CWE-284", "high", re.compile(r"(?i)GRANT\s+(ALL|INSERT|UPDATE|DELETE|SELECT)[^;]*\bTO\s+(anon|public)\b"),
        "Unauthenticated users receive table privileges.", SQL,
    ),
    LineRule(
        "SQL-SECDEF", "SECURITY DEFINER function", "Database Access Control", "CWE-269", "medium",
        re.compile(r"(?i)SECURITY\s+DEFINER"),
        "SECURITY DEFINER functions run with the owner's privileges; they need a fixed search_path and "
        "explicit authorization checks.", SQL,
    ),
    LineRule(
        "SQL-DISABLE-RLS", "Row-level security disabled", "Database Access Control", "CWE-284", "high",
        re.compile(r"(?i)DISABLE\s+ROW\s+LEVEL\s+SECURITY"), "RLS is turned off for this table.", SQL,
    ),
]


# ---------------------------------------------------------------------------
# File-level rules (need whole-file or cross-file context)
# ---------------------------------------------------------------------------

HANDLER_RE = re.compile(
    r"Deno\.serve\(|export\s+(default\s+)?(async\s+)?function\s+(handler|GET|POST|PUT|PATCH|DELETE)\b|"
    r"\bapp\.(get|post|put|patch|delete)\(|\brouter\.(get|post|put|patch|delete)\(|"
    r"export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=|@app\.route\(|@(app|router)\.(get|post|put|patch|delete)\("
)
AUTH_RE = re.compile(
    r"(?i)headers\.get\(\s*['\"]authorization|headers\[\s*['\"]authorization|\.authorization\b|auth\.getUser|getUser\(|getSession\(|verify(Jwt|Token|IdToken)?\(|jwt\.verify|"
    r"requireAuth|isAuthenticated|authenticate\(|passport\.|login_required|Depends\(\s*get_current_user|"
    r"currentUser|req\.user|session\.user|auth\.uid\(\)|bearer"
)


def _file_rules(f: SourceFile, all_files: list[SourceFile]) -> Iterable[tuple[str, str, str, str, str, int, str, str, str]]:
    lines = f.lines
    if f.language in JS_LANGS | PY:
        m = HANDLER_RE.search(f.content)
        if m and not AUTH_RE.search(f.content):
            line = f.content[: m.start()].count("\n") + 1
            mutating = bool(re.search(r"\.(update|insert|upsert|delete)\(|\b(UPDATE|INSERT|DELETE)\b", f.content))
            yield ("AUTH-MISSING-HANDLER", "HTTP handler with no authentication check",
                   "Missing Authentication", "CWE-306", "high" if mutating else "medium", line,
                   lines[line - 1].strip(),
                   "This request handler never reads or verifies the caller's identity (no Authorization "
                   "header, session or token verification found in the file)."
                   + (" It also performs data modification." if mutating else ""), "medium")

    if f.language in SQL:
        text = f.content
        # Tables created without RLS anywhere in the SQL set.
        all_sql = "\n".join(x.content for x in all_files if x.language == "sql")
        for tm in re.finditer(r"(?i)CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?(?P<t>(?:\"?public\"?\.)?\"?\w+\"?)", text):
            table = tm["t"].replace('"', "")
            short = table.split(".")[-1]
            if not re.search(rf"(?i)ALTER\s+TABLE\s+(ONLY\s+)?(\"?public\"?\.)?\"?{re.escape(short)}\"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", all_sql):
                line = text[: tm.start()].count("\n") + 1
                yield ("RLS-NOT-ENABLED", f"Table {table} has no row-level security", "Database Access Control",
                       "CWE-284", "medium", line, lines[line - 1].strip(),
                       "If this table is reachable through an auto-generated API (e.g. PostgREST/Supabase), "
                       "every authenticated or anonymous client can read/write all rows.", "low")
        # Policies that never scope to the current user.
        for pm in re.finditer(r"(?is)CREATE\s+POLICY\s+(?P<name>\"[^\"]+\"|\w+)\s+ON\s+(?P<table>[\w.\"]+)(?P<body>.*?);", text):
            body = pm["body"]
            if re.search(r"(?i)\b(USING|WITH\s+CHECK)\s*\(\s*true\s*\)", body):
                continue  # covered by RLS-PERMISSIVE line rule
            if not re.search(r"(?i)auth\.(uid|jwt|role)\(\)|current_user|current_setting\(|session_user", body):
                line = text[: pm.start()].count("\n") + 1
                yield ("RLS-UNSCOPED-POLICY", f"Policy {pm['name']} is not scoped to the current user",
                       "Database Access Control", "CWE-863", "high", line, lines[line - 1].strip(),
                       "The policy condition never references the requesting user (auth.uid()/JWT claims), so "
                       "its result is the same for every user. Check whether it effectively grants all rows.",
                       "medium")
            # UPDATE policies on tables that contain privilege columns.
            if re.search(r"(?i)FOR\s+(UPDATE|ALL)\b", body):
                table = pm["table"].replace('"', "").split(".")[-1]
                tdef = re.search(rf"(?is)CREATE\s+TABLE\s+[\w.\"]*{re.escape(table)}\"?\s*\((?P<cols>.*?)\);", all_sql)
                check = (re.search(r"(?is)WITH\s+CHECK\s*\((.*)\)", body) or [None, ""])[1] or ""
                priv_cols = {c.lower() for c in re.findall(
                    r"(?i)(?:^|,)\s*\"?(role|is_admin|admin|permissions?|plan|tier|owner_id|tenant_id|org_id)\"?\s+\w+",
                    tdef["cols"].strip())} if tdef else set()
                unprotected = sorted(c for c in priv_cols if not re.search(rf"(?i)\b{c}\b", check))
                if unprotected:
                    line = text[: pm.start()].count("\n") + 1
                    yield ("RLS-UPDATE-PRIV-COLUMN",
                           f"UPDATE policy on {table} does not protect column(s): {', '.join(unprotected)}",
                           "Privilege Escalation", "CWE-269", "high", line, lines[line - 1].strip(),
                           "Row-level policies restrict *which rows* can be updated, not *which columns*. "
                           "If the table has role/ownership columns and no column-level GRANT or trigger "
                           "protects them, a user can update their own row to escalate privileges or "
                           "reassign ownership.", "medium")


def run_rules(files: list[SourceFile]) -> list[Signal]:
    signals: list[Signal] = []
    seen: set[tuple[str, str, int]] = set()

    def add(rule_id, title, category, cwe, severity, path, line, snippet, hint, confidence):
        key = (rule_id, path, line)
        if key in seen:
            return
        seen.add(key)
        signals.append(Signal(f"S{len(signals) + 1:03d}", rule_id, title, category, cwe, severity,
                              path, line, snippet[:300], hint, confidence))

    for f in files:
        for idx, line in enumerate(f.lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "--", "*", "/*")) and "dangerouslySetInnerHTML" not in stripped:
                continue
            for rule in LINE_RULES:
                if rule.languages is not None and f.language not in rule.languages:
                    continue
                m = rule.pattern.search(line)
                if not m:
                    continue
                severity, confidence, hint = rule.severity, rule.confidence, rule.hint
                if rule.refine:
                    r = rule.refine(f, idx, m)
                    if r is None:
                        continue
                    severity, confidence, extra = r
                    hint += extra
                add(rule.id, rule.title, rule.category, rule.cwe, severity, f.path, idx + 1,
                    stripped, hint, confidence)
        for item in _file_rules(f, files):
            rule_id, title, category, cwe, severity, line, snippet, hint, confidence = item
            add(rule_id, title, category, cwe, severity, f.path, line, snippet, hint, confidence)
    return signals
