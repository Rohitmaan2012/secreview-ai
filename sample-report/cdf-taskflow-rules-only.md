# Security Assessment Report: vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app)

## 1. Assessment Information

| | |
|---|---|
| **Application** | vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app) |
| **Source** | `https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app` |
| **Assessment type** | Rule-based static code review (no AI) |
| **Assessment date** | 2026-11-04 23:37 UTC |
| **Tool** | SecReview AI v1.0.0 |
| **Files / lines reviewed** | 18 files, 951 lines |
| **Overall risk rating** | **HIGH** |

## 2. Executive Summary

18 source files of vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app) were scanned with the rule engine, which flagged 19 potential issue(s) (6 high, 9 medium, 4 low). These are unverified leads.

> Rules-only mode: findings are heuristic leads and have not been verified.

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 6 |
| Medium | 9 |
| Low | 4 |
| Info | 0 |
| **Total** | **19** |

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| [SR-001](#sr-001) | High | dangerouslySetInnerHTML renders raw HTML | `src/components/TaskComments.tsx:40` | Needs validation |
| [SR-002](#sr-002) | High | SQL built with string interpolation | `supabase/functions/search-tasks/index.ts:23` | Needs validation |
| [SR-003](#sr-003) | High | HTTP handler with no authentication check | `supabase/functions/update-task/index.ts:11` | Needs validation |
| [SR-004](#sr-004) | High | Row-level security policy allows every row | `supabase/migrations/002_access_policies.sql:13` | Needs validation |
| [SR-005](#sr-005) | High | UPDATE policy on profiles does not protect column(s): role | `supabase/migrations/002_access_policies.sql:15` | Needs validation |
| [SR-006](#sr-006) | High | Policy "Users can view task comments" is not scoped to the current user | `supabase/migrations/002_access_policies.sql:53` | Needs validation |
| [SR-007](#sr-007) | Medium | Hardcoded secret-like value | `src/lib/demoConfig.ts:9` | Needs validation |
| [SR-008](#sr-008) | Medium | HTTP handler with no authentication check | `supabase/functions/get-profile/index.ts:4` | Needs validation |
| [SR-009](#sr-009) | Medium | Privileged service-role / admin credential used in request handler | `supabase/functions/get-profile/index.ts:25` | Needs validation |
| [SR-010](#sr-010) | Medium | Record looked up by client-supplied identifier | `supabase/functions/get-profile/index.ts:31` | Needs validation |
| [SR-011](#sr-011) | Medium | HTTP handler with no authentication check | `supabase/functions/search-tasks/index.ts:4` | Needs validation |
| [SR-012](#sr-012) | Medium | Permissive CORS policy | `supabase/functions/update-task/index.ts:5` | Needs validation |
| [SR-013](#sr-013) | Medium | Privileged service-role / admin credential used in request handler | `supabase/functions/update-task/index.ts:33` | Needs validation |
| [SR-014](#sr-014) | Medium | Request body passed directly to a database write | `supabase/functions/update-task/index.ts:38` | Needs validation |
| [SR-015](#sr-015) | Medium | Record looked up by client-supplied identifier | `supabase/functions/update-task/index.ts:39` | Needs validation |
| [SR-016](#sr-016) | Low | All columns selected for an API response | `supabase/functions/get-profile/index.ts:30` | Needs validation |
| [SR-017](#sr-017) | Low | Internal error details returned to client | `supabase/functions/get-profile/index.ts:44` | Needs validation |
| [SR-018](#sr-018) | Low | Internal error details returned to client | `supabase/functions/update-task/index.ts:58` | Needs validation |
| [SR-019](#sr-019) | Low | Debug / verbose mode enabled in configuration | `src/lib/demoConfig.ts:12` | Needs validation |

**By category:** Missing Authentication (3), Database Access Control (2), Broken Access Control (2), Insecure Direct Object Reference (2), Security Misconfiguration (2), Information Disclosure (2), Cross-Site Scripting (XSS) (1), SQL Injection (1), Privilege Escalation (1), Hardcoded Secrets (1), Mass Assignment (1), Sensitive Data Exposure (1)

## 4. Detailed Findings

<a id="sr-001"></a>
### SR-001: dangerouslySetInnerHTML renders raw HTML

| | |
|---|---|
| **Severity** | High |
| **Category** | Cross-Site Scripting (XSS) |
| **CWE** | CWE-79 |
| **Affected file** | `src/components/TaskComments.tsx` |
| **Code location** | line 40 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

React's escape hatch injects raw HTML. If the value can contain user-controlled content, this is stored/reflected XSS.

#### Vulnerable Code (`src/components/TaskComments.tsx`, line 40)

```tsx
              <div
                dangerouslySetInnerHTML={{
                  __html: comment.text,
```

#### Potential Impact

React's escape hatch injects raw HTML. If the value can contain user-controlled content, this is stored/reflected XSS.

#### Recommended Fix

Render user content as text (React escapes it automatically). If rich text is required, sanitize it with a vetted library such as DOMPurify using a strict allowlist.

#### Secure Code Example

```tsx
// Safe default: render as text
<div className="comment-text">{comment.text}</div>

// Only if HTML is required:
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.text, { USE_PROFILES: { html: true } }) }} />
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-002"></a>
### SR-002: SQL built with string interpolation

| | |
|---|---|
| **Severity** | High |
| **Category** | SQL Injection |
| **CWE** | CWE-89 |
| **Affected file** | `supabase/functions/search-tasks/index.ts` |
| **Code location** | line 23 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

SQL text contains template interpolation; unless the value is a bound parameter, input is concatenated into the query.

#### Vulnerable Code (`supabase/functions/search-tasks/index.ts`, line 23)

```typescript
      FROM public.tasks
      WHERE title ILIKE '%${searchTerm}%'
      ORDER BY created_at DESC
```

#### Potential Impact

SQL text contains template interpolation; unless the value is a bound parameter, input is concatenated into the query.

#### Recommended Fix

Never build SQL by interpolating input. Use the driver's parameterized/tagged query API so values are sent separately from the SQL text, and escape LIKE wildcards.

#### Secure Code Example

```typescript
const pattern = `%${searchTerm.replace(/[\\%_]/g, "\\$&")}%`;
const tasks = await sql`
  SELECT id, title, description, status
  FROM public.tasks
  WHERE title ILIKE ${pattern}
  ORDER BY created_at DESC
  LIMIT 25
`;
```

#### Other Affected Locations

- `supabase/functions/search-tasks/index.ts:28` - Raw/unsafe query API: const tasks = await sql.unsafe(query);

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-003"></a>
### SR-003: HTTP handler with no authentication check

| | |
|---|---|
| **Severity** | High |
| **Category** | Missing Authentication |
| **CWE** | CWE-306 |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | line 11 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

This request handler never reads or verifies the caller's identity (no Authorization header, session or token verification found in the file). It also performs data modification.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, line 11)

```typescript

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
```

#### Potential Impact

This request handler never reads or verifies the caller's identity (no Authorization header, session or token verification found in the file). It also performs data modification.

#### Recommended Fix

Require and verify authentication at the start of the handler; reject unauthenticated requests with 401.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization");
if (!authHeader) return Response.json({ error: "Unauthorized" }, { status: 401 });
// verify the token with your auth provider and use the resulting user id
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-004"></a>
### SR-004: Row-level security policy allows every row

| | |
|---|---|
| **Severity** | High |
| **Category** | Database Access Control |
| **CWE** | CWE-284 |
| **Affected file** | `supabase/migrations/002_access_policies.sql` |
| **Code location** | line 13 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

A policy with USING (true)/WITH CHECK (true) grants the role access to every row, regardless of owner.

#### Vulnerable Code (`supabase/migrations/002_access_policies.sql`, line 13)

```sql
TO authenticated
USING (true);

```

#### Potential Impact

A policy with USING (true)/WITH CHECK (true) grants the role access to every row, regardless of owner.

#### Recommended Fix

Scope the policy to the rows the caller should see (owner, team or project membership).

#### Secure Code Example

```sql
CREATE POLICY "Users can view own tasks"
ON public.tasks FOR SELECT TO authenticated
USING (owner_id = auth.uid());
```

#### Other Affected Locations

- `supabase/migrations/002_access_policies.sql:38` - Row-level security policy allows every row: USING (true);

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-005"></a>
### SR-005: UPDATE policy on profiles does not protect column(s): role

| | |
|---|---|
| **Severity** | High |
| **Category** | Privilege Escalation |
| **CWE** | CWE-269 |
| **Affected file** | `supabase/migrations/002_access_policies.sql` |
| **Code location** | line 15 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

Row-level policies restrict *which rows* can be updated, not *which columns*. If the table has role/ownership columns and no column-level GRANT or trigger protects them, a user can update their own row to escalate privileges or reassign ownership.

#### Vulnerable Code (`supabase/migrations/002_access_policies.sql`, line 15)

```sql

CREATE POLICY "Users can update own profile"
ON public.profiles
```

#### Potential Impact

Row-level policies restrict *which rows* can be updated, not *which columns*. If the table has role/ownership columns and no column-level GRANT or trigger protects them, a user can update their own row to escalate privileges or reassign ownership.

#### Recommended Fix

Restrict which columns users may update (column-level GRANTs or a trigger that rejects changes to privileged columns).

#### Secure Code Example

```sql
REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (full_name, bio) ON public.profiles TO authenticated;
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-006"></a>
### SR-006: Policy "Users can view task comments" is not scoped to the current user

| | |
|---|---|
| **Severity** | High |
| **Category** | Database Access Control |
| **CWE** | CWE-863 |
| **Affected file** | `supabase/migrations/002_access_policies.sql` |
| **Code location** | line 53 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

The policy condition never references the requesting user (auth.uid()/JWT claims), so its result is the same for every user. Check whether it effectively grants all rows.

#### Vulnerable Code (`supabase/migrations/002_access_policies.sql`, line 53)

```sql

CREATE POLICY "Users can view task comments"
ON public.task_comments
```

#### Potential Impact

The policy condition never references the requesting user (auth.uid()/JWT claims), so its result is the same for every user. Check whether it effectively grants all rows.

#### Recommended Fix

Reference the requesting user in the policy condition, e.g. via ownership or membership of the parent row.

#### Secure Code Example

```sql
USING (EXISTS (SELECT 1 FROM public.tasks t WHERE t.id = task_comments.task_id AND t.owner_id = auth.uid()))
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-007"></a>
### SR-007: Hardcoded secret-like value

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Hardcoded Secrets |
| **CWE** | CWE-798 |
| **Affected file** | `src/lib/demoConfig.ts` |
| **Code location** | line 9 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

A credential-like key is assigned a string literal in source code. Secrets in source end up in version control and, for frontend code, in the shipped JS bundle. The value looks like a placeholder/demo value; report the insecure *pattern* (secret embedded in source/client bundle) without claiming a leaked live credential.

#### Vulnerable Code (`src/lib/demoConfig.ts`, line 9)

```typescript
    enabled: true,
    apiKey: "cdf_demo_private_key_NOT_REAL_12345",
  },
```

#### Potential Impact

A credential-like key is assigned a string literal in source code. Secrets in source end up in version control and, for frontend code, in the shipped JS bundle. The value looks like a placeholder/demo value; report the insecure *pattern* (secret embedded in source/client bundle) without claiming a leaked live credential.

#### Recommended Fix

Move the value out of source code. Load it from server-side configuration (environment variables or a secrets manager) and rotate it if it was ever real. Never ship private keys in frontend bundles; proxy calls that need them through a backend.

#### Secure Code Example

```typescript
// Server-side only: read from the environment, fail closed if missing
const apiKey = process.env.ANALYTICS_API_KEY;
if (!apiKey) throw new Error("ANALYTICS_API_KEY is not configured");
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-008"></a>
### SR-008: HTTP handler with no authentication check

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Missing Authentication |
| **CWE** | CWE-306 |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | line 4 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

This request handler never reads or verifies the caller's identity (no Authorization header, session or token verification found in the file).

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, line 4)

```typescript

Deno.serve(async (request: Request) => {
  if (request.method !== "GET") {
```

#### Potential Impact

This request handler never reads or verifies the caller's identity (no Authorization header, session or token verification found in the file).

#### Recommended Fix

Require and verify authentication at the start of the handler; reject unauthenticated requests with 401.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization");
if (!authHeader) return Response.json({ error: "Unauthorized" }, { status: 401 });
// verify the token with your auth provider and use the resulting user id
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-009"></a>
### SR-009: Privileged service-role / admin credential used in request handler

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Broken Access Control |
| **CWE** | CWE-250 |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | line 25 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

A privileged key bypasses database row-level security. Every query made with it must enforce authorization in code (verify caller identity and ownership) or it exposes all rows.

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, line 25)

```typescript
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );
```

#### Potential Impact

A privileged key bypasses database row-level security. Every query made with it must enforce authorization in code (verify caller identity and ownership) or it exposes all rows.

#### Recommended Fix

Do not use the privileged key for user requests. Create the client with the caller's JWT so row-level security applies, verify the user, and enforce ownership in the query.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization");
if (!authHeader) return Response.json({ error: "Unauthorized" }, { status: 401 });
const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
  global: { headers: { Authorization: authHeader } },
});
const { data: { user }, error } = await supabase.auth.getUser();
if (error || !user) return Response.json({ error: "Unauthorized" }, { status: 401 });
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-010"></a>
### SR-010: Record looked up by client-supplied identifier

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Insecure Direct Object Reference |
| **CWE** | CWE-639 |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | line 31 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

A record is fetched/modified by an ID from the request. Confirm the handler checks that the caller is allowed to access that specific record.

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, line 31)

```typescript
      .select("*")
      .eq("id", userId)
      .single();
```

#### Potential Impact

A record is fetched/modified by an ID from the request. Confirm the handler checks that the caller is allowed to access that specific record.

#### Recommended Fix

Derive the user from the verified session, and scope queries by owner (e.g. .eq("owner_id", user.id)) instead of trusting a client-supplied ID.

#### Secure Code Example

```typescript
.eq("id", taskId)
.eq("owner_id", user.id)
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-011"></a>
### SR-011: HTTP handler with no authentication check

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Missing Authentication |
| **CWE** | CWE-306 |
| **Affected file** | `supabase/functions/search-tasks/index.ts` |
| **Code location** | line 4 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

This request handler never reads or verifies the caller's identity (no Authorization header, session or token verification found in the file).

#### Vulnerable Code (`supabase/functions/search-tasks/index.ts`, line 4)

```typescript

Deno.serve(async (request: Request) => {
  if (request.method !== "GET") {
```

#### Potential Impact

This request handler never reads or verifies the caller's identity (no Authorization header, session or token verification found in the file).

#### Recommended Fix

Require and verify authentication at the start of the handler; reject unauthenticated requests with 401.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization");
if (!authHeader) return Response.json({ error: "Unauthorized" }, { status: 401 });
// verify the token with your auth provider and use the resulting user id
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-012"></a>
### SR-012: Permissive CORS policy

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Security Misconfiguration |
| **CWE** | CWE-942 |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | line 5 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

Any website can call this endpoint from a victim's browser. Endpoint accepts Authorization headers from any origin; risk depends on how auth is carried (bearer tokens vs cookies) and whether the endpoint is state-changing.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, line 5)

```typescript
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
```

#### Potential Impact

Any website can call this endpoint from a victim's browser. Endpoint accepts Authorization headers from any origin; risk depends on how auth is carried (bearer tokens vs cookies) and whether the endpoint is state-changing.

#### Recommended Fix

Allow only the application's own origins.

#### Secure Code Example

```typescript
const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);
const origin = request.headers.get("Origin") ?? "";
const corsHeaders = ALLOWED_ORIGINS.has(origin) ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {};
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-013"></a>
### SR-013: Privileged service-role / admin credential used in request handler

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Broken Access Control |
| **CWE** | CWE-250 |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | line 33 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

A privileged key bypasses database row-level security. Every query made with it must enforce authorization in code (verify caller identity and ownership) or it exposes all rows.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, line 33)

```typescript
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );
```

#### Potential Impact

A privileged key bypasses database row-level security. Every query made with it must enforce authorization in code (verify caller identity and ownership) or it exposes all rows.

#### Recommended Fix

Do not use the privileged key for user requests. Create the client with the caller's JWT so row-level security applies, verify the user, and enforce ownership in the query.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization");
if (!authHeader) return Response.json({ error: "Unauthorized" }, { status: 401 });
const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
  global: { headers: { Authorization: authHeader } },
});
const { data: { user }, error } = await supabase.auth.getUser();
if (error || !user) return Response.json({ error: "Unauthorized" }, { status: 401 });
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-014"></a>
### SR-014: Request body passed directly to a database write

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Mass Assignment |
| **CWE** | CWE-915 |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | line 38 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

Writing a client-supplied object directly lets callers set any column (owner, role, status...).

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, line 38)

```typescript
      .from("tasks")
      .update(changes)
      .eq("id", taskId)
```

#### Potential Impact

Writing a client-supplied object directly lets callers set any column (owner, role, status...).

#### Recommended Fix

Validate the request body and copy only an explicit allowlist of editable fields; never let clients set ownership, role or identifier columns.

#### Secure Code Example

```typescript
const ALLOWED = ["title", "description", "status"] as const;
const updates = Object.fromEntries(
  Object.entries(body.changes ?? {}).filter(([k]) => (ALLOWED as readonly string[]).includes(k)),
);
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-015"></a>
### SR-015: Record looked up by client-supplied identifier

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Insecure Direct Object Reference |
| **CWE** | CWE-639 |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | line 39 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

A record is fetched/modified by an ID from the request. Confirm the handler checks that the caller is allowed to access that specific record.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, line 39)

```typescript
      .update(changes)
      .eq("id", taskId)
      .select()
```

#### Potential Impact

A record is fetched/modified by an ID from the request. Confirm the handler checks that the caller is allowed to access that specific record.

#### Recommended Fix

Derive the user from the verified session, and scope queries by owner (e.g. .eq("owner_id", user.id)) instead of trusting a client-supplied ID.

#### Secure Code Example

```typescript
.eq("id", taskId)
.eq("owner_id", user.id)
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-016"></a>
### SR-016: All columns selected for an API response

| | |
|---|---|
| **Severity** | Low |
| **Category** | Sensitive Data Exposure |
| **CWE** | CWE-213 |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | line 30 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

Selecting every column may return sensitive fields to the caller; prefer an explicit allowlist.

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, line 30)

```typescript
      .from("profiles")
      .select("*")
      .eq("id", userId)
```

#### Potential Impact

Selecting every column may return sensitive fields to the caller; prefer an explicit allowlist.

#### Recommended Fix

Select only the columns the caller needs.

#### Secure Code Example

```typescript
.select("id, full_name, bio")
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-017"></a>
### SR-017: Internal error details returned to client

| | |
|---|---|
| **Severity** | Low |
| **Category** | Information Disclosure |
| **CWE** | CWE-209 |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | line 44 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

Raw exception text can reveal schema names, SQL, stack traces or infrastructure details.

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, line 44)

```typescript
    return Response.json(
      { error: String(error) },
      { status: 500 }
```

#### Potential Impact

Raw exception text can reveal schema names, SQL, stack traces or infrastructure details.

#### Recommended Fix

Log the detailed error server-side and return a generic message with a correlation id.

#### Secure Code Example

```typescript
const errorId = crypto.randomUUID();
console.error(errorId, error);
return Response.json({ error: "Internal error", errorId }, { status: 500 });
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-018"></a>
### SR-018: Internal error details returned to client

| | |
|---|---|
| **Severity** | Low |
| **Category** | Information Disclosure |
| **CWE** | CWE-209 |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | line 58 |
| **Status** | Needs validation |
| **Confidence** | Medium |
| **Detected by** | Static rule (unverified) |

#### Description

Raw exception text can reveal schema names, SQL, stack traces or infrastructure details.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, line 58)

```typescript
        error: "Unable to update task",
        details: String(error),
      },
```

#### Potential Impact

Raw exception text can reveal schema names, SQL, stack traces or infrastructure details.

#### Recommended Fix

Log the detailed error server-side and return a generic message with a correlation id.

#### Secure Code Example

```typescript
const errorId = crypto.randomUUID();
console.error(errorId, error);
return Response.json({ error: "Internal error", errorId }, { status: 500 });
```

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

<a id="sr-019"></a>
### SR-019: Debug / verbose mode enabled in configuration

| | |
|---|---|
| **Severity** | Low |
| **Category** | Security Misconfiguration |
| **CWE** | CWE-489 |
| **Affected file** | `src/lib/demoConfig.ts` |
| **Code location** | line 12 |
| **Status** | Needs validation |
| **Confidence** | Low |
| **Detected by** | Static rule (unverified) |

#### Description

Debug settings shipped to production can leak internals; ensure they are environment-driven.

#### Vulnerable Code (`src/lib/demoConfig.ts`, line 12)

```typescript

  debug: {
    enabled: true,
```

#### Potential Impact

Debug settings shipped to production can leak internals; ensure they are environment-driven.

#### Recommended Fix

Drive debug/logging settings from the environment and default them off in production builds.

#### Secure Code Example

```typescript
debug: { enabled: import.meta.env.DEV, logLevel: import.meta.env.DEV ? "verbose" : "warn" }
```

#### Other Affected Locations

- `src/lib/demoConfig.ts:14` - Debug / verbose mode enabled in configuration: logLevel: "verbose",

#### Validation Notes

Heuristic match (rules-only mode). Not verified by AI; confirm exploitability manually.

---

## 5. Remediation Summary

| Finding | Severity | File | Recommended Action |
|---|---|---|---|
| SR-001 | High | `src/components/TaskComments.tsx` | Render user content as text (React escapes it automatically). |
| SR-002 | High | `supabase/functions/search-tasks/index.ts` | Never build SQL by interpolating input. |
| SR-003 | High | `supabase/functions/update-task/index.ts` | Require and verify authentication at the start of the handler; reject unauthenticated requests with 401. |
| SR-004 | High | `supabase/migrations/002_access_policies.sql` | Scope the policy to the rows the caller should see (owner, team or project membership). |
| SR-005 | High | `supabase/migrations/002_access_policies.sql` | Restrict which columns users may update (column-level GRANTs or a trigger that rejects changes to privileged columns). |
| SR-006 | High | `supabase/migrations/002_access_policies.sql` | Reference the requesting user in the policy condition, e.g. |
| SR-007 | Medium | `src/lib/demoConfig.ts` | Move the value out of source code. |
| SR-008 | Medium | `supabase/functions/get-profile/index.ts` | Require and verify authentication at the start of the handler; reject unauthenticated requests with 401. |
| SR-009 | Medium | `supabase/functions/get-profile/index.ts` | Do not use the privileged key for user requests. |
| SR-010 | Medium | `supabase/functions/get-profile/index.ts` | Derive the user from the verified session, and scope queries by owner (e.g. |
| SR-011 | Medium | `supabase/functions/search-tasks/index.ts` | Require and verify authentication at the start of the handler; reject unauthenticated requests with 401. |
| SR-012 | Medium | `supabase/functions/update-task/index.ts` | Allow only the application's own origins. |
| SR-013 | Medium | `supabase/functions/update-task/index.ts` | Do not use the privileged key for user requests. |
| SR-014 | Medium | `supabase/functions/update-task/index.ts` | Validate the request body and copy only an explicit allowlist of editable fields; never let clients set ownership, role or identifier columns. |
| SR-015 | Medium | `supabase/functions/update-task/index.ts` | Derive the user from the verified session, and scope queries by owner (e.g. |
| SR-016 | Low | `supabase/functions/get-profile/index.ts` | Select only the columns the caller needs. |
| SR-017 | Low | `supabase/functions/get-profile/index.ts` | Log the detailed error server-side and return a generic message with a correlation id. |
| SR-018 | Low | `supabase/functions/update-task/index.ts` | Log the detailed error server-side and return a generic message with a correlation id. |
| SR-019 | Low | `src/lib/demoConfig.ts` | Drive debug/logging settings from the environment and default them off in production builds. |

## 6. Overall Assessment

**Overall risk rating: HIGH**

This report was produced by the deterministic rule engine only. Each item is a pattern that commonly indicates a vulnerability and must be reviewed by a developer to confirm exploitability.

## 7. Scope and Limitations

- Rules-only mode: findings are unverified heuristic matches. Run with AI enabled for verified findings and code-specific fixes.
- Static source-code review only: no code was executed, and no runtime or penetration testing was performed.
- Deployment configuration, infrastructure, and third-party services outside the scanned files were not assessed.
- Dependency versions were not checked against vulnerability databases (use npm audit / pip-audit alongside this tool).
- Findings marked 'needs validation' depend on runtime context and should be confirmed by a developer.
- No automated tool finds every vulnerability; absence of a finding is not proof of security.

## 8. Methodology

The deterministic rule engine ran 22 pattern matches over 18 files. No AI verification was performed.

## Appendix A: Files Reviewed

- `.oxlintrc.json` (json, 8 lines)
- `index.html` (html, 13 lines)
- `package.json` (json, 25 lines)
- `tsconfig.app.json` (json, 26 lines)
- `tsconfig.json` (json, 7 lines)
- `tsconfig.node.json` (json, 23 lines)
- `vite.config.ts` (typescript, 7 lines)
- `scripts/validate_project.py` (python, 118 lines)
- `src/App.tsx` (tsx, 321 lines)
- `src/main.tsx` (tsx, 10 lines)
- `src/types.ts` (typescript, 26 lines)
- `src/components/TaskComments.tsx` (tsx, 63 lines)
- `src/lib/demoConfig.ts` (typescript, 20 lines)
- `supabase/functions/get-profile/index.ts` (typescript, 48 lines)
- `supabase/functions/search-tasks/index.ts` (typescript, 44 lines)
- `supabase/functions/update-task/index.ts` (typescript, 66 lines)
- `supabase/migrations/001_initial_schema.sql` (sql, 57 lines)
- `supabase/migrations/002_access_policies.sql` (sql, 69 lines)


---
*Generated by SecReview AI v1.0.0. This is an automated, AI-assisted source-code assessment, not a complete penetration test. Validate findings and re-test after remediation.*
