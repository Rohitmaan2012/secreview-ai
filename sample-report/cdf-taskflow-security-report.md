# Security Assessment Report: vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app)

## 1. Assessment Information

| | |
|---|---|
| **Application** | vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app) |
| **Source** | `https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app` |
| **Assessment type** | AI-assisted static code review |
| **Assessment date** | 2026-11-05 21:48 UTC |
| **Tool** | SecReview AI v1.0.0 |
| **AI model** | gemini-3.6-flash |
| **Files / lines reviewed** | 18 files, 951 lines |
| **Overall risk rating** | **CRITICAL** |

## 2. Executive Summary

A static security review of the CDF TaskFlow codebase identified severe security vulnerabilities across Supabase Edge Functions, database Access Control Policies (RLS), and React frontend rendering. The overall security risk is CRITICAL. The primary concerns include unauthenticated database mutation and raw SQL injection in Edge Functions, allowing attackers to manipulate or exfiltrate database records without authentication. Additionally, missing authorization checks in Row-Level Security policies allow authenticated users to view all project tasks and escalate their privileges to administrator. Immediate remediation must focus on securing Edge Function endpoints with proper authentication, parameterizing SQL queries, and scoping database UPDATE permissions.

> AI-assisted findings were grounded against the source code and reviewed in a second, independent AI pass. Items marked *Needs validation* depend on runtime context and should be confirmed before being treated as exploitable.

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 3 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |
| **Total** | **7** |

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| [SR-001](#sr-001) | Critical | SQL Injection in Task Search Edge Function | `supabase/functions/search-tasks/index.ts:20` | Confirmed |
| [SR-002](#sr-002) | Critical | Unauthenticated Task Update with Mass Assignment and Privilege Bypass | `supabase/functions/update-task/index.ts:26` | Confirmed |
| [SR-003](#sr-003) | High | Cross-Site Scripting (XSS) via Unsanitized Comment Rendering | `src/components/TaskComments.tsx:39` | Confirmed |
| [SR-004](#sr-004) | High | Unauthenticated User Profile Lookup via Privileged Service Role Key | `supabase/functions/get-profile/index.ts:23` | Confirmed |
| [SR-005](#sr-005) | High | Privilege Escalation via Unrestricted Column Updates on Profiles RLS Policy | `supabase/migrations/002_access_policies.sql:15` | Confirmed |
| [SR-006](#sr-006) | Medium | Overly Permissive Read Access Policy for Tasks | `supabase/migrations/002_access_policies.sql:34` | Confirmed |
| [SR-007](#sr-007) | Low | Hardcoded Key Pattern Shipped in Client Application Configuration | `src/lib/demoConfig.ts:7` | Confirmed |

**By category:** Broken Access Control (3), SQL Injection (1), Cross-Site Scripting (1), Privilege Escalation (1), Hardcoded Secrets (1)

## 4. Detailed Findings

<a id="sr-001"></a>
### SR-001: SQL Injection in Task Search Edge Function

| | |
|---|---|
| **Severity** | Critical |
| **Category** | SQL Injection |
| **CWE** | CWE-89 |
| **OWASP** | A03:2021 Injection |
| **Affected file** | `supabase/functions/search-tasks/index.ts` |
| **Code location** | lines 20-28 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The search-tasks function constructs a SQL query using string interpolation with the untrusted query parameter 'q' and executes it via sql.unsafe().

#### Vulnerable Code (`supabase/functions/search-tasks/index.ts`, lines 20-28)

```typescript
    const query = `
      SELECT id, title, description, status
      FROM public.tasks
      WHERE title ILIKE '%${searchTerm}%'
      ORDER BY created_at DESC
      LIMIT 25
    `;

    const tasks = await sql.unsafe(query);
```

#### Potential Impact

An attacker can inject arbitrary SQL statements, allowing them to bypass access controls, extract sensitive data from all database tables, modify database contents, or execute administrative commands.

#### Example Attack Scenario

An attacker submits a GET request to /search-tasks?q=test%27%20UNION%20SELECT%20id%2C%20full_name%2C%20role%2C%20bio%20FROM%20public.profiles%20-- to leak user profile details.

#### Recommended Fix

Use tagged template literals provided by postgres.js to parameterize SQL queries safely instead of building SQL via string template interpolation and sql.unsafe().

#### Secure Code Example

```typescript
    const tasks = await sql`
      SELECT id, title, description, status
      FROM public.tasks
      WHERE title ILIKE ${'%' + searchTerm + '%'}
      ORDER BY created_at DESC
      LIMIT 25
    `;
```

#### Validation Notes

Accurately identifies a critical SQL injection vulnerability in the search-tasks Edge Function where untrusted query parameters are interpolated directly into a SQL string executed via postgres.unsafe().

---

<a id="sr-002"></a>
### SR-002: Unauthenticated Task Update with Mass Assignment and Privilege Bypass

| | |
|---|---|
| **Severity** | Critical |
| **Category** | Broken Access Control |
| **CWE** | CWE-284 |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | lines 26-41 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The update-task function accepts arbitrary JSON updates and applies them using the Supabase Service Role Key without authenticating the requester or verifying task ownership.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, lines 26-41)

```typescript
    const body = await request.json();

    const taskId = body.taskId;
    const changes = body.changes;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { data, error } = await supabase
      .from("tasks")
      .update(changes)
      .eq("id", taskId)
      .select()
      .single();
```

#### Potential Impact

Unauthenticated users can update any task in the system and modify privileged attributes such as task owner_id or project_id through mass assignment.

#### Example Attack Scenario

An unauthenticated attacker sends a POST request with body {"taskId": "<target-uuid>", "changes": {"owner_id": "<attacker-uuid>", "title": "Hacked"}} to reassign ownership of any task.

#### Recommended Fix

Pass the client's JWT Authorization header to createClient or create a Supabase client scoped to the user's token. Validate input fields against an allowlist before performing updates.

#### Secure Code Example

```typescript
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      return Response.json({ error: "Missing authorization header" }, { status: 401 });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: authHeader } } }
    );

    const allowedChanges: Record<string, unknown> = {};
    if (typeof changes.title === "string") allowedChanges.title = changes.title;
    if (typeof changes.description === "string") allowedChanges.description = changes.description;
    if (typeof changes.status === "string") allowedChanges.status = changes.status;

    const { data, error } = await supabase
      .from("tasks")
      .update(allowedChanges)
      .eq("id", taskId)
      .select()
      .single();
```

#### Validation Notes

Accurately identifies an unauthenticated Edge Function endpoint using the privileged Supabase Service Role Key to apply un-sanitized mass assignment updates on any task record.

---

<a id="sr-003"></a>
### SR-003: Cross-Site Scripting (XSS) via Unsanitized Comment Rendering

| | |
|---|---|
| **Severity** | High |
| **Category** | Cross-Site Scripting |
| **CWE** | CWE-79 |
| **OWASP** | A03:2021 Injection |
| **Affected file** | `src/components/TaskComments.tsx` |
| **Code location** | lines 39-43 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

Task comment text is rendered directly into the DOM using React's dangerouslySetInnerHTML attribute without HTML sanitization.

#### Vulnerable Code (`src/components/TaskComments.tsx`, lines 39-43)

```tsx
              <div
                dangerouslySetInnerHTML={{
                  __html: comment.text,
                }}
              />
```

#### Potential Impact

If an attacker inserts HTML or JavaScript payload into a comment, it executes in the browsers of users viewing the task details, potentially stealing session details or performing unauthorized actions.

#### Example Attack Scenario

An attacker submits a comment containing <img src=x onerror=alert(document.cookie)>. When another user views the task comments, the script executes.

#### Recommended Fix

Render user-supplied text directly inside React elements instead of dangerouslySetInnerHTML, or sanitize HTML with a library like DOMPurify.

#### Secure Code Example

```tsx
              <div>{comment.text}</div>
```

#### Validation Notes

Accurately identifies stored XSS in TaskComments.tsx caused by passing raw comment content to dangerouslySetInnerHTML.

---

<a id="sr-004"></a>
### SR-004: Unauthenticated User Profile Lookup via Privileged Service Role Key

| | |
|---|---|
| **Severity** | High |
| **Category** | Broken Access Control |
| **CWE** | CWE-639 |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | lines 23-32 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The get-profile Edge Function uses the service role key to query profiles based on a user-supplied 'userId' query parameter without verifying caller authentication.

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, lines 23-32)

```typescript
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", userId)
      .single();
```

#### Potential Impact

Any remote caller can query arbitrary user profile details by manipulating the userId parameter.

#### Example Attack Scenario

An attacker queries GET /get-profile?userId=<target-user-uuid> to fetch full profile details for any user.

#### Recommended Fix

Authenticate callers using their JWT token and enforce authorization checks or rely on user-scoped Supabase client calls.

#### Secure Code Example

```typescript
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: authHeader } } }
    );

    const { data, error } = await supabase
      .from("profiles")
      .select("id, full_name, bio, role")
      .eq("id", userId)
      .single();
```

#### Validation Notes

Accurately identifies an unauthenticated user profile retrieval function using the service role key, bypassing RLS and allowing unrestricted IDOR access to profile data.

---

<a id="sr-005"></a>
### SR-005: Privilege Escalation via Unrestricted Column Updates on Profiles RLS Policy

| | |
|---|---|
| **Severity** | High |
| **Category** | Privilege Escalation |
| **CWE** | CWE-269 |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected file** | `supabase/migrations/002_access_policies.sql` |
| **Code location** | lines 15-20 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The RLS UPDATE policy on public.profiles allows authenticated users to update their row but does not restrict which columns can be updated. PostgreSQL row-level security policies control row access, not column permissions.

#### Vulnerable Code (`supabase/migrations/002_access_policies.sql`, lines 15-20)

```sql
CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());
```

#### Potential Impact

A user with 'member' role can send an UPDATE query targeting their profile row setting role = 'admin' to escalate their privileges.

#### Example Attack Scenario

A member executes supabase.from('profiles').update({ role: 'admin' }).eq('id', myUserId) to self-promote to administrator.

#### Recommended Fix

Restrict update permissions on sensitive columns using column-level GRANT statements or trigger/CHECK logic in RLS policies.

#### Secure Code Example

```sql
REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (full_name, bio) ON public.profiles TO authenticated;

CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());
```

#### Validation Notes

Accurately identifies privilege escalation vulnerability where an RLS UPDATE policy on public.profiles allows users to update any column in their row, including 'role'.

---

<a id="sr-006"></a>
### SR-006: Overly Permissive Read Access Policy for Tasks

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Broken Access Control |
| **CWE** | CWE-284 |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected file** | `supabase/migrations/002_access_policies.sql` |
| **Code location** | lines 34-38 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The RLS policy 'Users can view tasks' uses USING (true), allowing any authenticated user to select all tasks across all projects regardless of project membership.

#### Vulnerable Code (`supabase/migrations/002_access_policies.sql`, lines 34-38)

```sql
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (true);
```

#### Potential Impact

Users can view private tasks belonging to projects created by other users.

#### Example Attack Scenario

An authenticated user queries the tasks table directly and views confidential tasks created by other users.

#### Recommended Fix

Restrict task select access to project owners or project collaborators.

#### Secure Code Example

```sql
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.projects
    WHERE projects.id = tasks.project_id
    AND projects.owner_id = auth.uid()
  )
);
```

#### Validation Notes

Accurately identifies an overly broad RLS SELECT policy on public.tasks (USING (true)) that exposes tasks across all projects to any authenticated user.

---

<a id="sr-007"></a>
### SR-007: Hardcoded Key Pattern Shipped in Client Application Configuration

| | |
|---|---|
| **Severity** | Low |
| **Category** | Hardcoded Secrets |
| **CWE** | CWE-798 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **Affected file** | `src/lib/demoConfig.ts` |
| **Code location** | lines 7-10 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

An API key string literal is embedded in the frontend source configuration. Note that the value appears to be a placeholder/demo key, but storing static credentials in client code is an insecure design pattern.

#### Vulnerable Code (`src/lib/demoConfig.ts`, lines 7-10)

```typescript
  analytics: {
    enabled: true,
    apiKey: "cdf_demo_private_key_NOT_REAL_12345",
  },
```

#### Potential Impact

Hardcoded credentials in frontend bundles are exposed to all site visitors and can be extracted easily.

#### Example Attack Scenario

An attacker inspects the bundled JavaScript file and extracts the hardcoded API key.

#### Recommended Fix

Inject client-side configuration parameters via environment variables (e.g., import.meta.env) at build time.

#### Secure Code Example

```typescript
  analytics: {
    enabled: true,
    apiKey: import.meta.env.VITE_ANALYTICS_API_KEY ?? "",
  },
```

#### Validation Notes

Accurately identifies embedding client-side configuration secret key patterns into frontend source code.

---

## 5. Remediation Summary

| Finding | Severity | File | Recommended Action |
|---|---|---|---|
| SR-001 | Critical | `supabase/functions/search-tasks/index.ts` | Use tagged template literals provided by postgres.js to parameterize SQL queries safely instead of building SQL via string template interpolation and sql.unsafe(). |
| SR-002 | Critical | `supabase/functions/update-task/index.ts` | Pass the client's JWT Authorization header to createClient or create a Supabase client scoped to the user's token. |
| SR-003 | High | `src/components/TaskComments.tsx` | Render user-supplied text directly inside React elements instead of dangerouslySetInnerHTML, or sanitize HTML with a library like DOMPurify. |
| SR-004 | High | `supabase/functions/get-profile/index.ts` | Authenticate callers using their JWT token and enforce authorization checks or rely on user-scoped Supabase client calls. |
| SR-005 | High | `supabase/migrations/002_access_policies.sql` | Restrict update permissions on sensitive columns using column-level GRANT statements or trigger/CHECK logic in RLS policies. |
| SR-006 | Medium | `supabase/migrations/002_access_policies.sql` | Restrict task select access to project owners or project collaborators. |
| SR-007 | Low | `src/lib/demoConfig.ts` | Inject client-side configuration parameters via environment variables (e.g., import.meta.env) at build time. |

## 6. Overall Assessment

**Overall risk rating: CRITICAL**

The application suffers from critical architectural authorization bypasses between the backend Edge Functions and the database layer. Specifically, Edge Functions utilize the Supabase SUPABASE_SERVICE_ROLE_KEY to perform queries, completely bypassing PostgreSQL Row Level Security without implementing compensating authentication or access checks in application logic. This pattern allows unauthenticated clients to read profile data, execute raw SQL injections, and modify arbitrary tasks via mass assignment. Simultaneously, the database RLS policies defined in SQL migrations lack column-level restrictions on sensitive profile attributes like 'role', allowing any authenticated user to elevate their role from 'member' to 'admin'. In the client tier, rendering user-controlled comment text via React's dangerouslySetInnerHTML introduces Stored Cross-Site Scripting (XSS), completing an attack path where XSS can be leveraged alongside insecure API functions.

### Prioritized Remediation Plan

1. Remove direct usage of SUPABASE_SERVICE_ROLE_KEY in Edge Functions (update-task, get-profile) and replace with user-context Supabase clients that enforce JWT authentication.
2. Fix SQL injection in search-tasks by replacing raw string template interpolation and sql.unsafe() with postgres.js parameterized query tagged templates.
3. Implement column-level permissions (REVOKE/GRANT) on public.profiles to prevent standard users from updating their own 'role' column.
4. Restrict task SELECT RLS policy to only return tasks belonging to projects owned or accessible by auth.uid().
5. Replace dangerouslySetInnerHTML in TaskComments.tsx with standard React child element rendering to prevent Stored XSS.

### Positive Observations

- Row Level Security (RLS) is enabled across all public database tables in the initial schema migration.
- Project creation and comment insertion policies correctly verify that author_id and owner_id match the authenticated user's auth.uid().

## 7. Scope and Limitations

- Static source-code review only: no code was executed, and no runtime or penetration testing was performed.
- Deployment configuration, infrastructure, and third-party services outside the scanned files were not assessed.
- Dependency versions were not checked against vulnerability databases (use npm audit / pip-audit alongside this tool).
- Findings marked 'needs validation' depend on runtime context and should be confirmed by a developer.
- No automated tool finds every vulnerability; absence of a finding is not proof of security.

## 8. Methodology

1. **Ingestion**: supported source files were collected (dependencies, build output and lock files excluded) and treated strictly as untrusted data.
2. **Static rule engine**: 22 heuristic leads were raised by language-aware rules (secrets, injection sinks, XSS sinks, auth checks, CORS, RLS policies, etc.).
3. **AI detection pass**: the full codebase (with line numbers) and the leads were analyzed by gemini-3.6-flash in 1 context batch(es), reasoning across files about data flow, authentication and database policies. The model confirmed or dismissed each lead and looked for issues the rules cannot express.
4. **Evidence grounding**: every finding's quoted code was matched against the real source to correct line numbers; 0 unsupported finding(s) were discarded.
5. **AI review pass**: an independent second pass re-checked each finding for false positives, duplicates, severity and fix correctness (0 dropped), and wrote the summary and overall assessment.
6. **Result**: 20 of 22 leads were confirmed and 2 dismissed as false positives. API usage: 2 requests, 34,092 input tokens (0 from prompt cache), 4,961 output tokens.

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

## Appendix B: Static Leads Dismissed by AI (false-positive filtering)

| Lead | Rule | Location | Reason dismissed |
|---|---|---|---|
| S003 | DEBUG-ENABLED | `src/lib/demoConfig.ts:12` | Debug configuration flag in demoConfig.ts is non-sensitive metadata for demo mode. |
| S004 | DEBUG-ENABLED | `src/lib/demoConfig.ts:14` | Verbose log level configuration in demoConfig.ts is non-sensitive client configuration. |
| S003 | DEBUG-ENABLED | `src/lib/demoConfig.ts:12` | Debug mode configuration flag in demoConfig.ts is non-sensitive in frontend client context. |
| S004 | DEBUG-ENABLED | `src/lib/demoConfig.ts:14` | Verbose logging level setting in demoConfig.ts does not leak sensitive server secrets or credentials. |


---
*Generated by SecReview AI v1.0.0. This is an automated, AI-assisted source-code assessment, not a complete penetration test. Validate findings and re-test after remediation.*
