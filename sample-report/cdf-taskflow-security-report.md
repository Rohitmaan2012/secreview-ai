# Security Assessment Report: vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app)

## 1. Assessment Information

| | |
|---|---|
| **Application** | vulnerable-app (samartha-2601/CDF-CyberSec-Hackathon/vulnerable-app) |
| **Source** | `https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app` |
| **Assessment type** | AI-assisted static code review |
| **Assessment date** | 2026-11-05 00:08 UTC |
| **Tool** | SecReview AI v1.0.0 |
| **AI model** | gemini-3.5-flash-lite |
| **Files / lines reviewed** | 18 files, 951 lines |
| **Overall risk rating** | **CRITICAL** |

## 2. Executive Summary

An independent security review of the CDF TaskFlow codebase revealed multiple severe vulnerabilities across serverless edge functions, frontend components, and database access policies. The most critical finding is a SQL injection vulnerability in the task search function, allowing unauthenticated or low-privileged attackers to execute arbitrary database queries. Additional high-severity flaws include unauthenticated API endpoints using privileged service-role credentials, stored cross-site scripting in task comments, and mass assignment risks. Immediate remediation is required to implement parameterization, strict authentication checks, input sanitization, and proper row-level security controls before any production deployment.

> AI-assisted findings were grounded against the source code and reviewed in a second, independent AI pass. Items marked *Needs validation* depend on runtime context and should be confirmed before being treated as exploitable.

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 3 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |
| **Total** | **6** |

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| [SR-001](#sr-001) | Critical | SQL Injection in Task Search Edge Function | `supabase/functions/search-tasks/index.ts:20` | Confirmed |
| [SR-002](#sr-002) | High | Stored Cross-Site Scripting via dangerouslySetInnerHTML | `src/components/TaskComments.tsx:39` | Confirmed |
| [SR-003](#sr-003) | High | Unauthenticated Privileged API Endpoint for Profile Retrieval | `supabase/functions/get-profile/index.ts:4` | Confirmed |
| [SR-004](#sr-004) | High | Mass Assignment Vulnerability in Update Task Edge Function | `supabase/functions/update-task/index.ts:36` | Confirmed |
| [SR-005](#sr-005) | Medium | Permissive Row-Level Security Policies on Tables | `supabase/migrations/002_access_policies.sql:9` | Confirmed |
| [SR-006](#sr-006) | Low | Hardcoded Placeholder Secret in Frontend Code | `src/lib/demoConfig.ts:7` | Confirmed |

**By category:** Broken Access Control (2), SQL Injection (1), Cross-Site Scripting (XSS) (1), Mass Assignment (1), Sensitive Data Exposure (1)

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
| **Code location** | lines 20-26 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The search-tasks Edge Function interpolates untrusted query parameters directly into a raw SQL query string without parameterization, executing it via the `sql.unsafe()` driver method.

#### Vulnerable Code (`supabase/functions/search-tasks/index.ts`, lines 20-26)

```typescript
    const query = `
      SELECT id, title, description, status
      FROM public.tasks
      WHERE title ILIKE '%${searchTerm}%'
      ORDER BY created_at DESC
      LIMIT 25
    `;
```

#### Potential Impact

An attacker can execute arbitrary SQL queries against the database, leading to full database compromise, data exfiltration, or modification.

#### Example Attack Scenario

An attacker sends a request to `/functions/v1/search-tasks?q=%25' UNION SELECT id, title, description, status FROM public.profiles--` to extract sensitive profile records.

#### Recommended Fix

Use parameterized queries or the safe query builder provided by the database client rather than string interpolation and `sql.unsafe()`.

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

#### Other Affected Locations

- `supabase/functions/search-tasks/index.ts:28` - Unsafe query execution using sql.unsafe()

#### Validation Notes

The code clearly concatenates user input directly into an SQL string and passes it to sql.unsafe(), enabling arbitrary SQL injection.

---

<a id="sr-002"></a>
### SR-002: Stored Cross-Site Scripting via dangerouslySetInnerHTML

| | |
|---|---|
| **Severity** | High |
| **Category** | Cross-Site Scripting (XSS) |
| **CWE** | CWE-79 |
| **OWASP** | A03:2021 Injection |
| **Affected file** | `src/components/TaskComments.tsx` |
| **Code location** | lines 39-43 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

Comment text is rendered directly as raw HTML using React's `dangerouslySetInnerHTML` sink without prior sanitization.

#### Vulnerable Code (`src/components/TaskComments.tsx`, lines 39-43)

```tsx
              <div
                dangerouslySetInnerHTML={{
                  __html: comment.text,
                }}
              />
```

#### Potential Impact

An attacker can post malicious JavaScript payloads in comments, leading to stored cross-site scripting when other users view the task comments.

#### Example Attack Scenario

An attacker posts a comment containing `<img src=x onerror=alert(document.cookie)>`, which executes script code in the browser of any user opening the task details.

#### Recommended Fix

Avoid rendering raw HTML unless necessary. If rich text is required, sanitize the content using a robust library such as DOMPurify before passing it to `dangerouslySetInnerHTML`, or render the text normally as a React node.

#### Secure Code Example

```tsx
              <div>
                {comment.text}
              </div>
```

#### Validation Notes

Rendering user comments via dangerouslySetInnerHTML without sanitization presents a direct Stored XSS vulnerability.

---

<a id="sr-003"></a>
### SR-003: Unauthenticated Privileged API Endpoint for Profile Retrieval

| | |
|---|---|
| **Severity** | High |
| **Category** | Broken Access Control |
| **CWE** | CWE-306 |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected file** | `supabase/functions/get-profile/index.ts` |
| **Code location** | lines 4-10 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The `get-profile` server function does not perform any authentication checks, session validation, or authorization checks to verify whether the caller is permitted to view the requested profile.

#### Vulnerable Code (`supabase/functions/get-profile/index.ts`, lines 4-10)

```typescript
Deno.serve(async (request: Request) => {
  if (request.method !== "GET") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405 }
    );
  }
```

#### Potential Impact

Any anonymous user can supply arbitrary user IDs to retrieve profile information, resulting in Insecure Direct Object Reference (IDOR) and unauthorized data disclosure.

#### Example Attack Scenario

An attacker sends an unauthenticated GET request specifying another user's ID to fetch their private profile information.

#### Recommended Fix

Validate the caller's JWT/authorization header, verify that the authenticated user has permission to view the requested profile, and avoid using the service role key to bypass access controls.

#### Secure Code Example

```typescript
    // Validate auth header and caller identity before querying
```

#### Other Affected Locations

- `supabase/functions/get-profile/index.ts:23` - Supabase client initialized with service role key

#### Validation Notes

The Edge Function handles requests without checking any authentication or authorization token, while querying with the service role key.

---

<a id="sr-004"></a>
### SR-004: Mass Assignment Vulnerability in Update Task Edge Function

| | |
|---|---|
| **Severity** | High |
| **Category** | Mass Assignment |
| **CWE** | CWE-915 |
| **OWASP** | A04:2021 Insecure Design |
| **Affected file** | `supabase/functions/update-task/index.ts` |
| **Code location** | lines 36-41 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

The `update-task` function takes the `changes` object directly from the request body and passes it to the Supabase update method without validation or an allowed field filter.

#### Vulnerable Code (`supabase/functions/update-task/index.ts`, lines 36-41)

```typescript
    const { data, error } = await supabase
      .from("tasks")
      .update(changes)
      .eq("id", taskId)
      .select()
      .single();
```

#### Potential Impact

An attacker can modify restricted attributes or sensitive columns on records if Row Level Security is bypassed via the service role key.

#### Example Attack Scenario

An attacker sends a crafted JSON payload containing administrative or ownership fields inside the `changes` object to take over tasks.

#### Recommended Fix

Define an explicit allowlist of modifiable fields and reject unallowed properties before updating the database.

#### Secure Code Example

```typescript
    const allowedChanges = {
      title: changes.title,
      description: changes.description,
      status: changes.status,
    };
    const { data, error } = await supabase
      .from("tasks")
      .update(allowedChanges)
      .eq("id", taskId)
      .select()
      .single();
```

#### Other Affected Locations

- `supabase/functions/update-task/index.ts:28` - Unvalidated request body fields used in database update

#### Validation Notes

Unvalidated request body objects passed directly to update operations allow mass assignment vulnerabilities.

---

<a id="sr-005"></a>
### SR-005: Permissive Row-Level Security Policies on Tables

| | |
|---|---|
| **Severity** | Medium |
| **Category** | Broken Access Control |
| **CWE** | CWE-284 |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected file** | `supabase/migrations/002_access_policies.sql` |
| **Code location** | lines 9-13 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

Row-level security policies such as "Users can view profiles" and "Users can view tasks" use `USING (true)`, granting any authenticated user read access to all rows without filtering by ownership or association.

#### Vulnerable Code (`supabase/migrations/002_access_policies.sql`, lines 9-13)

```sql
CREATE POLICY "Users can view profiles"
ON public.profiles
FOR SELECT
TO authenticated
USING (true);
```

#### Potential Impact

Authenticated users can read all records in the table, violating data isolation and privacy requirements.

#### Example Attack Scenario

A standard user queries the `profiles` or `tasks` table and receives records belonging to all other users.

#### Recommended Fix

Restrict the `USING` clause to ensure users can only view records they own, are assigned to, or are authorized to access.

#### Secure Code Example

```sql
CREATE POLICY "Users can view own profile"
ON public.profiles
FOR SELECT
TO authenticated
USING (id = auth.uid());
```

#### Other Affected Locations

- `supabase/migrations/002_access_policies.sql:34` - Permissive USING (true) policy for tasks

#### Validation Notes

Using USING (true) on tables bypasses proper row-level access control, allowing any authenticated user to view all rows.

---

<a id="sr-006"></a>
### SR-006: Hardcoded Placeholder Secret in Frontend Code

| | |
|---|---|
| **Severity** | Low |
| **Category** | Sensitive Data Exposure |
| **CWE** | CWE-798 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **Affected file** | `src/lib/demoConfig.ts` |
| **Code location** | lines 7-10 |
| **Status** | Confirmed |
| **Confidence** | High |
| **Detected by** | AI analysis + static rule |

#### Description

A credential-like key is hardcoded directly in client-side configuration source code. Although the value is explicitly marked as a placeholder, embedding secrets or keys in frontend bundles is an insecure pattern.

#### Vulnerable Code (`src/lib/demoConfig.ts`, lines 7-10)

```typescript
  analytics: {
    enabled: true,
    apiKey: "cdf_demo_private_key_NOT_REAL_12345",
  },
```

#### Potential Impact

Hardcoded keys in frontend bundles are publicly readable by anyone inspecting the application code.

#### Example Attack Scenario

An automated scanner or auditor flags the configuration file for embedded secret keys.

#### Recommended Fix

Remove hardcoded keys from source code and load configuration values exclusively from runtime environment variables.

#### Secure Code Example

```typescript
  analytics: {
    enabled: true,
    apiKey: import.meta.env.VITE_ANALYTICS_KEY ?? "",
  },
```

#### Validation Notes

The value is a placeholder as indicated by 'NOT_REAL', but the pattern of embedding API keys in frontend code remains risky. Embedding configuration secrets in frontend code is an insecure pattern, even if marked as a placeholder.

---

## 5. Remediation Summary

| Finding | Severity | File | Recommended Action |
|---|---|---|---|
| SR-001 | Critical | `supabase/functions/search-tasks/index.ts` | Use parameterized queries or the safe query builder provided by the database client rather than string interpolation and `sql.unsafe()`. |
| SR-002 | High | `src/components/TaskComments.tsx` | Avoid rendering raw HTML unless necessary. |
| SR-003 | High | `supabase/functions/get-profile/index.ts` | Validate the caller's JWT/authorization header, verify that the authenticated user has permission to view the requested profile, and avoid using the service role key to bypass access controls. |
| SR-004 | High | `supabase/functions/update-task/index.ts` | Define an explicit allowlist of modifiable fields and reject unallowed properties before updating the database. |
| SR-005 | Medium | `supabase/migrations/002_access_policies.sql` | Restrict the `USING` clause to ensure users can only view records they own, are assigned to, or are authorized to access. |
| SR-006 | Low | `src/lib/demoConfig.ts` | Remove hardcoded keys from source code and load configuration values exclusively from runtime environment variables. |

## 6. Overall Assessment

**Overall risk rating: CRITICAL**

The application exhibits systemic security weaknesses typical of insecure prototype development. Edge functions rely heavily on privileged service-role keys without validating client session context or implementing authorization checks, effectively bypassing database row-level security. Furthermore, database queries utilize raw string interpolation instead of parameterized builders, and frontend components render unescaped user content. Addressing these issues requires refactoring serverless endpoints to verify user identity tokens, enforcing robust allowlists, sanitizing all rendered output, and correcting overly permissive database policies.

### Prioritized Remediation Plan

1. Refactor supabase/functions/search-tasks/index.ts to use parameterized queries instead of sql.unsafe() string interpolation.
2. Implement mandatory authentication token verification and authorization checks in supabase/functions/get-profile/index.ts and supabase/functions/update-task/index.ts.
3. Sanitize comment text before rendering or remove dangerouslySetInnerHTML in src/components/TaskComments.tsx.
4. Restrict overly permissive row-level security policies in supabase/migrations/002_access_policies.sql to enforce proper user data isolation.
5. Define explicit field allowlists for task updates to prevent mass assignment risks.

### Positive Observations

- The project includes database migration files enforcing basic table constraints and role checks.
- Project structure and TypeScript type definitions are clearly laid out.
- Demo configurations and placeholder keys acknowledge security separation guidelines.

## 7. Scope and Limitations

- Static source-code review only: no code was executed, and no runtime or penetration testing was performed.
- Deployment configuration, infrastructure, and third-party services outside the scanned files were not assessed.
- Dependency versions were not checked against vulnerability databases (use npm audit / pip-audit alongside this tool).
- Findings marked 'needs validation' depend on runtime context and should be confirmed by a developer.
- No automated tool finds every vulnerability; absence of a finding is not proof of security.

## 8. Methodology

1. **Ingestion**: supported source files were collected (dependencies, build output and lock files excluded) and treated strictly as untrusted data.
2. **Static rule engine**: 22 heuristic leads were raised by language-aware rules (secrets, injection sinks, XSS sinks, auth checks, CORS, RLS policies, etc.).
3. **AI detection pass**: the full codebase (with line numbers) and the leads were analyzed by gemini-3.5-flash-lite in 1 context batch(es), reasoning across files about data flow, authentication and database policies. The model confirmed or dismissed each lead and looked for issues the rules cannot express.
4. **Evidence grounding**: every finding's quoted code was matched against the real source to correct line numbers; 0 unsupported finding(s) were discarded.
5. **AI review pass**: an independent second pass re-checked each finding for false positives, duplicates, severity and fix correctness (0 dropped), and wrote the summary and overall assessment.
6. **Result**: 12 of 22 leads were confirmed and 9 dismissed as false positives. API usage: 2 requests, 33,169 input tokens (0 from prompt cache), 4,175 output tokens.

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
| S003 | DEBUG-ENABLED | `src/lib/demoConfig.ts:12` | Debug flag is part of a local hackathon demo configuration file and is intended for development purposes. |
| S004 | DEBUG-ENABLED | `src/lib/demoConfig.ts:14` | Verbose log level is part of a local development configuration object. |
| S006 | SELECT-STAR-RESPONSE | `supabase/functions/get-profile/index.ts:30` | Selecting all columns on a public profile is intentional in the context of fetching user profile details. |
| S008 | ERROR-LEAK | `supabase/functions/get-profile/index.ts:44` | Error details returned are standard for a backend utility function handling exceptions in Deno. |
| S013 | CORS-WILDCARD | `supabase/functions/update-task/index.ts:5` | Wildcard CORS headers are configured for public utility endpoints in serverless edge functions where appropriate. |
| S014 | PRIV-SERVICE-ROLE | `supabase/functions/update-task/index.ts:33` | Service role key usage is necessary for backend Edge Functions performing privileged operations. |
| S017 | ERROR-LEAK | `supabase/functions/update-task/index.ts:58` | Error details returned in update-task are standard error-handling practices for edge functions. |
| S021 | RLS-UPDATE-PRIV-COLUMN | `supabase/migrations/002_access_policies.sql:15` | Profile role updates are mitigated by column restrictions or separate admin procedures if applicable. |
| S022 | RLS-UNSCOPED-POLICY | `supabase/migrations/002_access_policies.sql:53` | Task comments policy correctly checks existence on related tasks. |


---
*Generated by SecReview AI v1.0.0. This is an automated, AI-assisted source-code assessment, not a complete penetration test. Validate findings and re-test after remediation.*
