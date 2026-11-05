# Demo video script (3–5 minutes)

1. **Intro (30s)**: "SecReview AI finds vulnerabilities, suggests secure fixes and writes a full
   security report. It combines a generic static rule engine with two Claude passes: detection, then
   an independent review that removes false positives and duplicates."
2. **Start it (30s)**: show `pip install -e .`, `export GEMINI_API_KEY=...` (or ANTHROPIC_API_KEY), `secreview --help`.
3. **Analyze a codebase (60s)**: run
   `secreview scan https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app -o reports`
   and narrate the progress lines (files loaded → leads → AI detection → grounding → AI review).
   Optionally show `secreview web`, paste the same URL, and watch the job page.
4. **Detected vulnerabilities (60s)**: in the terminal summary, then the HTML report: severity
   cards, findings table, filter to High/Critical, open a finding to show file + line, quoted
   evidence, impact, attack scenario, confirmed vs needs-validation.
5. **Secure fixes (45s)**: scroll to "Secure code" for the SQL injection and the RLS policy
   findings; point out that fixes use the project's own libraries.
6. **Report (30s)**: executive summary, overall assessment, prioritized plan, limitations,
   Appendix B (leads the AI dismissed as false positives). Show the Markdown/JSON/SARIF files and
   print-to-PDF.
7. **Generalization (15s)**: `secreview scan tests/fixtures/unseen-app`: works on other stacks too.
