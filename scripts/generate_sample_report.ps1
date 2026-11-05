# Windows PowerShell version. Requires: pip install -e .   and $env:GEMINI_API_KEY (free) or $env:ANTHROPIC_API_KEY set
Set-Location (Join-Path $PSScriptRoot "..")
secreview scan "https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app" `
  -o sample-report -n cdf-taskflow-security-report -f md,html,json,sarif @args
