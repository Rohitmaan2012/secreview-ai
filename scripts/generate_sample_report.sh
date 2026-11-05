#!/usr/bin/env bash
# Generates the hackathon sample report by scanning CDF TaskFlow straight from GitHub.
# Requires: pip install -e .   and ANTHROPIC_API_KEY or GEMINI_API_KEY (free) set
set -euo pipefail
cd "$(dirname "$0")/.."
secreview scan "https://github.com/samartha-2601/CDF-CyberSec-Hackathon/tree/main/vulnerable-app" \
  -o sample-report -n cdf-taskflow-security-report -f md,html,json,sarif "$@"
