#!/usr/bin/env bash
# Classify synthetic Claude Code hook payloads, verify their decision receipt,
# and reject a forged verdict. This does not launch Claude Code or execute tools.
#
#   ./claude-integration.sh
#
# No API key or network required.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! python3 -c "import qedra" 2>/dev/null; then
  echo "qedra not importable. Install it first:  pip install -e ." >&2
  exit 1
fi

exec python3 demo_claude_hook.py
