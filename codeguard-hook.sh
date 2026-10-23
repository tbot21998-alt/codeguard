#!/bin/sh
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
runtime=${CODEGUARD_PYTHON:-"$script_dir/.venv/bin/python"}
if [ ! -x "$runtime" ]; then
  printf '%s\n' '{"decision":"deny","reason":"CodeGuard: Python environment missing. Install requirements or set CODEGUARD_PYTHON."}'
  exit 0
fi
"$runtime" -m guard agent-hook --client antigravity-cli --audit-log "$script_dir/reports/command-audit.jsonl" || printf '%s\n' '{"decision":"deny","reason":"CodeGuard: Inspector failed; execution blocked."}'
