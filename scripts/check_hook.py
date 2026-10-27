"""Test generated hooks through the host shell; inputs are never executed."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_integrations import hook_command


def main():
    command = hook_command("antigravity-cli", audit=False, local=True)
    launcher = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command] if os.name == "nt" else ["/bin/sh", "-c", command]
    with tempfile.TemporaryDirectory(prefix="codeguard hook ") as directory:
        cases = [("echo hello", "allow"), ("git status", "allow"), ("git diff", "allow"),
                 ("rm -rf /", "deny"),
                 ("git rm demo/audit.html demo/dashboard.html demo/intercept_check.py", "deny"),
                 ("git -C . rm -rf demo", "deny"),
                 ("Remove-Item demo/audit.html", "deny"),
                 ("del README.md", "deny"),
                 ("cmd /c del demo\\audit.html", "deny")]
        for source, expected in cases:
            event = {"toolCall": {"name": "run_command", "args": {"CommandLine": source}}}
            result = subprocess.run(launcher, input=json.dumps(event), text=True, capture_output=True, cwd=directory, timeout=30)
            try:
                decision = json.loads(result.stdout).get("decision")
            except (ValueError, AttributeError):
                decision = None
            print(json.dumps({"input": source, "expected": expected, "actual": decision, "exit": result.returncode}))
            if result.returncode != 0 or decision != expected:
                print(result.stderr, file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
