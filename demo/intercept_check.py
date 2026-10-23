import json
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter

from guard.interceptor import CodeGuardBlockedError, SafeExecutor
from guard.ml_model import probabilities


def main():
    probabilities("print('warmup')")
    with tempfile.TemporaryDirectory(prefix="codeguard-demo-") as folder:
        root = Path(folder)
        credentials = root / ".aws" / "credentials"
        credentials.parent.mkdir()
        credentials.write_text("FAKE_DEMO_SECRET_ONLY", encoding="utf-8")
        safe_marker = root / "safe_marker.txt"
        blocked_marker = root / "blocked_marker.txt"
        safe = f"from pathlib import Path\nPath({str(safe_marker)!r}).write_text('safe_ok', encoding='utf-8')"
        unsafe = f"from pathlib import Path\nsecret = Path({str(credentials)!r}).read_text()\nPath({str(blocked_marker)!r}).write_text(secret)"
        executor = SafeExecutor()
        executor.run(safe)
        started = perf_counter()
        blocked = False
        try:
            executor.run(unsafe)
        except CodeGuardBlockedError:
            blocked = True
        elapsed = (perf_counter() - started) * 1000
        audit = root / "command-audit.jsonl"
        cli_safe = subprocess.run([sys.executable, "-m", "guard", "run", "--report", "--audit-log", str(audit), "--", sys.executable, "-c", safe], capture_output=True, text=True, timeout=30)
        cli_unsafe = subprocess.run([sys.executable, "-m", "guard", "run", "--report", "--audit-log", str(audit), "--", sys.executable, "-c", unsafe], capture_output=True, text=True, timeout=30)
        decisions = [json.loads(line)["verdict"] for line in audit.read_text(encoding="utf-8").splitlines()] if audit.is_file() else []
        passed = safe_marker.read_text(encoding="utf-8") == "safe_ok" and blocked and not blocked_marker.exists() and cli_safe.returncode == 0 and cli_unsafe.returncode == 2 and decisions == ["allow", "block"]
        print(json.dumps({"passed": passed, "safe_marker_created": safe_marker.exists(), "blocked_exception_raised": blocked, "unsafe_marker_exists": blocked_marker.exists(), "interception_ms": round(elapsed, 3), "under_15ms": elapsed < 15, "cli_safe_exit_code": cli_safe.returncode, "cli_unsafe_exit_code": cli_unsafe.returncode, "audit_decisions": decisions, "cli_denial": cli_unsafe.stderr.strip(), "secret_source": "temporary fake credential only"}, indent=2))
        if not passed:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
