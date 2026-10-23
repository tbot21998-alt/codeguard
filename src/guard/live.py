import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from guard.interceptor import CodeGuardBlockedError, SafeExecutor
from guard.ml_model import probabilities
from guard.audit import write_audit


def decision_report(verdict, latency_ms, *, audit_log=None):
    report = {**verdict.model_dump(), "latency_ms": round(latency_ms, 4)}
    write_audit(report, audit_log)
    print(json.dumps(report), file=sys.stderr, flush=True)


def shell_argv(command):
    if os.name == "nt":
        executable = shutil.which("pwsh") or shutil.which("powershell")
        if executable is None:
            raise FileNotFoundError("PowerShell is required for the Windows guarded terminal")
        return [executable, "-NoLogo", "-NoProfile", "-Command", command]
    executable = shutil.which("bash") or shutil.which("sh")
    if executable is None:
        raise FileNotFoundError("A shell executable is required")
    return [executable, "-c", command]


def run_shell(*, audit_log=None):
    probabilities("print('warmup')")
    print("CodeGuard guarded terminal. Every external command is checked before it starts.")
    print("Commands: :help, :cd <directory>, :quit. Each command starts a fresh shell.")
    print("Only commands entered here are guarded; the current user permissions still apply.")
    executor = SafeExecutor()
    while True:
        try:
            command = input(f"codeguard [{Path.cwd()}]> ").strip()
            if not command:
                continue
            if command in {":quit", ":exit"}:
                return 0
            if command == ":help":
                print("Enter a shell command to inspect and run. :cd changes this session's working directory.")
                print("A block returns its reason and latency without creating the requested process.")
                continue
            if command.startswith(":cd "):
                os.chdir(Path(command[4:].strip().strip('"').strip("'")).expanduser())
                continue
            executor.run_command(shell_argv(command), on_decision=lambda verdict, latency: decision_report(verdict, latency, audit_log=audit_log))
        except CodeGuardBlockedError:
            continue
        except (EOFError, KeyboardInterrupt):
            print("\nGuarded terminal closed.")
            return 0
        except subprocess.TimeoutExpired:
            print("Command exceeded the 30-second timeout.", file=sys.stderr)
        except (OSError, ValueError) as error:
            print(f"Command not started or could not complete: {error}", file=sys.stderr)
