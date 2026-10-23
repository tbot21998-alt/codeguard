# CLI blocking and command monitoring

CodeGuard checks supported commands before execution and records their decisions. It cannot detect every vulnerability or monitor every process on the computer. It is a policy gate around a defined execution boundary, with native hooks for the eleven clients listed in `integrations/README.md`.

## Start protection and watch decisions

Keep the detector running for native hooks:

```powershell
cd 'D:\Users\Shlok Parekh\Downloads\LLMGuard\codeguard'
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

For the built-in guarded terminal, open a second terminal:

```powershell
.\.venv\Scripts\python.exe -m guard shell --audit-log .\reports\command-audit.jsonl
```

Watch its decisions from another PowerShell terminal after the first record exists:

```powershell
Get-Content .\reports\command-audit.jsonl -Tail 20 -Wait
```

The generated native hooks use the absolute project path for this same log. Records contain a UTC timestamp, client when applicable, verdict, inspection/request latency, and available categories, risk score, reason and evidence lines. They omit raw command and source text. Latency excludes process startup, host scheduling and audit-file writes. This is a decision log, not a post-execution process trace. It does not establish whether an allowed program later succeeded.

`--audit-log` is also supported by `guard run` and `guard agent-hook`. When explicitly requested logging fails, the guarded terminal does not start the command and the native adapter emits a denial. Logs are local, user-editable and excluded from Git; archive them periodically. They are not tamper-proof security evidence. Invalid input rejected before a terminal decision callback may appear only in stderr; native adapter errors are reported and logged when storage works.

## Bypasses closed in this update

- A Python script filename or `-m` invocation before a later `-c` no longer tricks the wrapper into inspecting a harmless argument while executing another entry point.
- Python interactive mode and unsupported interpreter startup options are refused. Known inline forms accept only a small set of understood options before the source argument.
- Node preloads before inline source are refused. Options after inline source are also refused unless they are ordinary program arguments following `--`.
- PowerShell and CMD trailing command arguments are inspected together, rather than checking only the first string after the command flag.
- Native adapters validate interpreter entry points before requesting an HTTP verdict. Chained commands, nested supported shell invocations, common wrappers such as `env` and `sudo`, and leading environment assignments receive the same boundary checks.
- HTTP responses must match the complete verdict schema. An allow response carrying threat categories, evidence lines, or a risk score at or above 0.3 is rejected.

These cases have regression tests written from the demonstrated failures. They are policy restrictions: a legitimate `python script.py` or `python -m pytest` can be blocked because the guard does not inspect that entry point. The JSON analysis endpoint still analyzes supplied source as text; strict execution-boundary restrictions do not turn the public development score into a measure of live-command usability.

## Updating existing native hooks

```powershell
.\.venv\Scripts\python.exe generate_integrations.py
.\.venv\Scripts\python.exe install_integrations.py --all
```

The installer upgrades the earlier generated command to add auditing, preserves unrelated settings, and backs up changed files. Restart each host. In Codex, open `/hooks` and trust the changed definition; changed commands invalidate the earlier trust hash. Check Hermes plugin discovery/activation. Installed configuration is not proof that the host executes the hook. Copilot host-level command-hook timeouts can fall through to normal permissions despite the adapter's fail-closed behavior.

## Verification and remaining limits

Run the Python suite and the controlled execution proof:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe demo/intercept_check.py
```

The marker demo uses temporary fake credentials only. It checks safe execution, a blocked unsafe call, exit codes 0 and 2, no unsafe marker, and an audit sequence of allow then block. Attack datasets are never executed.

Shell segmentation is deliberately limited and does not implement every shell grammar. Unrecognized wrappers, aliases, variable expansion, external executables, imported modules, environment startup behavior, mutable files and remote tools remain practical limits. Native hooks cover named shell tools, not all MCP, file, browser or cloud tools. A user or host can disable or skip an unmanaged hook. Use operating-system isolation and least privilege for arbitrary untrusted execution; an allow verdict does not certify safety.

The Word guide explains the baseline architecture and model in detail. This document describes the subsequent command-policy and persistent-monitoring update.
