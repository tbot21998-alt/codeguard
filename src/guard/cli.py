import argparse
import json
import sys
from pathlib import Path

from guard.detector import evaluate
from guard.interceptor import CodeGuardBlockedError, SafeExecutor
from guard.live import decision_report, run_shell
from guard.schema import CodeRequest
from guard.agent_hooks import TOOLS, run_agent_hook


def main():
    parser = argparse.ArgumentParser(description="Inspect generated code or gate an explicit CLI command.")
    commands = parser.add_subparsers(dest="action", required=True)
    inspect = commands.add_parser("evaluate", help="Read JSON from stdin or source from --file; never executes code")
    inspect.add_argument("--file", type=Path)
    commands.add_parser("hook", help="Read a JSON code request or Bash tool event; exit 2 to deny execution")
    shell = commands.add_parser("shell", help="Start a local terminal that checks each external command before execution")
    shell.add_argument("--audit-log", type=Path)
    agent_hook = commands.add_parser("agent-hook", help="Read a native AI CLI tool event and return its blocking directive")
    agent_hook.add_argument("--client", choices=sorted(TOOLS), required=True)
    agent_hook.add_argument("--endpoint", default=None, help="Optional HTTP service endpoint; defaults to direct in-process inspection")
    agent_hook.add_argument("--audit-log", type=Path)
    run = commands.add_parser("run", help="Evaluate and synchronously gate an explicit command")
    run.add_argument("--report", action="store_true", help="Print the decision and inspection latency to stderr")
    run.add_argument("--audit-log", type=Path)
    run.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "agent-hook":
        return run_agent_hook(args.client, args.endpoint, audit_log=args.audit_log)
    try:
        if args.action == "shell":
            return run_shell(audit_log=args.audit_log)
        if args.action == "run":
            argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
            callback = (lambda verdict, latency: decision_report(verdict, latency, audit_log=args.audit_log)) if args.report or args.audit_log else None
            result = SafeExecutor().run_command(argv, on_decision=callback)
            return result.returncode
        if args.action == "evaluate" and args.file:
            code = args.file.read_text(encoding="utf-8")
        else:
            payload = json.loads(sys.stdin.read())
            if args.action == "hook" and "tool_input" in payload:
                code = CodeRequest(code=payload["tool_input"]["command"]).code
            else:
                code = CodeRequest.model_validate(payload).code
        verdict = evaluate(code)
        print(verdict.model_dump_json())
        return 2 if verdict.verdict == "block" else 0
    except CodeGuardBlockedError as error:
        if not (args.action == "run" and (args.report or args.audit_log)):
            print(error.verdict.model_dump_json(), file=sys.stderr)
        return 2
    except (ValueError, KeyError, OSError) as error:
        print(json.dumps({"error": str(error), "execution_permitted": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
