import json
import sys
import time
from pathlib import Path
from http.client import HTTPException
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from guard.command_policy import validate_command_text
from guard.schema import Verdict
from guard.audit import write_audit


TOOLS = {
    "antigravity-cli": {"run_command", "manage_task"},
    "claude-code": {"Bash"},
    "codex": {"Bash"},
    "cursor": {"Shell"},
    "devin-cli": {"exec", "write_to_process"},
    "factory-droid": {"Execute"},
    "gemini-cli": {"run_shell_command"},
    "github-copilot-cli": {"bash", "Bash", "powershell", "PowerShell"},
    "grok-build": {"run_terminal_command", "run_terminal_cmd", "monitor", "bash", "Shell"},
    "hermes-agent": {"terminal"},
    "kimi-code": {"Bash"},
    "opencode": {"bash", "shell", "run_command"},
}


def directive(client, reason=None):
    if client == "cursor":
        return {"permission": "deny", "user_message": reason, "agent_message": reason} if reason else {"permission": "allow"}
    if client in {"antigravity-cli", "grok-build", "opencode"}:
        return {"decision": "deny", "reason": reason} if reason else {"decision": "allow"}
    if not reason:
        return {}
    if client == "hermes-agent":
        return {"action": "block", "message": reason}
    if client == "github-copilot-cli":
        return {"permissionDecision": "deny", "permissionDecisionReason": reason}
    if client in {"devin-cli", "gemini-cli"}:
        return {"decision": "block" if client == "devin-cli" else "deny", "reason": reason}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}


def command_from_event(client, event):
    if not isinstance(event, dict):
        raise ValueError("The tool event must be an object")
    call = event.get("toolCall", {}) if client == "antigravity-cli" else event
    if not isinstance(call, dict):
        raise ValueError("The tool call must be an object")
    name = call.get("name") if client == "antigravity-cli" else call.get("tool_name", call.get("toolName", call.get("tool")))
    if not isinstance(name, str):
        raise ValueError("Missing tool name; CodeGuard cannot identify this event")
    if name not in TOOLS[client]:
        return None
    if name == "write_to_process" or event.get("toolInputTruncated"):
        raise ValueError("Interactive process input or truncated tool input cannot be inspected safely")
    args = call.get("args") if client == "antigravity-cli" else call.get("tool_input", call.get("toolInput", call.get("toolArgs", call.get("args"))))
    if isinstance(args, str):
        args = json.loads(args)
    if not isinstance(args, dict):
        raise ValueError("Missing command arguments")
    if name == "manage_task":
        if args.get("Action") == "send_input":
            raise ValueError("Interactive process input cannot be inspected safely")
        return None
    command = args.get("CommandLine") if client == "antigravity-cli" else args.get("command", args.get("cmd"))
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Missing command text")
    return command


def check_http(command, endpoint):
    if endpoint not in {"http://127.0.0.1:8000", "http://localhost:8000"}:
        raise ValueError("Use the local CodeGuard service on port 8000")
    try:
        request = Request(endpoint + "/evaluate", data=json.dumps({"code": command}).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        with build_opener(ProxyHandler({})).open(request, timeout=2) as response:
            result = json.loads(response.read(1_048_576))
        verdict = Verdict.model_validate(result, strict=True)
        if verdict.verdict == "allow" and (verdict.categories or verdict.vulnerable_lines or verdict.risk_score is None or verdict.risk_score >= 0.85):
            raise ValueError("The detector returned an inconsistent allow verdict")
        return verdict.model_dump()
    except (OSError, URLError):
        from guard.detector import inspect_code
        return inspect_code(command).verdict.model_dump()


def handle_event(client, event, checker):
    started = time.perf_counter()
    try:
        command = command_from_event(client, event)
        if command is None:
            return directive(client), None
        validate_command_text(command)
        result = checker(command)
        if not isinstance(result, dict) or result.get("verdict") not in {"allow", "block"}:
            raise ValueError("The detector returned an invalid verdict")
        reason = "CodeGuard: " + str(result.get("reason", "Policy blocked this command")) if result["verdict"] == "block" else None
        return directive(client, reason), {"client": client, **{key: result[key] for key in ("verdict", "risk_score", "confidence_score", "categories", "reason", "vulnerable_lines") if key in result}, "latency_ms": round((time.perf_counter() - started) * 1000, 4)}
    except (ValueError, TypeError, OSError, URLError, HTTPException, RecursionError) as error:
        return directive(client, "CodeGuard failed closed: " + str(error)), {"client": client, "verdict": "block", "latency_ms": round((time.perf_counter() - started) * 1000, 4), "error": str(error)}


def run_agent_hook(client, endpoint=None, *, audit_log=None):
    audit_log = audit_log or Path.home() / ".codeguard/command-audit.jsonl"
    try:
        raw = sys.stdin.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("Tool event exceeds 1 MiB")
        event = json.loads(raw)
        if endpoint:
            checker = lambda command: check_http(command, endpoint)
        else:
            from guard.detector import inspect_code
            checker = lambda command: inspect_code(command).verdict.model_dump()
        output, report = handle_event(client, event, checker)
    except (ValueError, OSError, RecursionError) as error:
        output, report = directive(client, "CodeGuard failed closed: " + str(error)), {"error": str(error)}
    if report:
        try:
            write_audit(report, audit_log)
        except OSError:
            output = directive(client, "CodeGuard failed closed: command audit could not be written")
            report = {**report, "verdict": "block", "error": "command audit could not be written"}
    print(json.dumps(output))
    if report:
        print(json.dumps(report), file=sys.stderr)
    return 0
