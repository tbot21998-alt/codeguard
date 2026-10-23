import json
import os
import shlex
import sys
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "integrations"
CLIENTS = ["antigravity-cli", "claude-code", "codex", "cursor", "devin-cli", "factory-droid", "gemini-cli", "github-copilot-cli", "grok-build", "hermes-agent", "kimi-code", "opencode"]


def hook_argv(client, *, audit=True, local=False):
    prefix = [os.path.abspath(sys.executable), "-m", "guard"] if local else ["codeguard"]
    args = prefix + ["agent-hook", "--client", client]
    return args + ["--audit-log", str(ROOT / "reports/command-audit.jsonl")] if audit and local else args


def hook_command(client, *, audit=True, local=False):
    args = hook_argv(client, audit=audit, local=local)
    if local and os.name == "nt":
        expression = "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args)
        return subprocess.list2cmdline(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", expression])
    return shlex.join(args)


def configuration(client, *, local=False):
    handler = {"type": "command", "command": hook_command(client, local=local), "timeout": 30}
    standard = [{"matcher": "*", "hooks": [handler]}]
    if client == "cursor":
        return {"version": 1, "hooks": {"preToolUse": [{"command": hook_command(client, local=local), "timeout": 30, "failClosed": True}]}}
    if client == "github-copilot-cli":
        argv = hook_argv(client, local=local)
        return {"version": 1, "hooks": {"preToolUse": [{"type": "command", "exec": argv[0], "args": argv[1:], "timeoutSec": 30}]}}
    if client == "antigravity-cli":
        return {"codeguard": {"PreToolUse": standard}}
    if client == "factory-droid":
        return {"PreToolUse": standard}
    if client == "gemini-cli":
        return {"hooks": {"BeforeTool": [{"matcher": "run_shell_command", "hooks": [{"type": "command", "name": "codeguard", "command": hook_command(client, local=local), "timeout": 30000}]}]}}
    return {"hooks": {"PreToolUse": standard}}


def hermes_plugin(*, local=False):
    return '''import json
import subprocess

ANALYZER = ARGV


def pre_tool_call(tool_name="", args=None, **_):
    if tool_name != "terminal":
        return None
    try:
        result = subprocess.run(ANALYZER, input=json.dumps({"tool_name": tool_name, "args": args}), capture_output=True, text=True, encoding="utf-8", timeout=10)
        output = json.loads(result.stdout)
        if result.returncode != 0 or not isinstance(output, dict):
            return {"action": "block", "message": "CodeGuard hook failed"}
        if output.get("action") == "block":
            return output
        if output == {}:
            return None
        return {"action": "block", "message": "Unexpected CodeGuard response"}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {"action": "block", "message": "CodeGuard failed closed: " + str(error)}


def register(ctx):
    ctx.register_hook("pre_tool_call", pre_tool_call)
'''.replace("ARGV", repr(hook_argv("hermes-agent", local=local)))


def opencode_plugin(*, local=False):
    source = (OUTPUT / "opencode/codeguard.js").read_text(encoding="utf-8")
    prefix = [os.path.abspath(sys.executable), "-m", "guard"]
    return source.replace('const ANALYZER = ["codeguard"];', "const ANALYZER = " + json.dumps(prefix) + ";") if local else source


def main():
    for client in CLIENTS:
        folder = OUTPUT / client
        folder.mkdir(parents=True, exist_ok=True)
        if client == "opencode":
            continue
        if client == "hermes-agent":
            (folder / "__init__.py").write_text(hermes_plugin(), encoding="utf-8")
            (folder / "plugin.yaml").write_text('name: codeguard\nversion: "0.1.0"\ndescription: "Inspect terminal commands before execution"\nauthor: "CodeGuard"\nprovides_hooks:\n  - pre_tool_call\n', encoding="utf-8")
            continue
        if client == "kimi-code":
            (folder / "config-fragment.toml").write_text('[[hooks]]\nevent = "PreToolUse"\ncommand = ' + json.dumps(hook_command(client)) + '\n', encoding="utf-8")
            continue
        (folder / "hooks.json").write_text(json.dumps(configuration(client), indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"generated": CLIENTS, "directory": str(OUTPUT), "activated": False}, indent=2))


if __name__ == "__main__":
    main()
