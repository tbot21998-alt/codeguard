import json
import subprocess

ANALYZER = ['codeguard', 'agent-hook', '--client', 'hermes-agent']


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
