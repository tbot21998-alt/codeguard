import argparse
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from generate_integrations import CLIENTS, OUTPUT, ROOT, configuration, hermes_plugin, hook_command, opencode_plugin


def merge_configuration(existing, addition):
    if isinstance(existing, dict) and isinstance(addition, dict):
        return {**existing, **{key: merge_configuration(existing[key], value) if key in existing else value for key, value in addition.items()}}
    if isinstance(existing, list) and isinstance(addition, list):
        return existing + [item for item in addition if item not in existing]
    if type(existing) is not type(addition):
        raise ValueError("Existing configuration has an incompatible field type; merge manually")
    return addition


def destinations(home):
    return {
        "antigravity-cli": home / ".gemini/config/hooks.json",
        "claude-code": home / ".claude/settings.json",
        "codex": Path(os.environ.get("CODEX_HOME", str(home / ".codex"))) / "hooks.json",
        "cursor": home / ".cursor/hooks.json",
        "devin-cli": Path(os.environ.get("APPDATA", str(home / "AppData/Roaming"))) / "devin/config.json" if os.name == "nt" else Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))) / "devin/config.json",
        "factory-droid": home / ".factory/hooks.json",
        "gemini-cli": home / ".gemini/settings.json",
        "github-copilot-cli": Path(os.environ.get("COPILOT_HOME", str(home / ".copilot"))) / "hooks/codeguard.json",
        "grok-build": Path(os.environ.get("GROK_HOME", str(home / ".grok"))) / "hooks/codeguard.json",
        "hermes-agent": Path(os.environ.get("HERMES_HOME", str(home / ".hermes"))) / "plugins/codeguard",
        "kimi-code": Path(os.environ.get("KIMI_CODE_HOME", str(home / ".kimi-code"))) / "config.toml",
        "opencode": Path(os.environ.get("OPENCODE_CONFIG_DIR", os.environ.get("OPENCODE_HOME", str(Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))) / "opencode")))) / "plugins/codeguard.js",
    }


def write_with_backup(path, content):
    if path.is_file() and path.read_text(encoding="utf-8-sig") == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".codeguard-backup-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")))
    temporary = path.with_name(path.name + ".codeguard-tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
    return True


def upgrade_generated_command(value, client):
    if isinstance(value, str) and value == hook_command(client, audit=False):
        return hook_command(client)
    if isinstance(value, list):
        if client == "github-copilot-cli" and value == ["-m", "guard", "agent-hook", "--client", client]:
            return value + ["--audit-log", str(ROOT / "reports/command-audit.jsonl")]
        return [upgrade_generated_command(item, client) for item in value]
    if isinstance(value, dict):
        return {key: upgrade_generated_command(item, client) for key, item in value.items()}
    return value


def install_client(client, target):
    source = OUTPUT / client
    if client == "opencode":
        return write_with_backup(target, opencode_plugin(local=True))
    if client == "hermes-agent":
        changed = [write_with_backup(target / "__init__.py", hermes_plugin(local=True)), write_with_backup(target / "plugin.yaml", (source / "plugin.yaml").read_text(encoding="utf-8"))]
        return any(changed)
    if client == "kimi-code":
        existing = target.read_text(encoding="utf-8-sig") if target.is_file() else ""
        existing = existing.replace(json.dumps(hook_command(client, audit=False)), json.dumps(hook_command(client)))
        addition = '[[hooks]]\nevent = "PreToolUse"\ncommand = ' + json.dumps(hook_command(client, local=True)) + '\n'
        if addition.strip() in existing:
            return write_with_backup(target, existing)
        if re.search(r"^\s*hooks\s*=", existing, re.M):
            raise ValueError("Kimi has an inline hooks array; merge the generated TOML entry manually")
        return write_with_backup(target, existing.rstrip() + ("\n\n" if existing.strip() else "") + addition)
    existing = json.loads(target.read_text(encoding="utf-8-sig")) if target.is_file() else {}
    if not isinstance(existing, dict):
        raise ValueError("Existing hook configuration must be a JSON object")
    addition = configuration(client, local=True)
    merged = {**existing, "codeguard": addition["codeguard"]} if client == "antigravity-cli" else merge_configuration(upgrade_generated_command(existing, client), addition)
    return write_with_backup(target, json.dumps(merged, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Merge generated CodeGuard hooks into local CLI settings, backing up changed files")
    parser.add_argument("--client", choices=CLIENTS)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--project", type=Path, help="Install Antigravity or OpenCode into this workspace instead of the global configuration")
    arguments = parser.parse_args()
    if arguments.all == bool(arguments.client):
        parser.error("Choose --all or one --client")
    try:
        from guard.ml_model import MODEL_PATH
    except ImportError:
        parser.error("Install CodeGuard with this Python first: python -m pip install -e .")
    if not MODEL_PATH.is_file():
        parser.error("CodeGuard's model is missing; restore the model before installing hooks")
    targets = destinations(Path.home())
    if arguments.project:
        if arguments.client not in {"antigravity-cli", "opencode"}:
            parser.error("--project requires --client antigravity-cli or --client opencode")
        project = arguments.project.resolve()
        targets["antigravity-cli"] = project / ".agents/hooks.json"
        targets["opencode"] = project / ".opencode/plugins/codeguard.js"
    results = []
    for client in CLIENTS if arguments.all else [arguments.client]:
        try:
            changed = install_client(client, targets[client])
            results.append({"client": client, "path": str(targets[client]), "configuration": "installed" if changed else "unchanged", "host_activation_verified": False})
        except (ValueError, OSError) as error:
            results.append({"client": client, "error": str(error), "configuration": "not installed"})
    print(json.dumps(results, indent=2))
    return 1 if any("error" in result for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
