# Portable CLI integrations

The current supported integration targets are **Antigravity CLI (AGY)** and **OpenCode**. Other bundled CLI templates are experimental/unverified. For the complete beginner setup, see [setupguide.md](../setupguide.md).

CodeGuard inspects supported command tool calls before execution. The checked-in templates use `codeguard` on PATH; they contain no developer-specific drive or home paths. The installer generates each machine's configuration using the Python interpreter running the installer. It preserves virtual-environment paths, quotes spaces, and does not require activating that environment each time a client starts.

## Install on each computer

Use Python 3.12 or newer and a supported Windows, macOS, or Linux host. Do not copy a virtual environment from another computer or operating system. Keep the source checkout available for an editable installation.

Windows PowerShell, from the `codeguard` directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe install_integrations.py --client antigravity-cli
.\.venv\Scripts\python.exe install_integrations.py --client opencode
```

macOS or Linux, from the same directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python install_integrations.py --client antigravity-cli
.venv/bin/python install_integrations.py --client opencode
```

LightGBM needs its native runtime. On macOS an OpenMP runtime may need installation; on Linux the corresponding OpenMP runtime must be available. Follow errors from the package installer and your operating system's package manager. ARM and other architectures require compatible Python dependency wheels or a working native build toolchain; they have not been tested here.

For project-only installation, add `--project "/absolute/path/to/workspace"` to either install command. Existing project-level hooks can take precedence over global hooks, so replace an old project-level CodeGuard definition using this option too.

The installer backs up changed files, replaces Antigravity's named `codeguard` definition, preserves unrelated definitions, and is idempotent for these two integrations. Restart the client after installation. If you move the checkout or recreate its virtual environment, run the installer again. No HTTP server is needed: these hooks call the local Python inspector directly.

## Antigravity CLI

Global destination: `~/.gemini/config/hooks.json`. Project destination: `.agents/hooks.json`.

The hook receives `toolCall.name` and `toolCall.args`. It inspects `run_command.CommandLine`, returns `decision: allow` or `decision: deny`, and denies `manage_task` requests that send interactive input. Other tools retain the client's own permissions.

After restarting Antigravity, run `/hooks` and verify the CodeGuard definition is enabled. Client permissions and hook trust settings still apply. The included `codeguard-hook.cmd` is an optional Windows launcher; `sh codeguard-hook.sh` is its POSIX counterpart. Both resolve a virtual environment beside the script, or use the executable path in `CODEGUARD_PYTHON`.

On Windows, use the installer-generated encoded PowerShell launcher so paths with spaces survive the client's `cmd.exe` invocation. Do not substitute a manually quoted executable string. Verify the generated command with `.venv\Scripts\python.exe scripts/check_hook.py`.

## OpenCode

Global destination: `~/.config/opencode/plugins/codeguard.js`, respecting `OPENCODE_CONFIG_DIR`, `OPENCODE_HOME`, or `XDG_CONFIG_HOME` when set. Project destination: `.opencode/plugins/codeguard.js`.

OpenCode automatically loads local plugins from these directories. Do not add a second plugin reference, which could execute the hook twice. The old `plugins` configuration key was incorrect; npm plugins use the singular `plugin` key, and this local plugin needs no config entry.

The integration targets OpenCode's `tool.execute.before` plugin API. It inspects `bash`, `shell`, and `run_command` calls. It blocks on an explicit denial, missing command, malformed or empty response, missing Python executable, nonzero inspector exit, output overflow, or timeout. The proposed command is passed as JSON data to the inspector, never executed by the plugin.

The installer embeds the current machine's Python executable. `CODEGUARD_PYTHON` can override it with a full executable path, not a shell command. Restart OpenCode after changing this environment variable.

## Logs and scope

Generated Antigravity configurations log to the checkout's `reports/command-audit.jsonl`. The OpenCode plugin and portable PATH-based templates default to `~/.codeguard/command-audit.jsonl`. These files are local and should not be committed.

These integrations guard supported command calls, not arbitrary file writes, MCP tools, remote sessions, terminals opened elsewhere, or every possible way a program can execute code. An allow verdict is not an OS sandbox. Host failure to load a hook cannot be prevented by the hook itself.

Windows adapter subprocesses, actual safe/blocked inspections, installer merging, and OpenCode plugin failure handling have automated tests. POSIX quoting is tested, but native macOS/Linux and live client activation were not verified in this Windows session. Phones and tablets can access a deployed web UI; native mobile execution is not supported by this integration.

## Verification

From `codeguard`, using its virtual environment:

```sh
python -m pytest tests/test_portable_integrations.py -q
node --test tests/opencode.test.mjs
```

The Python tests submit commands to the inspector as text, including a dangerous string expected to be denied; they do not execute those commands. Verify host activation using a harmless command such as `echo codeguard-check` and inspect the audit log.

## References

- [Antigravity hooks](https://antigravity.google/docs/hooks)
- [OpenCode plugins](https://dev.opencode.ai/docs/plugins/)

Other existing CLI templates remain available through `generate_integrations.py` and `install_integrations.py --all`; they have not been independently verified in this portability update.
