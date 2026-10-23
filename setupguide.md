# CodeGuard setup guide

This guide covers unpacking the project, installing Python dependencies, starting the dashboard, and enabling command inspection in Antigravity CLI (AGY) and OpenCode.

## 1. Current support

**Only Antigravity CLI and OpenCode are currently supported integration targets for this setup.** Other CLI templates in the repository are experimental or unverified. Their presence does not mean those clients are supported. Do not use `--all` for the supported setup described here.

| Component | Status |
| --- | --- |
| Antigravity CLI | Hook adapter and installation supported; restart the client and verify activation with `/hooks` |
| OpenCode | Local plugin supported for the `tool.execute.before` API; restart the client after installation |
| Other AI coding CLIs | Not supported by this setup guide; existing templates are unverified |
| Windows | Adapter subprocesses, installation behavior, and safe/blocked inspection tested locally |
| macOS and Linux | Portable implementation and commands provided; native end-to-end operation has not been tested in this Windows development session |
| Phones, tablets, other architectures | No claim of native support; Python, dependencies, and the AI client must support the device |

Live activation inside the two AI clients must still be checked on the destination machine. Automated adapter tests alone do not prove that a client has loaded its hook.

## 2. Does it work immediately after unzipping?

The source no longer depends on the original developer's username or drive path. However, **unzipping alone does not install Python, dependencies, or client hooks**. On every new computer:

1. Unzip the project into its permanent location.
2. Install Python and create a new virtual environment there.
3. Install the project's dependencies.
4. Run the integration installer for Antigravity CLI and/or OpenCode.
5. Restart the client and verify its hook is active.

The installer records that computer's Python executable in its local client configuration. This is intentional: the client can then find CodeGuard even when its terminal has not activated the virtual environment. Do not copy generated client settings or `.venv` from another computer. If you move the project later, recreate the environment in the new location and rerun the installers.

## 3. Prerequisites and folder layout

- Python **3.12 or newer**. Python 3.14 was used for the local Windows verification. The pinned NumPy/SciPy dependencies require at least Python 3.12.
- Internet access for the initial dependency installation. Inspection uses the local CPU and does not call an external LLM.
- Antigravity CLI and/or OpenCode already installed independently. The CodeGuard installer does not install these applications.
- A compatible LightGBM native runtime. See troubleshooting if loading LightGBM fails.
- The OpenCode application provides its own plugin environment.

Obtain Python from [python.org](https://www.python.org/downloads/). The client documentation is available at [Antigravity](https://antigravity.google/docs/hooks) and [OpenCode](https://dev.opencode.ai/docs/plugins/).

The extracted folder should look approximately like this:

```text
LLMGuard/
  setupguide.md
  README.md
  SECURITY.md
  codeguard/
    app.py
    pyproject.toml
    requirements.lock
    requirements.txt
    install_integrations.py
    generate_integrations.py
    models/codeguard.joblib
    models/codeguard.json
    src/guard/
    integrations/
    demo/
```

**Run the installation commands from the inner `codeguard` directory**, which contains `pyproject.toml`. If your archive contains this directory's contents directly, use that directory instead. Keep the included model files; they are needed for detection. A dataset is not required to start the service or use the hooks.

## 4. Windows installation

Open PowerShell. Replace the example path with the folder where you extracted the project:

```powershell
Set-Location 'C:\Projects\LLMGuard\codeguard'
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m guard --help
```

If `python` is not recognized but the Windows Python launcher is installed, use `py -3 --version` and `py -3 -m venv .venv` for the first two Python commands. Check that it selects Python 3.12 or newer.

Activation is optional: all commands here explicitly use `.venv\Scripts\python.exe`. You do not need to change PowerShell's execution policy just to follow this guide.

Install the integrations you use:

```powershell
.\.venv\Scripts\python.exe install_integrations.py --client antigravity-cli
.\.venv\Scripts\python.exe install_integrations.py --client opencode
```

Successful output reports `"configuration": "installed"` or `"unchanged"`. `"host_activation_verified": false` means the installer wrote the settings but cannot confirm that the AI client has loaded them. Follow section 6.

## 5. macOS or Linux installation

Open a terminal and replace the example path:

```sh
cd "$HOME/Projects/LLMGuard/codeguard"
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip check
.venv/bin/python -m guard --help
.venv/bin/python install_integrations.py --client antigravity-cli
.venv/bin/python install_integrations.py --client opencode
```

Use a versioned Python executable such as `python3.12` for environment creation if the default `python3` is older than 3.12. If your Linux distribution separates the `venv` module, install the package matching that Python version through its package manager first.

These commands are designed for POSIX systems, but native macOS/Linux execution has not yet been verified here. Dependency availability varies by operating system and CPU architecture.

## 6. Activate Antigravity CLI and OpenCode

### Antigravity CLI / AGY

The installer merges the named `codeguard` hook into:

```text
~/.gemini/config/hooks.json
```

On Windows, `~` is your user directory, usually `C:\Users\YOUR_NAME`. Existing unrelated hooks are preserved; changed files receive timestamped backups.

1. Close and reopen Antigravity CLI.
2. Enter `/hooks` inside the client.
3. Confirm that the `codeguard` hook is present and enabled. Complete any trust/permission review the client requires.
4. Ask the agent to run the harmless command `echo codeguard-check`.
5. Confirm a new entry appears in `codeguard/reports/command-audit.jsonl`.

The hook inspects `run_command` calls and denies interactive `manage_task` send-input requests, whose full execution context cannot be inspected by this adapter. Other tools retain the client's permissions.

### OpenCode

The installer writes a local plugin to:

```text
~/.config/opencode/plugins/codeguard.js
```

It respects `OPENCODE_CONFIG_DIR`, then `OPENCODE_HOME`, and otherwise the configured/default configuration directory. OpenCode automatically discovers local plugins in its plugin directory.

1. Close and reopen OpenCode.
2. Check startup output for plugin loading errors.
3. Ask the agent to run `echo codeguard-check`.
4. Confirm a new entry appears in `~/.codeguard/command-audit.jsonl`.

Do not add another explicit reference to the same plugin: duplicate registration can inspect each command twice. Do not use the old `plugins` JSON key. The singular `plugin` key is used for package plugins; this automatically discovered local plugin needs no entry.

This integration uses OpenCode's `tool.execute.before` API and inspects `bash`, `shell`, and `run_command`. It blocks a command if the inspector denies it, cannot start, times out, returns an error, or returns malformed output. A future client version with a different plugin API may need an adapter update.

### Install for one workspace instead of globally

Use one scope to avoid duplicate checks. Replace the workspace path with the project the AI agent will work on.

Windows:

```powershell
.\.venv\Scripts\python.exe install_integrations.py --client antigravity-cli --project 'C:\Projects\MyApp'
.\.venv\Scripts\python.exe install_integrations.py --client opencode --project 'C:\Projects\MyApp'
```

macOS/Linux:

```sh
.venv/bin/python install_integrations.py --client antigravity-cli --project "$HOME/Projects/MyApp"
.venv/bin/python install_integrations.py --client opencode --project "$HOME/Projects/MyApp"
```

Project destinations are `.agents/hooks.json` and `.opencode/plugins/codeguard.js`. Old project-specific Antigravity settings can override global settings: update them using `--project` too if an old CodeGuard definition is present.

## 7. Verify the detector without executing input

The following commands send JSON text to the inspector. They do not execute the submitted code.

Windows:

```powershell
'{"code":"print(1)"}' | .\.venv\Scripts\python.exe -m guard evaluate
'{"toolCall":{"name":"run_command","args":{"CommandLine":"echo codeguard-check"}}}' | .\.venv\Scripts\python.exe -m guard agent-hook --client antigravity-cli
'{"tool":"bash","args":{"command":"echo codeguard-check"}}' | .\.venv\Scripts\python.exe -m guard agent-hook --client opencode
```

macOS/Linux:

```sh
printf '%s\n' '{"code":"print(1)"}' | .venv/bin/python -m guard evaluate
printf '%s\n' '{"toolCall":{"name":"run_command","args":{"CommandLine":"echo codeguard-check"}}}' | .venv/bin/python -m guard agent-hook --client antigravity-cli
printf '%s\n' '{"tool":"bash","args":{"command":"echo codeguard-check"}}' | .venv/bin/python -m guard agent-hook --client opencode
```

For these harmless examples, expect an `allow` verdict or decision. Hooks print their decision on stdout and diagnostic/audit details on stderr. The standalone evaluator uses exit code 2 for a block/error; native hooks communicate their decisions using JSON and can exit successfully while denying a command.

The current distribution does not include the earlier regression test files. The commands above are installation smoke checks; also verify activation and audit entries inside each client as described in section 6.

## 8. Start the HTTP endpoint and dashboard

The HTTP server is optional for the two native integrations; they call Python directly. Start it when you want the browser UI or HTTP API.

Windows:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8011
```

macOS/Linux:

```sh
.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8011
```

Keep that terminal running. Open:

- Dashboard: <http://127.0.0.1:8011/>
- API documentation: <http://127.0.0.1:8011/docs>
- Health endpoint: <http://127.0.0.1:8011/health>
- Audit viewer: <http://127.0.0.1:8011/audit>

The audit viewer reads the project's `reports/command-audit.jsonl`; it does not currently merge OpenCode's home-directory log. Use the commands below to read that log separately.

To stop the server, press `Ctrl+C`. The first inspection can be slower while the model initializes. Bind to `127.0.0.1` for local use; this service currently has no authentication layer and should not be exposed publicly without access controls.

### Call the API

Windows PowerShell:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8011/health'
Invoke-RestMethod -Uri 'http://127.0.0.1:8011/evaluate' -Method Post -ContentType 'application/json' -Body '{"idx":0,"code":"print(1)"}'
```

macOS/Linux:

```sh
curl http://127.0.0.1:8011/health
curl -X POST http://127.0.0.1:8011/evaluate -H 'Content-Type: application/json' -d '{"idx":0,"code":"print(1)"}'
```

## 9. Upload a dataset and download JSONL results

Create a UTF-8 file named `input.jsonl` with one JSON object on each line:

```jsonl
{"idx":0,"code":"print(1)"}
{"idx":1,"code":"print('hello')"}
```

1. Open the dashboard.
2. Choose the dataset file.
3. Click **Analyze file**.
4. Wait for the completion message.
5. Click **Download JSONL** beside the analysis button.

The download is `codeguard-report.jsonl`, with one result per line. Supplied `idx` values are preserved; missing IDs use a zero-based record position. The download button stays disabled while analysis is incomplete.

The upload API also accepts JSON and CSV, but a regular API report is a JSON object. Its `stream=true` mode emits progress events; that event stream is not the same as the dashboard's final result-only JSONL download. Unlabeled uploads cannot establish accuracy or recall.

## 10. Read audit logs

Windows:

```powershell
Get-Content .\reports\command-audit.jsonl -Tail 20
Get-Content "$HOME\.codeguard\command-audit.jsonl" -Tail 20
```

macOS/Linux:

```sh
tail -n 20 reports/command-audit.jsonl
tail -n 20 "$HOME/.codeguard/command-audit.jsonl"
```

Logs appear only after an inspected command produces an audit record. The first path is used by generated Antigravity settings; the second is the default for OpenCode and direct hook commands without `--audit-log`. A logging failure blocks the command. Keep logs private.

## 11. Troubleshooting

| Problem | What to do |
| --- | --- |
| `No module named guard` | Run installation from `codeguard` with the same virtual-environment Python used by the hook. `requirements.lock` includes `-e .`, which installs this project. |
| Python version rejected | Install Python 3.12+ and create a fresh environment with that interpreter. |
| Missing model | Restore `models/codeguard.joblib` from the trusted project distribution. Do not use an arbitrary downloaded Joblib file. |
| Package/model version error | Install `requirements.lock` in a fresh environment rather than mixing unrelated package versions. |
| `libomp`, `libgomp`, or LightGBM loading error | Install the OS/architecture-compatible OpenMP runtime. On macOS with Homebrew, this is commonly `brew install libomp`; on Debian/Ubuntu, `sudo apt-get install libgomp1`. Consult the LightGBM installation documentation for your platform. |
| No compatible dependency wheel | Use a supported Python/CPU combination or install the required native build tools. Universal architecture support is not established. |
| Hook still references an old location | Rerun `install_integrations.py` from the new environment; update any workspace override with `--project`. Restart the client. |
| No logs after an agent command | Confirm the hook/plugin loaded, the tool is one of the supported command tools, and the correct log path is being inspected. |
| OpenCode says inspector unavailable | Confirm the installed Python still exists and can run `-m guard --help`. Check any `CODEGUARD_PYTHON` override, then reinstall the plugin. |
| `CODEGUARD_PYTHON` is set | Its value must be one executable path, not `python -m guard` or another shell command. Remove an obsolete override before restarting. |
| Duplicate audit entries | Check for both project and global OpenCode installations, or a duplicate explicit plugin entry. Use one installation scope. |
| Port 8011 is busy | Start Uvicorn with `--port 8012` and use that port in the browser and API commands. |
| Terminal command is not blocked | Ordinary terminals outside the integrated agent or CodeGuard wrapper are not intercepted. Verify hook activation first. |

For platform-specific native dependencies, consult the [official LightGBM installation guide](https://lightgbm.readthedocs.io/en/stable/Installation-Guide.html).

## 12. Sharing the project as a ZIP

Include the source, `pyproject.toml`, requirements files, model files, UI, integration templates, installer scripts, and documentation.

Do not include `.venv`, `.git`, `.git.zip`, `.tools`, `__pycache__`, build output, private uploads, reports, credentials, or generated `.agents`/`.opencode` settings. Excluding files from Git does not automatically exclude them from a ZIP created in File Explorer; review the archive contents yourself.

Recipients must follow the setup steps on their computer. CodeGuard does not install itself when an archive is opened. Do not distribute an already-created virtual environment as a portable runtime.

## 13. What protection means

CodeGuard inspects the supported command calls before those clients execute them. It is not system-wide antivirus, an operating-system sandbox, or a guarantee that every unsafe command will be detected. It does not intercept unrelated terminals, arbitrary file writes, all MCP tools, or remote devices automatically. The host must load the integration, and the model can produce both false positives and false negatives.

For implementation details, read [the project README](codeguard/README.md), [integration notes](codeguard/integrations/README.md), and [the security policy](SECURITY.md).
