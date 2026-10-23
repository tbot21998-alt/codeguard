@echo off
setlocal
set "CODEGUARD_RUNTIME=%~dp0.venv\Scripts\python.exe"
if defined CODEGUARD_PYTHON set "CODEGUARD_RUNTIME=%CODEGUARD_PYTHON%"
if not exist "%CODEGUARD_RUNTIME%" (
  echo {"decision":"deny","reason":"CodeGuard: Python environment missing. Install requirements or set CODEGUARD_PYTHON."}
  exit /b 0
)
"%CODEGUARD_RUNTIME%" -m guard agent-hook --client antigravity-cli --audit-log "%~dp0reports\command-audit.jsonl"
if errorlevel 1 echo {"decision":"deny","reason":"CodeGuard: Inspector failed; execution blocked."}
