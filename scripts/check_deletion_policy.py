"""Regression checks for deletion bypasses; no submitted command is executed."""
from guard.agent_hooks import handle_event
from guard.detector import evaluate


DENIED = [
    "git rm demo/audit.html demo/dashboard.html demo/intercept_check.py",
    "git -C . rm -rf demo", "git -c core.autocrlf=false rm -- demo/audit.html",
    "git --git-dir=.git --work-tree=. rm demo/audit.html",
    '"C:/Program Files/Git/cmd/git.exe" rm demo/audit.html',
    "git rm -- demo/--cached", "git status && git rm demo/audit.html",
    "git rm demo/audit.html; git rm --cached demo/dashboard.html",
    "git rm demo/audit.html && git rm -n demo/dashboard.html",
    "git rm demo/audit.html\ngit status", "rm demo/audit.html", "unlink demo/audit.html",
    "Remove-Item demo/audit.html", "ri demo -Recurse", "del demo\\audit.html",
    "del README.md", "erase demo", "rd demo",
    "cmd /c del demo\\audit.html", 'powershell -Command "Remove-Item demo/audit.html"',
    'bash -c "git rm demo/audit.html"', "Get-ChildItem demo | Remove-Item -Force",
    "find demo -type f -delete", "find demo -exec rm {} +", "find demo | xargs rm",
]
ALLOWED = ["echo hello", "git status", "git diff", "git log -1", "git ls-files",
           "git rm --cached demo/audit.html", "git rm -n demo/audit.html",
           "git rm --dry-run demo/audit.html", "echo git rm demo/audit.html"]


def main():
    checks = 0
    for expected, cases in [("deny", DENIED), ("allow", ALLOWED)]:
        for command in cases:
            verdict = evaluate(command, language="bash", use_model=False)
            assert verdict.verdict == ("block" if expected == "deny" else "allow"), (command, verdict)
            if expected == "deny":
                assert "destructive_command" in verdict.categories, (command, verdict)
            for client in ["antigravity-cli", "opencode"]:
                event = {"toolCall": {"name": "run_command", "args": {"CommandLine": command}}} if client == "antigravity-cli" else {"tool": "bash", "args": {"command": command}}
                output, report = handle_event(client, event, lambda source: evaluate(source, language="bash", use_model=False).model_dump())
                assert output["decision"] == expected, (command, client, output)
                assert report["command"] == command, (command, report)
                checks += 1
    print(f"Passed: {len(DENIED) + len(ALLOWED)} detector cases and {checks} adapter decisions.")


if __name__ == "__main__":
    main()
