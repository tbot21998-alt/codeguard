import re
import shlex

from guard.generic_rules import SAFE_RM_TARGET
from guard.patterns import PERSISTENCE_PATH, SECRET_PATH, internal_url, risky_package
from guard.schema import Finding


def deletion_reason(command):
    """Recognize deletion operations by executable/arguments, including Git globals."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        words = list(lexer)
    except ValueError:
        words = command.split()
    for position, word in enumerate(words):
        executable = word.strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        if executable != "git":
            continue
        arguments = words[position + 1:]
        boundary = next((i for i, value in enumerate(arguments) if value and all(c in ";&|" for c in value)), len(arguments))
        arguments = arguments[:boundary]
        index = 0
        while index < len(arguments):
            option = arguments[index]
            if option in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path"}:
                index += 2
            elif option.startswith("-"):
                index += 1
            else:
                break
        if index < len(arguments) and arguments[index] == "rm":
            options = arguments[index + 1:]
            options = options[:options.index("--")] if "--" in options else options
            if "--cached" not in options and "--dry-run" not in options and not any(
                item.startswith("-") and not item.startswith("--") and "n" in item[1:] for item in options
            ):
                return "Git rm deletes tracked working-tree files. Deletion is blocked; do not retry with another removal tool."
    return None


def shell_findings(command, line=1):
    findings = []
    for offset, raw in enumerate(command.splitlines()):
        current = raw.strip()
        if not current or current.startswith("#"):
            continue
        try:
            words = shlex.split(current, comments=True)
        except ValueError:
            words = current.split()
        if not words:
            continue
        if words[0] in {"echo", "printf"} and not re.search(r"[|;>]|\$\(|`", current):
            continue
        for position, word in enumerate(words):
            executable = word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
            if executable not in {"python", "python3", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14", "py", "bash", "sh", "zsh", "node", "cmd", "powershell", "pwsh"}:
                continue
            index = next((i + 1 for i in range(position + 1, min(position + 5, len(words) - 1)) if words[i].lower() in {"-c", "-e", "--eval", "/c", "-command"}), None)
            if index is not None:
                from guard.static_rules import analyze
                language = "python" if executable.startswith("python") or executable == "py" else "javascript" if executable == "node" else "bash"
                source = " ".join(words[index:]) if executable in {"cmd", "powershell", "pwsh"} else words[index]
                nested = analyze(source, language)
                findings.extend(Finding(item.category, item.reason, line + offset, item.score) for item in nested)
        normalized = " ".join(words)
        def add(category, reason):
            findings.append(Finding(category, reason, line + offset))
        removal = deletion_reason(current)
        if removal:
            add("destructive_command", removal)
        if re.search(r"(?:^|[;&|]\s*)(?:(?:sudo|command|exec|nohup)\s+)*(?:/\S*/)?(?:rm|unlink)\s+", normalized, re.I):
            add("destructive_command", "File removal can delete project data, even without recursive flags.")
        if re.search(r"(?:^|[;&|]\s*)(?:Remove-Item|ri|del|erase|rmdir|rd)\s+", normalized, re.I):
            add("destructive_command", "File or directory deletion is blocked, including PowerShell and Windows removal aliases.")
        if re.search(r"\bfind\s+[^\n]*(?:-delete\b|-exec\s+(?:\S*/)?(?:rm|unlink)\b)", normalized):
            add("destructive_command", "Find deletes project files directly or through another removal command.")
        if re.search(r"\bxargs\s+[^\n]*\b(?:rm|unlink|rmdir)\b", normalized):
            add("destructive_command", "Xargs passes file names to a removal command.")
        if re.search(r"(?:^|[;&|]\s*|\s)(?:sudo\s+)?(?:/\S*/)?rm\s+[^;&|]*", normalized):
            rm_part = re.split(r"\brm\s+", normalized, maxsplit=1)[-1]
            targets = [part for part in rm_part.split() if not part.startswith("-")]
            if re.search(r"(?:^|\s)(?:-[A-Za-z]*[rR]|--recursive)", rm_part) and not (targets and all(SAFE_RM_TARGET.match(part) for part in targets)):
                add("destructive_command", "Recursive removal can destroy filesystem data.")
        if re.search(r"\bgit\s+(?:checkout\s+(?:[^;&|]*\s)?--(?:\s|$)|restore\s+(?!--staged\b)|reset\s+[^;&|]*--hard\b|clean\s+[^;&|]*-[A-Za-z]*f|stash\s+(?:drop|clear)\b|push\s+[^;&|]*(?:--force\b|-f\b))", normalized):
            add("destructive_command", "Rule: destructive_command. Git command discards work irreversibly; do not retry. Use 'git stash' instead.")
        if re.search(r"\b(?:mkfs(?:\.[\w]+)?|format\s+[a-z]:|diskpart)\b|\bdd\b[^;]*\bof=/dev/(?:sd|hd|nvme|vd)|\b(?:Remove-Item|del|rmdir)\b[^;]*(?:-Recurse|/s)", normalized, re.I):
            add("destructive_command", "Command formats a device or recursively removes data.")
        if SECRET_PATH.search(normalized) and re.search(r"\b(?:cat|head|tail|less|more|cp|scp|curl|wget|Get-Content|type|base64)\b|<", normalized, re.I):
            add("secret_access", "Command reads a protected credential or account file.")
        if PERSISTENCE_PATH.search(normalized) and re.search(r">|\b(?:tee|cp|mv|install|Set-Content|Add-Content)\b", normalized, re.I):
            add("persistence_or_privesc", "Command writes a startup, authorization, or privileged configuration file.")
        if re.search(r"\bsystemctl\s+(?:daemon-reload|enable)|\bNOPASSWD\s*:\s*ALL|\bcrontab\s+(?!-l\b|-h\b|--help\b)\S", normalized):
            add("persistence_or_privesc", "Command changes scheduled execution or privilege policy.")
        if re.search(r"\bdd\b.*\bif=/dev/(?:zero|urandom)", normalized) and not re.search(r"\bcount=\d+", normalized):
            add("resource_exhaustion", "Unbounded device copy can fill storage.")
        if re.search(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&", current) or re.search(r"\bwhile\s+(?:true|:)\s*;?\s*do\b", normalized):
            add("resource_exhaustion", "Unbounded shell loop or fork bomb consumes resources.")
        if re.search(r"\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b|\bbase64\b.*\|\s*(?:ba)?sh\b|\beval\s+.*(?:base64|\$\()", normalized):
            add("obfuscated_execution", "Command executes fetched or decoded instructions.")
        if re.search(r"\b(?:curl|wget|nc|ncat|scp)\b", normalized) and (SECRET_PATH.search(normalized) or re.search(r"(?:--data(?:-binary)?|-d)\s+@|\b(?:env|printenv)\b.*\|", normalized)):
            add("data_exfiltration", "Command sends local file or environment data over a network.")
        for word in words:
            if internal_url(word):
                add("ssrf_network_exfil", "Command targets a metadata endpoint, internal service, or unsafe URL scheme.")
        install = re.search(r"\b(?:pip\d*|npm|pnpm|yarn)\s+(?:install|add)\s+(.+)", normalized)
        if install:
            for spec in install[1].split():
                reason = risky_package(spec)
                if reason:
                    add("dependency_risk", reason)
    return findings
