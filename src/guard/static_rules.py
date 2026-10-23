import ast
import io
import re
import tokenize

from guard.generic_rules import generic_findings, injection_offsets
from guard.patterns import INJECTION, SECRET_PATH, TOKEN, internal_url
from guard.python_rules import python_findings
from guard.schema import Finding
from guard.shell_rules import shell_findings
from guard.sql_rules import sql_findings


def analyze(code, language):
    findings = []
    strings = []
    tree = None
    if language == "python":
        try:
            tree = ast.parse(code)
            findings.extend(python_findings(tree))
            strings = [(node.value, node.lineno) for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        except (SyntaxError, ValueError, RecursionError):
            findings.append(Finding("obfuscated_execution", "Python could not be analyzed safely; execution is refused.", 1))
        try:
            comments = [(token.string, token.start[0]) for token in tokenize.generate_tokens(io.StringIO(code).readline) if token.type == tokenize.COMMENT]
        except (tokenize.TokenError, IndentationError):
            comments = []
        if comments:
            comment_lines = dict((line, text) for text, line in comments)
            strings.append(("\n".join(comment_lines.get(line, "") for line in range(1, len(code.splitlines()) + 1)), 1))
    if language == "sql":
        findings.extend(sql_findings(code))
    if language in {"bash", "yaml"}:
        findings.extend(shell_findings(code))
    if language != "python":
        strings.append((code, 1))
    for text, line in strings:
        starts = sorted({match.start() for match in INJECTION.finditer(text)} | set(injection_offsets(text)))
        for start in starts:
            findings.append(Finding("ai_targeted_instructions", "Text attempts to override an AI reader's instructions or suppress security review.", line + text[:start].count("\n")))
    if language == "javascript":
        for line, text in enumerate(code.splitlines(), 1):
            if TOKEN.search(text):
                findings.append(Finding("secret_access", "Source embeds a credential-like token.", line))
            if re.search(r"\b(?:eval|Function)\s*\(|\batob\s*\(", text):
                findings.append(Finding("obfuscated_execution", "JavaScript dynamically evaluates or decodes instructions.", line))
            if re.search(r"\b(?:exec|execSync|spawnSync)\s*\(", text):
                commands = re.findall(r"\b(?:exec|execSync|spawnSync)\s*\(\s*(['\"])(.*?)\1", text)
                for _, command in commands:
                    findings.extend(shell_findings(command, line))
                if not commands:
                    findings.append(Finding("destructive_command", "JavaScript passes dynamic input to a process execution API.", line))
            if SECRET_PATH.search(text) and re.search(r"readFile(?:Sync)?\s*\(", text):
                findings.append(Finding("secret_access", "JavaScript reads a protected credential file.", line))
            for url in re.findall(r"(?:https?|gopher|dict|file)://[^\s'\"`<>]+", text):
                if internal_url(url):
                    findings.append(Finding("ssrf_network_exfil", "Source references a metadata endpoint, internal service, or unsafe URL scheme.", line))
    findings.extend(generic_findings(code))
    return list(dict.fromkeys(findings))
