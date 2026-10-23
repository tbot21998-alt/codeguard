"""Check the complete Git index for common accidental publication hazards."""

import re
import subprocess
from pathlib import PurePosixPath


PRIVATE_DIRS = {"data", "reports", "uploads", ".aws", ".ssh", ".azure", ".gcloud", ".kube", ".agents", ".codex", "malware-samples", "payloads", ".venv", "__pycache__"}
PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".log", ".dmp", ".exe", ".dll", ".so", ".dylib", ".msi", ".scr", ".com", ".zip", ".7z", ".rar"}
SECRET_PATTERNS = {
    "private key": rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "GitHub token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{70,})\b",
    "AWS access key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "OpenAI project key": rb"\bsk-proj-[A-Za-z0-9_-]{40,}",
    "Slack token": rb"\bxox[baprs]-[A-Za-z0-9-]{20,}",
    "Google API key": rb"\bAIza[A-Za-z0-9_-]{35}",
    "credential assignment needing review": rb"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|password)\s*[=:]\s*[\x22\x27][^\x22\x27\r\n]{16,}[\x22\x27]",
}


def inspect_file(name, content):
    path = PurePosixPath(name.lower())
    basename = path.name
    if (PRIVATE_DIRS.intersection(path.parts) or path.suffix in PRIVATE_SUFFIXES
            or basename in {".env", ".npmrc", ".pypirc", "credentials.json"}
            or (basename.startswith(".env.") and basename != ".env.example")
            or (basename.startswith("service-account") and path.suffix == ".json")
            or (basename.startswith("codeguard-report") and path.suffix in {".json", ".jsonl"})):
        return ["private data, credentials, archive, or executable publication path"]
    if name in {"models/codeguard.joblib", "codeguard/models/codeguard.joblib"}:
        return []
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        content = content.decode("utf-16").encode("utf-8")
    if b"\0" in content:
        return ["unreviewed binary content"]
    return [label for label, pattern in SECRET_PATTERNS.items() if re.search(pattern, content)]


def main():
    root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()
    entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
    failures = []
    scanned = 0
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, filename = entry.split(b"\t", 1)
        mode, oid, stage = metadata.split()
        name = filename.decode("utf-8", errors="replace")
        if stage != b"0" or mode not in {b"100644", b"100755"}:
            failures.append((name, "unmerged entry, symbolic link, or embedded repository needs review"))
            continue
        content = subprocess.check_output(["git", "cat-file", "blob", oid.decode()], cwd=root)
        scanned += 1
        failures.extend((name, issue) for issue in inspect_file(name, content))
    for name, issue in failures:
        print(f"BLOCK: {name}: {issue}")
    print(f"Checked {scanned} indexed files; {len(failures)} finding(s). Credential values are never printed.")
    print("Scope: staged snapshot only. History, model internals, malware behavior, and GitHub account status are not certified.")
    print("The existing model artifact is permitted by path, not validated as safe by this check.")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
