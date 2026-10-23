"""Plain-language explanations for each threat category (what it is, why it matters, what to do)."""

EXPLANATIONS = {
    "secret_access": {
        "title": "Reads secrets",
        "what": "This code reads a password, key, token or credential file.",
        "why": "Secrets give whoever holds them access to your accounts and servers. Code you did not write should not touch them.",
        "fix": "Remove the secret access, or pass only the one value that is really needed through a safe, approved route.",
    },
    "data_exfiltration": {
        "title": "Sends data out",
        "what": "This code reads local data and sends it to another machine.",
        "why": "Files, databases or environment variables can leave your computer without you noticing.",
        "fix": "Only send data you chose to share, to a destination you trust, and review exactly what is sent.",
    },
    "destructive_command": {
        "title": "Deletes or damages data",
        "what": "This code can delete files, wipe a disk, or change every row in a database.",
        "why": "The damage is often permanent and there may be no way to undo it.",
        "fix": "Limit it to one specific folder or table, add a WHERE condition, and keep a backup first.",
    },
    "persistence_or_privesc": {
        "title": "Stays behind or gains more power",
        "what": "This code sets itself up to run again later, or gives someone higher privileges.",
        "why": "Attackers use this to keep access after the first run and to take over the whole machine.",
        "fix": "Do not change startup jobs, user accounts, sudo rules or login keys from generated code.",
    },
    "obfuscated_execution": {
        "title": "Hides what it runs",
        "what": "This code decodes, downloads or unpacks something and then runs it.",
        "why": "You cannot see what will actually run, so harmful behavior can be hidden inside.",
        "fix": "Replace it with plain, readable code. Never run content that is decoded or downloaded on the fly.",
    },
    "dependency_risk": {
        "title": "Risky package install",
        "what": "This code installs a package from an unusual place or one with a name close to a popular package.",
        "why": "Look-alike or untrusted packages are a common way to slip malware into a project.",
        "fix": "Check the exact name, pin the version, and install only from the official registry.",
    },
    "resource_exhaustion": {
        "title": "Can freeze the machine",
        "what": "This code can run forever or use up memory, CPU, disk or processes.",
        "why": "It can slow down or crash the computer or a shared server.",
        "fix": "Add a stop condition, a time limit, and a cap on size or number of workers.",
    },
    "ssrf_network_exfil": {
        "title": "Reaches internal systems",
        "what": "This code connects to an internal address, such as cloud credentials, a private network or the local machine.",
        "why": "Those services are not meant to be reached by outside code and can hand out secrets or control.",
        "fix": "Allow only the public hosts you expect and block internal and special addresses.",
    },
    "ai_targeted_instructions": {
        "title": "Tries to trick the AI reviewer",
        "what": "This text tells an AI assistant to ignore its rules, skip checks, or approve the code.",
        "why": "It is an attempt to get harmful code past automated review.",
        "fix": "Remove the instruction text. Real code does not need to talk to the reviewer.",
    },
}


def explain_category(category):
    return EXPLANATIONS.get(category, {"title": category.replace("_", " ").capitalize(), "what": "A risky pattern was found.", "why": "It may harm your system or data.", "fix": "Review it before running."})


def explanations_for(findings, code_lines, categories, reason):
    """One short entry per flagged line (or per category when the model flagged it without a line)."""
    entries, seen = [], set()
    for item in findings:
        key = (item.category, item.line)
        if key in seen:
            continue
        seen.add(key)
        info = explain_category(item.category)
        source = code_lines[item.line - 1].strip() if 1 <= item.line <= len(code_lines) else None
        entries.append({"category": item.category, "title": info["title"], "line": item.line, "code": source, "detail": item.reason,
                        "what": info["what"], "why": info["why"], "fix": info["fix"]})
    if not entries:
        for category in categories:
            info = explain_category(category)
            entries.append({"category": category, "title": info["title"], "line": None, "code": None, "detail": reason,
                            "what": info["what"], "why": info["why"], "fix": info["fix"]})
    return entries
