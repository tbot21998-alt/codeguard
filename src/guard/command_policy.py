import re
import shlex


def command_source(argv, depth=0):
    if depth > 8:
        raise ValueError("Command wrapper nesting exceeds the inspection limit")
    if not argv or not argv[0] or any(not isinstance(arg, str) or "\0" in arg for arg in argv):
        raise ValueError("Command arguments must be strings without NUL bytes and name an executable")
    executable = argv[0].strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    assignment = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argv[0]) is not None
    if executable in {"env", "sudo", "command", "exec", "nohup"} or assignment:
        candidates = argv if assignment else argv[1:]
        index = next((i for i, value in enumerate(candidates) if not value.startswith("-") and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", value)), None)
        if index is None:
            raise ValueError("Command wrapper has no inspectable executable")
        safe_options = {"-i", "--ignore-environment", "-n", "-H", "-E", "--"}
        if any(value.startswith("-") and value not in safe_options for value in candidates[:index]):
            raise ValueError("Command wrapper options could hide an uninspected executable")
        command_source(candidates[index:], depth + 1)
        return shlex.join(argv), "bash"
    python = re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?|py", executable) is not None
    settings = ("python", {"-c"}, {"-u", "-B", "-E", "-I", "-O", "-OO", "-s", "-S", "-q", "-b", "-bb", "-d"}) if python else {
        "node": ("javascript", {"-e", "--eval"}, {"--no-warnings", "--trace-warnings", "--use-strict"}),
        "bash": ("bash", {"-c"}, {"--noprofile", "--norc", "-e", "-u", "-x", "-v"}),
        "sh": ("bash", {"-c"}, {"-e", "-u", "-x", "-v"}),
        "zsh": ("bash", {"-c"}, {"-f", "-e", "-u", "-x"}),
        "powershell": ("bash", {"-command"}, {"-nologo", "-noprofile", "-noninteractive"}),
        "pwsh": ("bash", {"-command"}, {"-nologo", "-noprofile", "-noninteractive"}),
        "cmd": ("bash", {"/c"}, {"/d", "/q", "/s"}),
    }.get(executable)
    if settings is None:
        return shlex.join(argv), "bash"
    language, source_flags, safe_flags = settings
    normalized = [value.lower() if executable in {"powershell", "pwsh", "cmd"} else value for value in argv]
    index = next((i for i, value in enumerate(normalized[1:], 1) if value in source_flags), None)
    if index is None or index + 1 >= len(argv):
        raise ValueError("Interpreter execution requires inspectable inline source; script files, modules and interactive sessions are blocked")
    if any(value not in safe_flags for value in normalized[1:index]):
        raise ValueError("Interpreter options before inline source could execute an uninspected script, module or preload")
    if executable == "node":
        trailing = argv[index + 2:]
        options = trailing[:trailing.index("--")] if "--" in trailing else trailing
        if any(value.startswith("-") for value in options):
            raise ValueError("Node options after inline source can preload uninspected code; put ordinary program arguments after --")
    source = " ".join(argv[index + 1:]) if executable in {"powershell", "pwsh", "cmd"} else argv[index + 1]
    if not source.strip() or source == "-":
        raise ValueError("Interpreter source from standard input cannot be inspected")
    return source, language


def validate_command_text(command, depth=0):
    if depth > 8:
        raise ValueError("Nested interpreter command exceeds the inspection limit")
    for line in command.splitlines():
        lexer = shlex.shlex(line, posix=False, punctuation_chars=";&|")
        lexer.whitespace_split = True
        segments = list(lexer)
        current = []
        for token in segments + [";"]:
            if token and all(character in ";&|" for character in token):
                if current:
                    source, language = command_source(current)
                    if language == "bash" and source != shlex.join(current):
                        validate_command_text(source, depth + 1)
                current = []
                continue
            current.append(token[1:-1] if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'" else token)
