import ast
import re

from guard.patterns import PERSISTENCE_PATH, SECRET_PATH, TOKEN, internal_url, risky_package
from guard.python_context import PythonContext
from guard.schema import Finding
from guard.shell_rules import shell_findings
from guard.sql_rules import sql_findings

PROCESS_CALLS = {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen", "asyncio.create_subprocess_shell"}
DESERIALIZERS = {"pickle.load", "pickle.loads", "marshal.loads", "shelve.open", "yaml.unsafe_load", "dill.loads", "dill.load", "jsonpickle.decode"}


def python_findings(tree):
    ctx = PythonContext(tree)
    findings = []
    names = {ctx.name(call.func) for call in ctx.calls}
    strings = [node for node in ctx.nodes if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    source_lines = []
    sinks = []
    installs = []
    has_decoder = any(name in {"compile", "__import__", "importlib.import_module", "base64.b64decode", "base64.urlsafe_b64decode", "inspect.getsource"} for name in names)
    for node in ctx.nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = ctx.literal(node.value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(value, str) and "\n" not in value and (TOKEN.search(value) or any(re.search(r"(?:aws_secret_access_key|api_key|access_token|client_secret|password)$", ctx.name(target), re.I) for target in targets) and len(value) >= 16):
                findings.append(Finding("secret_access", "Assignment embeds a credential-like token in source.", node.lineno))
        if isinstance(node, ast.Attribute) and ctx.name(node) == "os.environ":
            source_lines.append(node.lineno)
        if isinstance(node, ast.Subscript) and ctx.name(node.value) == "os.environ":
            key = ctx.literal(node.slice)
            if isinstance(key, str) and re.search(r"SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY", key, re.I):
                findings.append(Finding("secret_access", "Reads a sensitive environment variable.", node.lineno))
    for call in ctx.calls:
        name = ctx.name(call.func)
        argument = ctx.text(call.args[0]) if call.args else ""
        if name in PROCESS_CALLS:
            findings.extend(shell_findings(argument, call.lineno))
            shell = any(keyword.arg == "shell" and ctx.literal(keyword.value) is True for keyword in call.keywords)
            if shell and call.args and ctx.literal(call.args[0]) is None:
                findings.append(Finding("destructive_command", "Dynamic input reaches a shell-enabled subprocess.", call.lineno))
            if name in {"os.system", "os.popen"} and call.args and ctx.literal(call.args[0]) is None:
                findings.append(Finding("destructive_command", "Runtime input reaches a shell interpreter.", call.lineno))
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and ctx.aliases.get(call.func.value.id) in {"os", "subprocess"} and call.func.value.id not in {"os", "subprocess"}:
                findings.append(Finding("obfuscated_execution", "An aliased process API executes a command.", call.lineno))
            if re.search(r"\b(?:pip\d*|npm|pnpm|yarn)\s+(?:install|add)\b", argument):
                installs.append(call)
            if re.search(r"\b(?:ping|curl|wget|nc|scp)\b", argument):
                sinks.append(call.lineno)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            findings.append(Finding("obfuscated_execution" if has_decoder else "destructive_command", "Dynamic code execution can run instructions unavailable to static analysis.", call.lineno))
        if name in DESERIALIZERS or name == "yaml.load" and not any("SafeLoader" in ast.unparse(keyword.value) for keyword in call.keywords):
            findings.append(Finding("obfuscated_execution", "Unsafe deserialization can execute embedded code.", call.lineno))
        if name in {"__import__", "importlib.import_module"} and (ctx.literal(call.args[0]) is None if call.args else True):
            findings.append(Finding("obfuscated_execution", "Runtime module resolution conceals executable dependencies.", call.lineno))
        if name in {"os.getenv", "os.environ.get"} and re.search(r"SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY", argument, re.I):
            findings.append(Finding("secret_access", "Reads a sensitive environment variable.", call.lineno))
            source_lines.append(call.lineno)
        path = argument
        mode = next((ctx.literal(keyword.value) for keyword in call.keywords if keyword.arg == "mode"), ctx.literal(call.args[1]) if len(call.args) > 1 else "r")
        is_open = name in {"open", "io.open"} or isinstance(call.func, ast.Attribute) and call.func.attr == "open"
        method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        if isinstance(call.func, ast.Attribute) and method in {"read_text", "read_bytes", "write_text", "write_bytes", "open"} and name not in {"io.open", "shelve.open"}:
            path = ctx.text(call.func.value)
            if method == "open":
                mode = ctx.literal(call.args[0]) if call.args else "r"
        reading = is_open and (not isinstance(mode, str) or "r" in mode or "+" in mode) or method in {"read_text", "read_bytes"}
        writing = is_open and isinstance(mode, str) and any(flag in mode for flag in "wax+") or method in {"write_text", "write_bytes"}
        if reading:
            source_lines.append(call.lineno)
        if reading and SECRET_PATH.search(path):
            findings.append(Finding("secret_access", "Reads a protected credential or account file.", call.lineno))
        if writing and PERSISTENCE_PATH.search(path):
            findings.append(Finding("persistence_or_privesc", "Writes startup, authorization, or privileged configuration.", call.lineno))
        if re.match(r"(?:requests|httpx|urllib\.request|aiohttp)\.", name) or method in {"send", "sendall", "sendto"}:
            sinks.append(call.lineno)
            for arg in call.args:
                if internal_url(ctx.text(arg)):
                    findings.append(Finding("ssrf_network_exfil", "Network request targets metadata, an internal service, or an unsafe URL scheme.", call.lineno))
        if method in {"execute", "executemany", "executescript"} and call.args:
            query_node = ctx.resolve(call.args[0])
            interpolated = isinstance(query_node, (ast.JoinedStr, ast.BinOp)) or isinstance(query_node, ast.Call) and isinstance(query_node.func, ast.Attribute) and query_node.func.attr == "format"
            findings.extend(sql_findings(argument, call.lineno, interpolated and ctx.literal(query_node) is None))
    if sinks and source_lines:
        findings.append(Finding("data_exfiltration", "Local file or environment data and an outbound sink coexist; review the data flow.", min(sinks)))
    if installs:
        for string in strings:
            reason = risky_package(string.value)
            if reason:
                findings.append(Finding("dependency_risk", reason, string.lineno))
    if any(reading_name in names for reading_name in {"open", "io.open"}) and any(SECRET_PATH.search(string.value) for string in strings):
        for string in strings:
            if SECRET_PATH.search(string.value):
                findings.append(Finding("secret_access", "Sensitive path is supplied to code that opens local files.", string.lineno))
    for node in ctx.nodes:
        if isinstance(node, ast.While) and (lambda v: isinstance(v, (bool, int)) and v in (True, 1))(ctx.literal(node.test)) and not any(isinstance(child, (ast.Break, ast.Return, ast.Raise, ast.Await)) or isinstance(child, ast.Call) and ctx.name(child.func) in {"time.sleep", "asyncio.sleep"} for child in ast.walk(node)):
            findings.append(Finding("resource_exhaustion", "Unbounded loop has no visible exit or yielding operation.", node.lineno))
        if isinstance(node, (ast.For, ast.While, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            children = list(ast.walk(node))
            child_calls = [child for child in children if isinstance(child, ast.Call)]
            if any(ctx.name(child.func) == "os.fork" for child in child_calls):
                findings.append(Finding("resource_exhaustion", "Loop repeatedly forks processes.", node.lineno))
            large_range = any(ctx.name(child.func) == "range" and any(isinstance(ctx.literal(arg), int) and ctx.literal(arg) > 100 for arg in child.args) for child in child_calls)
            allocates = any(ctx.name(child.func) in {"threading.Thread", "socket.socket", "multiprocessing.Process"} for child in child_calls)
            if large_range and allocates:
                findings.append(Finding("resource_exhaustion", "Loop creates more than 100 threads, processes, or sockets.", node.lineno))
    findings.extend(_semantic_findings(ctx))
    return findings


def _int_value(node, depth=0):
    if depth > 6:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp):
        left, right = _int_value(node.left, depth + 1), _int_value(node.right, depth + 1)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Pow) and 0 <= right <= 64 and abs(left) <= 10**6:
            return left ** right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.LShift) and 0 <= right <= 128:
            return left << right
    return None


REMOVERS = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree", "shutil.move"}
SAFE_PREFIXES = ("/tmp/", "/var/tmp/")
REGEX_FUNCS = {"re.match", "re.search", "re.fullmatch", "re.compile", "re.sub", "re.findall", "re.split"}
NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()]*)\)[+*{]|\(\.\*\)[*+]|\([^()]*\|[^()]*\)[+*]\$")


def _semantic_findings(ctx):
    findings = []
    tainted = set()
    for node in ctx.nodes:
        if isinstance(node, ast.Assign):
            if any(_is_request_input(ctx, child) for child in ast.walk(node.value)):
                tainted.update(target.id for target in node.targets if isinstance(target, ast.Name))
    for call in ctx.calls:
        name = ctx.name(call.func)
        first = call.args[0] if call.args else None
        text = ctx.text(first) if first is not None else ""
        if name in REMOVERS and first is not None and re.match(r"(?:/|~|[A-Za-z]:[\\/])", text) and not text.startswith(SAFE_PREFIXES):
            findings.append(Finding("destructive_command", "Deletes files or directories outside a temporary location.", call.lineno))
        if name in {"__import__", "importlib.import_module"} and isinstance(first, (ast.BinOp, ast.JoinedStr, ast.Call)):
            findings.append(Finding("obfuscated_execution", "Module name is assembled at runtime to hide what is imported.", call.lineno))
        if name in {"os.setuid", "os.setgid", "os.seteuid", "os.setresuid"} and first is not None and ctx.literal(first) == 0:
            findings.append(Finding("persistence_or_privesc", "Switches the process to root.", call.lineno))
        if name in REGEX_FUNCS and first is not None and NESTED_QUANTIFIER.search(ctx.literal(first) if isinstance(ctx.literal(first), str) else ""):
            findings.append(Finding("resource_exhaustion", "Regular expression with nested quantifiers can backtrack catastrophically.", call.lineno))
        if name in {"bytearray", "list", "range"} and first is not None and isinstance(_int_value(first), int) and _int_value(first) >= 10**9:
            findings.append(Finding("resource_exhaustion", "Allocates or iterates an enormous number of items.", call.lineno))
        if name in {"requests.get", "requests.post", "requests.request", "requests.head", "httpx.get", "httpx.post", "urllib.request.urlopen", "urllib.request.Request"} and first is not None:
            if any(_is_request_input(ctx, child) or isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(first)):
                findings.append(Finding("ssrf_network_exfil", "A URL taken from request input is fetched server-side without validation.", call.lineno))
    for node in ctx.nodes:
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.LShift)):
            sides = (node.left, node.right)
            repeats = any(isinstance(side, ast.Constant) and isinstance(side.value, (str, bytes)) or isinstance(side, (ast.List, ast.Tuple)) for side in sides)
            size = [_int_value(side) for side in sides if _int_value(side) is not None]
            if repeats and size and max(size) >= 10**9:
                findings.append(Finding("resource_exhaustion", "Builds an enormous in-memory sequence.", node.lineno))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = [child for child in ast.walk(node) if child is not node]
            calls_self = any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == node.name for child in inner)
            guarded = any(isinstance(child, (ast.If, ast.IfExp, ast.Try, ast.While, ast.For, ast.Match, ast.BoolOp)) for child in inner)
            if calls_self and not guarded:
                findings.append(Finding("resource_exhaustion", "Function recurses unconditionally and will exhaust the stack.", node.lineno))
    return findings


def _is_request_input(ctx, node):
    if isinstance(node, (ast.Attribute, ast.Name)):
        return re.match(r"(?:flask\.)?request\.(?:args|form|values|json|data|GET|POST|get_json)|sys\.argv", ctx.name(node)) is not None
    if isinstance(node, ast.Call):
        return ctx.name(node.func) == "input"
    return False