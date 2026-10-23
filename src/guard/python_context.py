import ast


class PythonContext:
    def __init__(self, tree):
        self.nodes = list(ast.walk(tree))
        self.calls = [node for node in self.nodes if isinstance(node, ast.Call)]
        self.aliases = {}
        self.bindings = {}
        for node in self.nodes:
            if isinstance(node, ast.Import):
                self.aliases.update({alias.asname or alias.name: alias.name for alias in node.names})
            if isinstance(node, ast.ImportFrom):
                self.aliases.update({alias.asname or alias.name: f"{node.module}.{alias.name}" for alias in node.names})
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.bindings.setdefault(target.id, []).append(node.value)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
                self.bindings.setdefault(node.target.id, []).append(node.value)

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self.name(node.value)}.{node.attr}"
        return ""

    def resolve(self, node, depth=0):
        if depth >= 8:
            return node
        if isinstance(node, ast.Name) and len(self.bindings.get(node.id, [])) == 1:
            return self.resolve(self.bindings[node.id][0], depth + 1)
        return node

    def literal(self, node, depth=0):
        if depth >= 8:
            return None
        node = self.resolve(node)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self.literal(item, depth + 1) for item in node.elts]
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            left = self.literal(node.left, depth + 1)
            right = self.literal(node.right, depth + 1)
            if isinstance(left, str) and isinstance(right, str):
                return left + ("/" if isinstance(node.op, ast.Div) else "") + right
        if isinstance(node, ast.JoinedStr):
            values = [self.literal(item.value if isinstance(item, ast.FormattedValue) else item, depth + 1) for item in node.values]
            if all(isinstance(item, (str, int, float)) for item in values):
                return "".join(map(str, values))
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            if name in {"str", "Path", "pathlib.Path", "os.path.expanduser", "os.path.expandvars"} and node.args:
                return self.literal(node.args[0], depth + 1)
            if name == "os.path.join":
                values = [self.literal(arg, depth + 1) for arg in node.args]
                if all(isinstance(item, str) for item in values):
                    return "/".join(values)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"expanduser", "resolve"}:
                return self.literal(node.func.value, depth + 1)
        return None

    def text(self, node):
        value = self.literal(node)
        if isinstance(value, list):
            return " ".join(str(item) if item is not None else "{dynamic}" for item in value)
        if isinstance(value, str):
            return value
        node = self.resolve(node)
        if isinstance(node, ast.JoinedStr):
            return "".join(item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else "{dynamic}" for item in node.values)
        if isinstance(node, ast.BinOp):
            return self.text(node.left)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return self.text(node.func.value)
        return ""
