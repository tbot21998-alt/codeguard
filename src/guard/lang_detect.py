import ast
import re


def detect_language(code):
    stripped = code.lstrip()
    if re.match(r"#![^\n]*\b(?:ba|z|k)?sh\b", stripped):
        return "bash"
    if re.match(r"#![^\n]*python", stripped):
        return "python"
    if re.match(r"(?:sudo\s+)?(?:rm\s+[-/]|dd\s+if=|(?:cat|head|tail|curl|wget|pip\d*|npm|git|echo|printf)\s+(?![=]))", stripped):
        return "bash"
    if re.match(r"(?:fetch|require|console\.\w+)\s*\(", stripped):
        return "javascript"
    try:
        tree = ast.parse(code)
        if tree.body and all(isinstance(node, ast.Expr) and isinstance(node.value, (ast.BinOp, ast.UnaryOp, ast.Name, ast.Attribute, ast.Compare)) for node in tree.body) and "(" not in code:
            return "bash"
        return "python"
    except (SyntaxError, ValueError, RecursionError):
        pass
    if re.search(r"(?m)^\s*(?:CREATE\s+(?:PROCEDURE|TABLE)|SELECT\s|UPDATE\s+\w+\s+SET|DELETE\s+FROM|INSERT\s+INTO|DROP\s+(?:TABLE|DATABASE)|TRUNCATE\s)", stripped, re.I):
        return "sql"
    if re.search(r"(?m)^\s*(?:const |let |var |(?:async )?function |module\.exports|export (?:default |function ))", stripped):
        return "javascript"
    if re.search(r"(?m)^\s*(?:runs-on:|steps:|jobs:|on:|apiVersion:|services:)", stripped):
        return "yaml"
    if "<!--" in stripped or re.search(r"(?m)^#{1,6} .+\n\s*\n[A-Za-z]", stripped):
        return "markdown"
    return "bash"
