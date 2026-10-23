import re

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from guard.schema import Finding


def sql_findings(query, line=1, interpolated=False):
    findings = []
    for match in re.finditer(r"\b(?:SELECT|UPDATE|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE)|TRUNCATE(?:\s+TABLE)?)\b[^;]*", query, re.I):
        statement = match.group()
        statement_line = line + query[:match.start()].count("\n")
        if interpolated:
            category = "data_exfiltration" if re.match("SELECT", statement, re.I) else "destructive_command"
            findings.append(Finding(category, "SQL includes runtime string interpolation instead of bound parameters.", statement_line))
        try:
            tree = sqlglot.parse_one(statement)
        except (ParseError, RecursionError):
            tree = None
        if isinstance(tree, (exp.Drop, exp.TruncateTable)):
            findings.append(Finding("destructive_command", "SQL removes a table, database, or its contents.", statement_line))
        if isinstance(tree, (exp.Update, exp.Delete)) and tree.args.get("where") is None:
            findings.append(Finding("destructive_command", "SQL modifies every row without a WHERE constraint.", statement_line))
    return findings
