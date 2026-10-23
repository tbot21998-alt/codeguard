import functools
import subprocess
from time import perf_counter

from guard.detector import evaluate
from guard.schema import Verdict
from guard.command_policy import command_source, validate_command_text


class CodeGuardBlockedError(RuntimeError):
    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(verdict.reason)


def require_allowed(code, *, language=None):
    verdict = evaluate(code, language=language)
    if verdict.verdict == "block":
        raise CodeGuardBlockedError(verdict)
    return verdict


def codeguard_protect(function):
    @functools.wraps(function)
    def protected(code, *args, **kwargs):
        require_allowed(code)
        return function(code, *args, **kwargs)
    return protected


def evaluate_command(argv):
    if not argv or any(not isinstance(arg, str) or "\0" in arg for arg in argv):
        raise ValueError("command must contain nonempty string arguments without NUL bytes")
    try:
        source, language = command_source(argv)
        if language == "bash":
            validate_command_text(source)
        return evaluate(source, language=language)
    except ValueError as error:
        return Verdict(verdict="block", risk_score=None, categories=["obfuscated_execution"], code_language="bash", reason=str(error), vulnerable_lines=[1])


class SafeExecutor:
    def run(self, code):
        require_allowed(code, language="python")
        namespace = {"__name__": "__main__"}
        exec(compile(code, "<codeguard-approved>", "exec"), namespace)
        return namespace

    def run_command(self, argv, *, cwd=None, timeout=30, capture_output=False, text=True, check=False, on_decision=None):
        frozen_argv = tuple(argv)
        started = perf_counter()
        verdict = evaluate_command(frozen_argv)
        if on_decision is not None:
            on_decision(verdict, (perf_counter() - started) * 1000)
        if verdict.verdict == "block":
            raise CodeGuardBlockedError(verdict)
        return subprocess.run(list(frozen_argv), shell=False, cwd=cwd, timeout=timeout, capture_output=capture_output, text=text, check=check)
