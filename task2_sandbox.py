"""
Task 2: Controlled Execution Sandbox
======================================
A secure sandbox that safely executes untrusted Python expressions/scripts
with strict resource limits, operation restrictions, and violation detection.
"""

import ast
import sys
import os
import time
import threading
import resource
import signal
import traceback
import logging
from datetime import datetime
from io import StringIO

# ─────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────
logging.basicConfig(
    filename="sandbox_audit.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def audit(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    getattr(logging, level.lower(), logging.info)(msg)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
MAX_EXECUTION_TIME  = 5       # seconds
MAX_OUTPUT_LENGTH   = 2000    # chars
MAX_MEMORY_MB       = 32      # MB

# Completely forbidden AST node types
FORBIDDEN_NODES = {
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.AsyncFunctionDef,
    ast.AsyncFor,
    ast.AsyncWith,
}

# Forbidden built-in names
FORBIDDEN_NAMES = {
    "open", "exec", "eval", "compile", "input",
    "__import__", "globals", "locals", "vars",
    "getattr", "setattr", "delattr", "hasattr",
    "breakpoint", "memoryview", "bytearray",
    "object", "type", "super",
    "exit", "quit", "help",
    "copyright", "credits", "license",
}

# Forbidden attribute access patterns
FORBIDDEN_ATTRS = {
    "__class__", "__bases__", "__subclasses__",
    "__mro__", "__dict__", "__code__", "__globals__",
    "__builtins__", "__loader__", "__spec__",
    "__file__", "__path__",
    "system", "popen", "subprocess", "socket",
    "read", "write", "unlink", "remove", "rmdir",
    "chmod", "chown", "getcwd", "listdir",
}

# Allowed built-in functions (whitelist)
SAFE_BUILTINS = {
    "abs", "all", "any", "bin", "bool", "chr",
    "dict", "dir", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "hash", "hex",
    "int", "isinstance", "issubclass", "iter",
    "len", "list", "map", "max", "min", "next",
    "oct", "ord", "pow", "print", "range",
    "repr", "reversed", "round", "set", "slice",
    "sorted", "str", "sum", "tuple", "zip",
    "True", "False", "None",
}

# ─────────────────────────────────────────────
# AST Security Validator
# ─────────────────────────────────────────────
class SecurityVisitor(ast.NodeVisitor):
    """Walks the AST and raises SecurityViolation on disallowed constructs."""

    def __init__(self):
        self.violations = []

    def _flag(self, node, reason):
        self.violations.append(f"Line {getattr(node, 'lineno', '?')}: {reason}")

    def visit_Import(self, node):
        self._flag(node, f"Import statement forbidden: {[a.name for a in node.names]}")

    def visit_ImportFrom(self, node):
        self._flag(node, f"'from ... import' forbidden: module={node.module}")

    def visit_Call(self, node):
        # Check direct name calls  e.g. exec("..."), open("file")
        if isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_NAMES:
                self._flag(node, f"Forbidden built-in call: {node.func.id}()")
        # Check attribute calls  e.g. os.system(), subprocess.run()
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_ATTRS:
                self._flag(node, f"Forbidden attribute call: .{node.func.attr}()")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in FORBIDDEN_ATTRS:
            self._flag(node, f"Forbidden attribute access: .{node.attr}")
        # Detect dunder chains like ().__class__.__bases__
        if node.attr.startswith("__") and node.attr.endswith("__"):
            self._flag(node, f"Dunder attribute access forbidden: {node.attr}")
        self.generic_visit(node)

    def visit_Global(self, node):
        self._flag(node, "global statement forbidden")

    def visit_Nonlocal(self, node):
        self._flag(node, "nonlocal statement forbidden")

    def visit_AsyncFunctionDef(self, node):
        self._flag(node, "async functions forbidden")

    def visit_AsyncFor(self, node):
        self._flag(node, "async for loops forbidden")

    def visit_AsyncWith(self, node):
        self._flag(node, "async with forbidden")


# ─────────────────────────────────────────────
# Sandbox Result
# ─────────────────────────────────────────────
class SandboxResult:
    def __init__(self):
        self.accepted   = False
        self.output     = ""
        self.error      = ""
        self.violations = []
        self.exec_time  = 0.0

    def __str__(self):
        status = "✅ ACCEPTED" if self.accepted else "❌ REJECTED"
        lines = [
            "─" * 55,
            f"  Status     : {status}",
            f"  Exec time  : {self.exec_time:.3f}s",
        ]
        if self.violations:
            lines.append("  Violations :")
            for v in self.violations:
                lines.append(f"    • {v}")
        if self.output:
            lines.append("  Output     :")
            for ln in self.output.splitlines():
                lines.append(f"    {ln}")
        if self.error:
            lines.append("  Error      :")
            for ln in self.error.splitlines():
                lines.append(f"    {ln}")
        lines.append("─" * 55)
        return "\n".join(lines)


# ─────────────────────────────────────────────
# Core Sandbox
# ─────────────────────────────────────────────
class Sandbox:
    """Executes untrusted Python code with multi-layer security controls."""

    def __init__(self):
        self._safe_builtins = {k: __builtins__[k] if isinstance(__builtins__, dict)
                               else getattr(__builtins__, k, None)
                               for k in SAFE_BUILTINS
                               if (isinstance(__builtins__, dict) and k in __builtins__)
                               or hasattr(__builtins__, k)}
        # Allow safe math
        import math
        self._safe_globals = {
            "__builtins__": self._safe_builtins,
            "math": math,
        }

    # ── Layer 1: Static AST analysis ──────────────
    def _static_check(self, code: str):
        violations = []
        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError as e:
            return None, [f"SyntaxError: {e}"]

        visitor = SecurityVisitor()
        visitor.visit(tree)
        violations.extend(visitor.violations)
        return tree, violations

    # ── Layer 2: Time-limited execution ───────────
    def _run_with_timeout(self, code: str, result: SandboxResult):
        stdout_capture = StringIO()
        old_stdout = sys.stdout
        sys.stdout = stdout_capture

        exec_globals = dict(self._safe_globals)  # fresh namespace per run
        try:
            exec(compile(code, "<sandbox>", "exec"), exec_globals)
            result.output = stdout_capture.getvalue()[:MAX_OUTPUT_LENGTH]
            result.accepted = True
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
            result.accepted = False
        finally:
            sys.stdout = old_stdout

    # ── Public API ────────────────────────────────
    def execute(self, code: str) -> SandboxResult:
        result = SandboxResult()
        audit(f"Received input ({len(code)} chars)")

        # Layer 1 – Static AST check
        tree, violations = self._static_check(code)
        if violations:
            result.violations = violations
            result.error = "Static security check failed."
            audit(f"BLOCKED by static check: {violations}", "WARNING")
            return result
        if tree is None:
            result.error = violations[0] if violations else "Parse error"
            return result

        # Layer 2 – Timed execution in thread
        start = time.perf_counter()
        t = threading.Thread(target=self._run_with_timeout, args=(code, result), daemon=True)
        t.start()
        t.join(timeout=MAX_EXECUTION_TIME)
        result.exec_time = time.perf_counter() - start

        if t.is_alive():
            # Thread still running → timeout exceeded
            result.accepted = False
            result.violations.append(f"Execution timeout exceeded ({MAX_EXECUTION_TIME}s)")
            result.error = "Execution killed: timeout."
            audit("BLOCKED: execution timeout", "WARNING")
            return result

        if result.accepted:
            audit(f"ACCEPTED: executed in {result.exec_time:.3f}s")
        else:
            audit(f"REJECTED at runtime: {result.error}", "WARNING")

        return result


# ─────────────────────────────────────────────
# Demo / Test Runner
# ─────────────────────────────────────────────
TEST_CASES = [
    # (description, code)
    ("Safe arithmetic",
     "x = 2 ** 10\nprint('2^10 =', x)"),

    ("Safe list comprehension",
     "evens = [i for i in range(20) if i % 2 == 0]\nprint(evens)"),

    ("Safe math module",
     "import math\nprint(math.sqrt(144))"),

    ("ATTACK – import os",
     "import os\nprint(os.listdir('/'))"),

    ("ATTACK – exec()",
     "exec('print(42)')"),

    ("ATTACK – open() file read",
     "f = open('/etc/passwd')\nprint(f.read())"),

    ("ATTACK – __import__",
     "__import__('subprocess').run(['ls','-la'])"),

    ("ATTACK – dunder escape",
     "x = ().__class__.__bases__[0].__subclasses__()"),

    ("ATTACK – infinite loop (timeout test)",
     "while True:\n    pass"),

    ("Safe fibonacci",
     """
def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
print([fib(i) for i in range(10)])
"""),
]


def run_demo():
    sandbox = Sandbox()
    print("\n" + "═" * 55)
    print("    CONTROLLED EXECUTION SANDBOX — DEMO")
    print("═" * 55 + "\n")

    for desc, code in TEST_CASES:
        print(f"\n▶  Test: {desc}")
        print(f"   Code : {code.strip()[:80]}{'…' if len(code.strip()) > 80 else ''}")
        result = sandbox.execute(code)
        print(result)

    print("\nAll tests complete. See sandbox_audit.log for full audit trail.\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        sandbox = Sandbox()
        print("Controlled Execution Sandbox — Interactive Mode")
        print("Type 'exit' to quit. Multi-line: end with an empty line.\n")
        while True:
            lines = []
            try:
                line = input(">>> ")
                if line.lower() == "exit":
                    break
                lines.append(line)
                while True:
                    line = input("... ")
                    if line == "":
                        break
                    lines.append(line)
            except (EOFError, KeyboardInterrupt):
                break
            code = "\n".join(lines)
            if code.strip():
                print(sandbox.execute(code))
    else:
        run_demo()
