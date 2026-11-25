#!/usr/bin/env python3
"""Enforce operating rule 14: every function states its purpose.

Purpose
-------
A reviewer - human or AI - reviews a function by reading its stated purpose and judging
the code against it. A function with no docstring can be read but not reviewed, so logic
errors survive review. This test turns that idea into a build gate instead of a habit:
if any function in the project loses its docstring, the suite fails and names it.

What it checks
--------------
* Every `def` / `async def` in every tracked `.py` file has a docstring.
* Every module itself has a module-level docstring (the file's own purpose statement).
* A docstring must carry more than the function's own name, which catches the
  name-only form of compliance (`def now(): "now"`) that states nothing.

What it deliberately does not check
-----------------------------------
* Wording quality beyond the trivial-name rule - prose review stays human/AI review.
* Shell scripts: they use header comments, not docstrings, so they are out of scope here
  and are covered by their own tests (`test_ingest.py` invokes the shims directly).
"""

import ast
import os
import sys

# Directories holding project source. Test files are included on purpose: a test
# function without a docstring does not say which behaviour it is asserting, which is
# exactly the ambiguity this rule exists to remove.
SOURCE_DIRS = ("controller", "tarpit", "tests", "bin", "web")

# A docstring that is only the function's own name (plus punctuation/whitespace) is
# compliance theatre; require at least a few characters of actual content beyond it.
MIN_CONTENT_BEYOND_NAME = 8


def find_python_files(root):
    """Yield every .py file under the source directories that actually exist.

    Skips `__pycache__` and anything under `archive/`, because archived scripts are
    frozen history and rewriting them would destroy the record they exist to keep.
    """
    for directory in SOURCE_DIRS:
        path = os.path.join(root, directory)
        if not os.path.isdir(path):
            continue
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = [d for d in dirnames if d != "__pycache__" and d != "archive"]
            for filename in filenames:
                if filename.endswith(".py"):
                    yield os.path.join(dirpath, filename)


def check_file(path):
    """Return a list of "line:N message" findings for one file.

    Checks the module docstring and every function/method docstring in a single parse,
    so the cost is one `ast.parse` per file rather than one per function.
    """
    findings = []
    with open(path, "r") as handle:
        source = handle.read()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:  # an unparseable file cannot be reviewed at all
        return ["line:%d unparseable: %s" % (exc.lineno or 0, exc.msg)]

    if not ast.get_docstring(tree):
        findings.append("line:0 module has no docstring (what does this file exist to do?)")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        docstring = ast.get_docstring(node)
        if not docstring or not docstring.strip():
            findings.append("line:%d %s() has no docstring" % (node.lineno, node.name))
            continue
        stripped = docstring.strip().strip("\"'").strip()
        if len(stripped) < len(node.name) + MIN_CONTENT_BEYOND_NAME:
            findings.append(
                "line:%d %s() docstring restates only the name: %r"
                % (node.lineno, node.name, docstring.strip())
            )
    return findings


def main():
    """Run the check across the project and report every finding.

    Exits non-zero with the full list rather than failing on the first one, so a single
    run tells the author everything that is missing in one pass.
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    files = sorted(find_python_files(root))
    if not files:
        sys.stderr.write("no python sources found under %s\n" % root)
        return 1

    total_functions = 0
    failures = []
    for path in files:
        with open(path, "r") as handle:
            total_functions += sum(
                1
                for node in ast.walk(ast.parse(handle.read()))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        for finding in check_file(path):
            failures.append("%s %s" % (os.path.relpath(path, root), finding))

    print("files checked: %d   functions checked: %d   findings: %d"
          % (len(files), total_functions, len(failures)))
    for failure in failures:
        print("  FAIL %s" % failure)
    if failures:
        print("FAIL: operating rule 14 - every function must state its purpose")
        return 1
    print("PASS: every function in the project states its purpose")
    return 0


if __name__ == "__main__":
    sys.exit(main())
