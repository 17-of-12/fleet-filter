#!/usr/bin/env bash
# check.sh - the project's single static-feedback entry point (operating rule 15).
#
# Purpose
# -------
# Answer "does this project's code lint, compile, and pass its tests" with one command and in
# seconds, before anything is built or deployed. Rule 11 says tests must pass before deploy; this
# script is the command that makes that claim checkable rather than asserted. It produces no
# artifacts, and in its default read-only mode it cannot create a diff.
#
# Design notes
# ------------
# * Rust and Python are checked from one entry point because both ship from this repo and a change
#   in one routinely breaks what the other expects (the gateway and bin/render-signature-rules.py
#   consume the same controller/signatures.yaml).
# * Rust is checked natively against the toolchain ADR-0001 pins (rustc/cargo/rustfmt/clippy
#   1.92.0, installed from ol9_appstream on this host) with the target directory kept outside the
#   source tree, so repeated checks reuse compiled dependencies instead of rebuilding all 65 crates.
#   The container build stays the only artifact path: a native EL9 binary links glibc 2.34 and
#   cannot run on the EL8 fleet, so "it checks natively" and "it is shippable" are different claims.
# * Python is checked through .venv (rule 15), never the system interpreter, and additionally under
#   every interpreter listed in PYTHONS because the deployed controller runs on older system
#   Pythons on lab-web01 (3.6.8/3.9, measured).
# * Every step runs under `timeout` and prints exactly one status line; on failure the captured
#   output is echoed and the script exits. An unbounded command once consumed a whole session
#   (the measure-request-cost.sh incident), so nothing here is allowed to run without a ceiling.
# * `--fix` is the only mutating mode (cargo fmt + ruff --fix). Keeping mutation opt-in means
#   running the checker is never the reason an unexpected diff appears in a review.
#
# Usage
# -----
#   bin/check.sh                 # rust + python, read-only
#   bin/check.sh --rust          # gateway only (fmt, clippy, tests)
#   bin/check.sh --python        # ruff + every test suite under each interpreter
#   bin/check.sh --fix           # apply cargo fmt and ruff --fix first, then check
#   TIMEOUT=120 bin/check.sh     # per-step ceiling in seconds (default 900)
#   PYTHONS="/usr/bin/python3.11" bin/check.sh  # override the interpreter matrix

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_DIR="${REPO_ROOT}/gateway"
VENV="${VENV:-${REPO_ROOT}/.venv}"
TIMEOUT="${TIMEOUT:-900}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/fleet-filter-gateway/target}"
LOG_DIR="${TMPDIR:-/tmp}/fleet-filter-check.$$"

usage() {
    sed -n '/^# Usage$/,/^#   PYTHONS=/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

DO_RUST=0
DO_PYTHON=0
FIX=0
while [ $# -gt 0 ]; do
    case "$1" in
        --rust) DO_RUST=1 ;;
        --python) DO_PYTHON=1 ;;
        --all) DO_RUST=1; DO_PYTHON=1 ;;
        --fix) FIX=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
# Default with no selector is "everything", so CI and a human run the same set by default.
if [ "$DO_RUST" -eq 0 ] && [ "$DO_PYTHON" -eq 0 ]; then
    DO_RUST=1
    DO_PYTHON=1
fi

mkdir -p "$LOG_DIR"
trap 'rm -rf "$LOG_DIR"' EXIT

FAILURES=0

# run_step NAME CMD... - run one check under a timeout, print one status line, keep the output.
#
# The output is captured to a file rather than streamed: a passing step should cost one line of
# the report, and a failing step should show the evidence without the caller re-running it.
run_step() {
    local name="$1"
    shift
    local log="${LOG_DIR}/$(echo "$name" | tr ' /.' '___').log"
    printf '%-34s ' "$name"
    if timeout "$TIMEOUT" "$@" >"$log" 2>&1; then
        echo "PASS"
    else
        echo "FAIL"
        echo "--- output (${name}) ---"
        tail -n 60 "$log"
        echo "----------------------"
        FAILURES=$((FAILURES + 1))
    fi
}

echo "== Fleet-Filter check ($(hostnamectl --static 2>/dev/null || hostname)) =="

if [ "$DO_RUST" -eq 1 ]; then
    if command -v cargo >/dev/null 2>&1; then
        echo "rust:    $(rustc --version) / $(cargo --version)"
        export CARGO_TARGET_DIR
        cd "$GATEWAY_DIR"
        if [ "$FIX" -eq 1 ]; then
            run_step "rust: cargo fmt (apply)" cargo fmt --all
        fi
        run_step "rust: cargo fmt --check" cargo fmt --all -- --check
        run_step "rust: cargo clippy" cargo clippy --all-targets -- -D warnings
        run_step "rust: cargo test" cargo test
    else
        echo "rust:    cargo not on PATH"
        FAILURES=$((FAILURES + 1))
    fi
fi

if [ "$DO_PYTHON" -eq 1 ]; then
    if [ -x "$VENV/bin/python" ]; then
        echo "python:  $("$VENV/bin/python" --version) at $VENV (ruff $("$VENV/bin/ruff" --version | awk '{print $2}'))"
        cd "$REPO_ROOT"
        if [ "$FIX" -eq 1 ]; then
            run_step "python: ruff --fix" "$VENV/bin/ruff" check --fix .
        fi
        run_step "python: ruff check" "$VENV/bin/ruff" check .
        # The interpreter matrix mirrors what actually executes this code in the field: the venv
        # interpreter plus any older system interpreter present. Tests that need a module the
        # interpreter lacks (for example PyYAML on a system Python) skip themselves and report it.
        # The second interpreter exists to catch constructs that pass on the venv's Python and fail
        # on an older system one. Naming a specific version made a fresh clone fail on any host that
        # does not happen to ship it, which is most of them; use whatever system Python is present,
        # and fall back to the venv alone when there is none.
        if [ -z "${PYTHONS:-}" ]; then
            PYTHONS="$VENV/bin/python"
            for candidate in /usr/bin/python3 /usr/bin/python3.13 /usr/bin/python3.12 \
                             /usr/bin/python3.11 /usr/bin/python3.10 /usr/bin/python3.9; do
                if [ -x "$candidate" ]; then
                    PYTHONS="$PYTHONS $candidate"
                    break
                fi
            done
        fi
        for interpreter in $PYTHONS; do
            [ -x "$interpreter" ] || { echo "warning: PYTHONS entry $interpreter not executable" >&2; continue; }
            for suite in tests/unit/test_*.py tests/security/test_*.py; do
                [ -f "$suite" ] || continue
                run_step "python: $(basename "$suite") ($(basename "$interpreter"))" \
                    "$interpreter" "$suite"
            done
        done
    else
        echo "python:  no venv at $VENV"
        echo "         create it with: python3.12 -m venv $VENV && $VENV/bin/pip install -r requirements-dev.txt"
        FAILURES=$((FAILURES + 1))
    fi
fi

# The exploit ledger is a claim about the lab, so it is checked with the same gate as the code. It
# reads the tree only - no host, no container - which is what makes it safe to run on every change.
if [ -x "$REPO_ROOT/bin/exploit-regress.py" ] && [ -n "${VENV:-}" ] && [ -x "$VENV/bin/python" ]; then
    # Deliberately not `lab-inventory.py`: that talks to the lab over SSH, and the gate has to pass
    # on a box with no lab reachable. The ledger check is offline by construction.
    run_step "ledger: exploit coverage claims" "$VENV/bin/python" "$REPO_ROOT/bin/exploit-regress.py"
    # Coverage says a verdict is supported. This says the *public* tree can show the support: the
    # signature is defined, the session is one an export ships, and the document names the exploit.
    # Without it, the install that found the bug keeps the only copy of the answer.
    # Documentation rots by link: a moved file leaves a small lie nobody clicks until they do.
    if [ -x "$REPO_ROOT/bin/check-doc-links.py" ]; then
        run_step "docs: relative links resolve" "$VENV/bin/python" "$REPO_ROOT/bin/check-doc-links.py"
    fi
    if [ -x "$REPO_ROOT/bin/exploit-upstream.py" ]; then
        run_step "ledger: contributable upstream" "$VENV/bin/python" \
            "$REPO_ROOT/bin/exploit-upstream.py" --quiet
    fi
fi

echo "result:  $([ "$FAILURES" -eq 0 ] && echo 'all checks passed' || echo "$FAILURES check(s) failed")"
[ "$FAILURES" -eq 0 ] || exit 1
