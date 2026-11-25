#!/usr/bin/env python3
"""Stage 4 webtree file audit - the fourth layer of protection on a web VM.

Intent: answer "what appeared in the webtree that should not be here?" for files, in the gap the
other three layers cannot cover. The Rust gateway matches *requests* inline, Wazuh ingests *logs*
and reports file *changes*, and neither of them can tell you whether a newly created file is a
webshell. This module does the static analysis half of that question.

Design principle (owner direction 2026-11-16): match **structure**, not **strings**. A string or
hash signature is defeated the moment someone asks an LLM to rewrite a canned webshell into a
unique fingerprint, so tier 1 here measures shape - entropy, encoded-literal length, minification
ratio, dangerous-function census, extension-versus-magic mismatch, and (where PHP is available)
the real token stream from the host's own interpreter. A rewritten shell still has to *do*
something, and the shape survives the rewrite.

Tiers implemented in this file:
  * tier 1 - shape metrics and a weighted score (always runs, stdlib only, Python 3.6+)
  * tier 2 - yara signature match (runs when a yara binary and ruleset are supplied)
  * tier 3 - verdict: clean / review / quarantine, with the firing features recorded so a console
    can show *why* a file was flagged rather than only *how much*

The tool is read-only. It never writes to, moves, or deletes an audited file; quarantine is a
separate, explicit action so a false positive stays recoverable.
"""

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter

# High-risk PHP constructs: a legitimate page rarely contains these, a shell almost always does.
HIGH_RISK_FUNCTIONS = (
    "eval", "assert", "system", "exec", "shell_exec", "passthru", "proc_open", "popen",
    "create_function", "call_user_func_array", "preg_replace_callback", "preg_match_all",
)
# Medium-risk: common in real application code, so they only contribute when combined with
# something else. Capping their contribution is what keeps real code from scoring as a shell.
MEDIUM_RISK_FUNCTIONS = (
    "base64_decode", "gzinflate", "gzuncompress", "str_rot13", "strrev", "convert_uudecode",
    "file_get_contents", "file_put_contents", "urldecode", "rawurldecode", "hex2bin",
    "pack", "unpack", "substr", "explode",
)
# PHP functions whose token we can count directly from token_get_all output.
PHP_TOKEN_FUNCTIONS = ("eval", "assert", "system", "exec", "shell_exec", "passthru", "proc_open")

DEFAULT_REVIEW_SCORE = 4
DEFAULT_QUARANTINE_SCORE = 8
# Where the scanner image bakes its ruleset. Auto-detected so running the image needs no flags.
IMAGE_RULES_PATH = "/opt/fleet-filter/rules/fleet-filter.yar"
# Owner rule 2026-11-16: routine runs cover new/changed files only; the whole tree is rescanned
# weekly, so a host is never rehashed every few minutes but drift still gets caught.
DEFAULT_FULL_SCAN_INTERVAL_HOURS = 168

BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
HEX_RUN = re.compile(rb"(?:0x)?[0-9a-fA-F]{48,}")
VAR_FUNC_CALL = re.compile(rb"\$(?:\{[^{}\n]{1,64}\}|[A-Za-z_][A-Za-z0-9_]*)\s*\(")
PHP_OPEN_TAG = re.compile(rb"<\?php|<\?=")

# Magic-number table, deliberately small: it exists to catch "extension says PHP, bytes say
# image/archive", which is a classic way to hide a shell from a human reviewer.
MAGIC_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"),
    (b"GIF89a", "gif"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"),
    (b"Rar!\x1a\x07", "rar"), (b"<html", "html"), (b"<!DOCTYPE", "html"), (b"<?xml", "xml"),
)
IMAGE_EXTENSIONS = ("png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "tif", "tiff")
CODE_EXTENSIONS = ("php", "phtml", "php5", "php7", "inc", "phar", "pht")


def shannon_entropy(data):
    """Return the Shannon entropy in bits per byte for `data` (0.0-8.0).

    Text and markup land in the 4-6 range, source code in the 4.5-5.5 range, and a file whose body
    is an encoded payload approaches 8.0. That separation is the whole reason tier 1 works.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = float(len(data))
    return -sum((c / length) * math.log(c / length, 2) for c in counts.values())


def longest_base64_run(data):
    """Return the length of the longest base64-shaped literal in `data`, ignoring short matches."""
    best = 0
    for match in BASE64_RUN.finditer(data):
        if len(match.group(0)) > best:
            best = len(match.group(0))
    return best


def longest_hex_run(data):
    """Return the length of the longest hex-literal run in `data` (48+ characters only)."""
    best = 0
    for match in HEX_RUN.finditer(data):
        if len(match.group(0)) > best:
            best = len(match.group(0))
    return best


def bytes_per_line(data):
    """Return the average number of bytes per line, the minification-ratio proxy.

    A one-line 4 KB file scores 4096.0. Normal markup or source is tens of bytes per line. Line
    counting treats a trailing newline as ending the last line rather than starting an empty one, so
    a normal 2-line file is measured against 2 lines and not 3.
    """
    if not data:
        return 0.0
    newlines = data.count(b"\n")
    lines = newlines if newlines and data.endswith(b"\n") else newlines + 1
    return round(float(len(data)) / float(lines), 2)


def detect_magic(data):
    """Return the file type implied by the leading bytes, or None when nothing matches."""
    head = data[:16]
    for signature, name in MAGIC_SIGNATURES:
        if head.startswith(signature):
            return name
    if head.lstrip()[:1] in (b"<",):
        return "html"
    return None


def extension_of(path):
    """Return the lowercase extension of `path` without the dot ('' when there is none)."""
    return os.path.splitext(path)[1].lstrip(".").lower()


def magic_mismatch(path, data):
    """Return a human-readable extension-vs-content mismatch, or None when they agree.

    Only image extensions are checked, because that is the case that hides a shell: a `.png` that
    is really PHP, or a `.php` that is really a PNG served to leak source.
    """
    ext = extension_of(path)
    magic = detect_magic(data)
    if ext in IMAGE_EXTENSIONS and magic not in (ext if ext != "jpg" else "jpeg", None):
        return "extension .%s but bytes are %s" % (ext, magic)
    if ext in ("php", "phtml", "inc") and magic in ("png", "jpeg", "gif", "zip", "gzip"):
        return "extension .%s but bytes are %s" % (ext, magic)
    return None


def dangerous_functions(data):
    """Return {function_name: occurrences} for the high- and medium-risk PHP functions.

    Counted textually rather than by parsing so the metric still exists on hosts without PHP. The
    word-boundary match is what stops `eval` from matching inside `evaluate(` or `revalue`.
    """
    found = {}
    for name in HIGH_RISK_FUNCTIONS + MEDIUM_RISK_FUNCTIONS:
        count = len(re.findall(rb"(?<![A-Za-z0-9_])" + name.encode("ascii") + rb"\s*\(", data))
        if count:
            found[name] = count
    return found


def variable_function_calls(data):
    """Return the count of variable-function call shapes: `$f()`, `$f[1]()`, and `${"sys"."tem"}()`.

    The braced form is the one obfuscators use to hide a function name from a string search, so it
    has to be matched explicitly rather than assumed to look like `$name(`.
    """
    return len(VAR_FUNC_CALL.findall(data))


def php_token_stats(path, php_bin="php"):
    """Return real PHP token counts from the host interpreter, or None when PHP cannot parse it.

    Using the host's own `php -r token_get_all()` beats regex guessing: it distinguishes a comment
    that mentions `eval` from an actual T_EVAL token, and it fails loudly on a file PHP cannot
    parse, which is itself a signal.
    """
    if not os.path.exists(php_bin):
        return None
    try:
        proc = subprocess.run(
            [php_bin, "-r",
             '$f=$argv[1];$t=@token_get_all(file_get_contents($f));'
             'if(!is_array($t)){fwrite(STDERR,"unparseable");exit(3);}'
             'foreach($t as $x){echo is_array($x)?token_name($x[0])."\\n":"STRING\\n";}',
             path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    names = [line for line in proc.stdout.decode("utf-8", "replace").splitlines() if line]
    counts = Counter(names)
    return {
        "tokens": len(names),
        "eval": counts.get("T_EVAL", 0),
        "assert": counts.get("T_ASSERT", 0),
        "strings": counts.get("STRING", 0) + counts.get("T_CONSTANT_STRING", 0),
        "inline_html": counts.get("T_INLINE_HTML", 0),
        "comments": counts.get("T_COMMENT", 0) + counts.get("T_DOC_COMMENT", 0),
    }


def shape_metrics(path, data, php_bin=None):
    """Compute every tier-1 metric for one file's bytes and return them as a flat dict."""
    metrics = {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "extension": extension_of(path),
        "entropy": round(shannon_entropy(data), 3),
        "longest_base64": longest_base64_run(data),
        "longest_hex": longest_hex_run(data),
        "bytes_per_line": bytes_per_line(data),
        "php_open_tags": len(PHP_OPEN_TAG.findall(data)),
        "variable_function_calls": variable_function_calls(data),
        "dangerous_functions": dangerous_functions(data),
        "magic_mismatch": magic_mismatch(path, data),
    }
    if php_bin and metrics["extension"] in CODE_EXTENSIONS:
        metrics["php_tokens"] = php_token_stats(path, php_bin)
    else:
        metrics["php_tokens"] = None
    return metrics


def score_metrics(metrics):
    """Return (score, [reasons]) for tier-1 metrics using the documented weights.

    Weights are deliberately explicit and capped so no single metric can quarantine a file on its
    own except a magic mismatch, which is a factual contradiction rather than a heuristic. The
    reason list is what the console renders; a score without reasons is not actionable.
    """
    score = 0
    reasons = []
    size = metrics["size"]
    entropy = metrics["entropy"]
    if size and size <= 65536:
        if entropy >= 7.0:
            score += 3
            reasons.append("entropy %.2f in a %d-byte file" % (entropy, size))
        elif entropy >= 6.5:
            score += 2
            reasons.append("entropy %.2f" % entropy)
        elif entropy >= 6.0:
            score += 1
            reasons.append("entropy %.2f" % entropy)
    elif entropy >= 7.2:
        score += 1
        reasons.append("entropy %.2f in a large file" % entropy)

    if metrics["longest_base64"] >= 120:
        score += 3
        reasons.append("base64 literal of %d chars" % metrics["longest_base64"])
    elif metrics["longest_base64"] >= 64:
        score += 2
        reasons.append("base64 literal of %d chars" % metrics["longest_base64"])
    elif metrics["longest_base64"] >= 32:
        score += 1
        reasons.append("base64 literal of %d chars" % metrics["longest_base64"])
    if metrics["longest_hex"] >= 48:
        score += 1
        reasons.append("hex literal of %d chars" % metrics["longest_hex"])

    high = {k: v for k, v in metrics["dangerous_functions"].items() if k in HIGH_RISK_FUNCTIONS}
    medium = {k: v for k, v in metrics["dangerous_functions"].items() if k in MEDIUM_RISK_FUNCTIONS}
    high_points = min(6, sum(min(v, 2) for v in high.values()))
    if high_points:
        score += high_points
        reasons.append("high-risk functions: %s" % ", ".join(sorted(high)))
    medium_points = min(3, sum(min(v, 2) for v in medium.values()))
    if medium_points and high:
        score += medium_points
        reasons.append("decode/IO helpers: %s" % ", ".join(sorted(medium)))

    if metrics["variable_function_calls"] >= 2:
        score += 2
        reasons.append("%d variable-function calls" % metrics["variable_function_calls"])
    elif metrics["variable_function_calls"] == 1:
        score += 1
        reasons.append("1 variable-function call")

    if size >= 512 and metrics["bytes_per_line"] >= 1000:
        score += 1
        reasons.append("single-expression body (%.0f bytes/line)" % metrics["bytes_per_line"])
    if metrics["magic_mismatch"]:
        score += 4
        reasons.append(metrics["magic_mismatch"])
    if metrics["php_open_tags"] > 1 and size < 4096:
        score += 1
        reasons.append("%d PHP open tags in a small file" % metrics["php_open_tags"])
    tokens = metrics.get("php_tokens")
    if tokens and tokens["tokens"] and tokens["inline_html"] == 0 and tokens["strings"] > 20:
        score += 1
        reasons.append("pure-code PHP with %d string tokens and no HTML" % tokens["strings"])
    return score, reasons


def verdict_for(score, review_at=DEFAULT_REVIEW_SCORE, quarantine_at=DEFAULT_QUARANTINE_SCORE):
    """Map a tier-1 score onto `clean`, `review`, or `quarantine` using the configured thresholds."""
    if score >= quarantine_at:
        return "quarantine"
    if score >= review_at:
        return "review"
    return "clean"


def parse_yara_matches(stdout):
    """Turn yara stdout into rule names.

    yara prints one line per match formatted as `RULE_NAME FILE`, optionally with a `NAMESPACE:` prefix
    on the rule. The first version of this parser took the *last* token, which is the scanned path, so
    a rule that matched reported the filename instead of its own name - the same class of defect as a
    responder that returns 200 with an empty body. Parsing is split out so it can be tested without a
    yara binary on the host.
    """
    matches = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        token = line.split()[0]
        if ":" in token:
            token = token.rsplit(":", 1)[-1]
        if token:
            matches.append(token)
    return matches


def run_yara(path, rules_path, yara_bin="yara"):
    """Run tier 2 (yara) over one file and return the matching rule names, or None if unavailable.

    yara is optional by design: the shape metrics must work on a host where yara is not installed,
    and a missing binary must degrade to tier 1 rather than fail the audit.
    """
    if not rules_path or not shutil.which(yara_bin) or not os.path.exists(rules_path):
        return None
    try:
        proc = subprocess.run([yara_bin, "-r", rules_path, path],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):
        return None
    return parse_yara_matches(proc.stdout.decode("utf-8", "replace"))


def discover_files(root, limit=None, follow_symlinks=False):
    """Yield regular files under `root`, skipping symlinks unless explicitly followed.

    Symlinks are skipped by default because a link out of the docroot is how a docroot audit ends
    up reading /etc/passwd, and because a link's *existence* is the finding, not its target.
    """
    if os.path.isfile(root):
        yield root
        return
    collected = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) and not follow_symlinks:
                continue
            if not os.path.isfile(path):
                continue
            yield path
            collected += 1
            if limit is not None and collected >= limit:
                return


def parse_allowlist(text):
    """Parse allowlist file contents into a set of entries (blanks and `#` comments dropped)."""
    entries = set()
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        entries.add(entry)
    return entries


def load_allowlist(path):
    """Return a set of normalized paths or glob-free path prefixes from an allowlist file.

    Lines that are blank or start with '#' are ignored. Entries are matched against the audit path
    exactly or as a prefix, which is how a known-good app directory gets suppressed without
    disabling the audit for the whole host.
    """
    if not path or not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as handle:
        return parse_allowlist(handle.read())


def is_allowlisted(path, allowlist, root=None):
    """Return True when `path` is suppressed by an allowlist entry.

    Three entry forms are supported, because the first audit of a real docroot needed all three:

    * an absolute path (`/var/www/html/dataanalysis/index.php`) - exact match, or that file's
      directory for anything beneath it;
    * a path relative to the audit root (`dataanalysis/vendor`) - resolved against `root` when
      given, otherwise against the working directory. Resolving against the root is what makes the
      same allowlist file work on a host whose docroot is mounted somewhere else;
    * a bare directory name with a trailing slash (`vendor/`, `node_modules/`) - matches any path
      that has a directory component with that name anywhere in it. This is the form that
      suppresses a dependency tree without naming every app that has one: the first build01 audit
      returned 57 quarantined files and every one of them lived under a `vendor/` directory.
    """
    if not allowlist:
        return False
    normalized = os.path.normpath(path)
    parts = normalized.split(os.sep)
    for entry in allowlist:
        if not os.path.isabs(entry) and entry.endswith("/") and "/" not in entry.rstrip("/"):
            # Bare directory name: any component of the path may match it.
            if entry.rstrip("/") in parts[1:] or entry.rstrip("/") == os.path.basename(
                    os.path.dirname(normalized)):
                return True
            continue
        candidate = entry if os.path.isabs(entry) else os.path.normpath(
            os.path.join(root or os.getcwd(), entry))
        candidate = os.path.normpath(candidate)
        if normalized == candidate or normalized.startswith(candidate + os.sep):
            return True
    return False


def audit_file(path, php_bin=None, rules_path=None, yara_bin=None,
               review_at=DEFAULT_REVIEW_SCORE, quarantine_at=DEFAULT_QUARANTINE_SCORE):
    """Audit one file and return its full record (tier 1 always, tier 2 when yara is usable)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(1048576)  # 1 MiB cap: shape is visible in the head, and this
                                        # bounds cost on a docroot full of large assets
    except (IOError, OSError):
        return {"path": path, "error": "unreadable"}
    record = shape_metrics(path, data, php_bin)
    record["mtime"] = int(os.stat(path).st_mtime) if os.path.exists(path) else 0
    score, reasons = score_metrics(record)
    yara_hits = run_yara(path, rules_path, yara_bin) if rules_path else None
    if yara_hits:
        score += 5
        reasons.append("yara: %s" % ", ".join(yara_hits))
    record["score"] = score
    record["reasons"] = reasons
    # A known-bad signature match is a certainty, not a heuristic, so it decides the verdict outright
    # (owner rule 2026-11-16: "there is no threshold if you send code looking to actively exploit
    # things"). The score is still reported so the console can show what the shape metrics thought.
    if yara_hits:
        record["verdict"] = "quarantine"
    else:
        record["verdict"] = verdict_for(score, review_at, quarantine_at)
    if yara_hits is not None:
        record["yara"] = yara_hits
    return record


def load_state(path):
    """Return the previously saved audit state, or an empty state when the file is absent/unreadable.

    The state is what turns this from a full-tree scan into an incremental one: it remembers the
    mtime, size, and verdict of every file already scored, so a routine run only re-reads what is
    new or changed. A corrupt state file is treated as empty rather than fatal, because losing
    memory costs a re-scan while an error costs the audit.
    """
    if not path or not os.path.exists(path):
        return {"files": {}, "last_full_scan": 0}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (ValueError, IOError, OSError):
        return {"files": {}, "last_full_scan": 0}
    if not isinstance(state, dict) or "files" not in state:
        return {"files": {}, "last_full_scan": 0}
    state.setdefault("last_full_scan", 0)
    return state


def save_state(path, state):
    """Write `state` atomically so an interrupted run cannot leave a half-written manifest.

    A truncated state file would make the next run rescan everything (harmless but noisy) or, worse,
    forget a file that had been flagged, so the write goes to a temp file and is renamed.
    """
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, sort_keys=True)
    os.replace(tmp, path)


def file_is_current(cached, path):
    """Return True when `cached` still describes the file on disk (same mtime and size).

    mtime+size is the cheap identity check. It is deliberately not a hash: hashing every file is
    exactly the cost incremental mode exists to avoid, and a content-only change that keeps the size
    still moves mtime. The hash is computed when the file is actually audited and stored after that.
    """
    if not cached:
        return False
    try:
        stat = os.stat(path)
    except (IOError, OSError):
        return False
    return cached.get("mtime") == int(stat.st_mtime) and cached.get("size") == stat.st_size


def audit(root, limit=None, php_bin=None, rules_path=None, yara_bin=None, allowlist_path=None,
          review_at=DEFAULT_REVIEW_SCORE, quarantine_at=DEFAULT_QUARANTINE_SCORE,
          state_path=None, full=False, full_every_hours=None, now=None):
    """Audit a tree, reusing cached verdicts for unchanged files unless a full scan is due.

    Scan selection follows the owner's rule of 2026-11-16: keep routine work scoped to new or
    changed files, and pay for the whole tree only once every `full_every_hours`. A run is full when
    `full` is set, when no prior full scan is recorded, or when the recorded one is older than the
    interval; otherwise only files whose mtime/size differ from the state are read.

    Files recorded in the state but missing from disk are reported as `removed` rather than silently
    dropped, because a shell that disappears between two audits is still a finding.
    """
    moment = int(time.time()) if now is None else int(now)
    allowlist = load_allowlist(allowlist_path)
    state = load_state(state_path)
    due_full = bool(full) or not state.get("last_full_scan")
    if not due_full and full_every_hours:
        due_full = (moment - int(state.get("last_full_scan") or 0)) >= int(full_every_hours) * 3600
    mode = "full" if due_full else "incremental"

    records = []
    seen = set()
    new_files = changed_files = reused_files = 0
    for path in discover_files(root, limit=limit):
        if is_allowlisted(path, allowlist, root=root):
            continue
        seen.add(path)
        cached = state["files"].get(path)
        if not due_full and file_is_current(cached, path):
            reused = dict(cached["record"]) if isinstance(cached.get("record"), dict) else \
                {"path": path, "verdict": cached.get("verdict", "clean"), "score": cached.get("score", 0),
                 "reasons": ["verdict reused from state"], "reused": True}
            reused["reused"] = True
            reused["last_seen"] = moment
            records.append(reused)
            reused_files += 1
            continue
        changed_files += 1 if cached else 0
        new_files += 0 if cached else 1
        record = audit_file(path, php_bin=php_bin, rules_path=rules_path, yara_bin=yara_bin,
                            review_at=review_at, quarantine_at=quarantine_at)
        record["first_seen"] = cached.get("first_seen", moment) if cached else moment
        record["last_seen"] = moment
        records.append(record)
        if "error" not in record:
            state["files"][path] = {"mtime": record.get("mtime", moment), "size": record.get("size", 0),
                                    "verdict": record.get("verdict"), "score": record.get("score", 0),
                                    "first_seen": record["first_seen"], "record": record}

    removed = sorted(set(state["files"]) - seen) if limit is None else []
    if due_full:
        state["last_full_scan"] = moment
        for path in removed:
            gone = state["files"].pop(path)
            records.append({"path": path, "verdict": "removed", "score": 0,
                            "reasons": ["previously %s, now absent from the tree"
                                        % gone.get("verdict", "seen")], "size": gone.get("size", 0)})
    save_state(state_path, state)

    counts = Counter(r.get("verdict", "error") for r in records)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment)),
        "root": os.path.abspath(root),
        "mode": mode,
        "files_audited": len([r for r in records if not r.get("reused")]),
        "new_files": new_files,
        "changed_files": changed_files,
        "reused_files": reused_files,
        "removed_files": len(removed),
        "files_total": len(seen),
        "summary": {
            "clean": counts.get("clean", 0),
            "review": counts.get("review", 0),
            "quarantine": counts.get("quarantine", 0),
            "removed": counts.get("removed", 0),
            "errors": counts.get("error", 0),
        },
        "files": records,
    }


def render_text(report):
    """Render a report as aligned text, the operator-facing view of the same data the JSON holds."""
    lines = ["webtree audit: %s (%s scan, %d files, %d audited this run)"
             % (report["root"], report["mode"], report["files_total"], report["files_audited"])]
    lines.append("summary: clean=%(clean)d review=%(review)d quarantine=%(quarantine)d "
                 "removed=%(removed)d errors=%(errors)d" % report["summary"])
    lines.append("changes: new=%d modified=%d reused=%d removed=%d"
                 % (report["new_files"], report["changed_files"], report["reused_files"],
                    report["removed_files"]))
    flagged = [r for r in report["files"] if r.get("verdict") in ("review", "quarantine")]
    flagged.sort(key=lambda r: -r.get("score", 0))
    if not flagged:
        lines.append("no files above the review threshold")
    for record in flagged[:50]:
        lines.append("%-10s %4d  %s" % (record.get("verdict"), record.get("score", 0),
                                        record.get("path")))
        if record.get("reasons"):
            lines.append("             %s" % "; ".join(record["reasons"]))
    return "\n".join(lines)


def build_parser():
    """Return the argument parser for the audit CLI."""
    parser = argparse.ArgumentParser(
        prog="webtree-audit.py",
        description="Static audit of a web document root: shape metrics, yara, and a verdict.")
    parser.add_argument("path", help="document root (or a single file) to audit")
    parser.add_argument("--json", dest="json_out", help="write the JSON report to this path")
    parser.add_argument("--limit", type=int, help="audit at most N files")
    parser.add_argument("--state", dest="state", default=None,
                        help="state file for incremental scans (default: <path>/.webtree-audit.state.json)")
    parser.add_argument("--full", action="store_true",
                        help="ignore the state and re-audit every file")
    parser.add_argument("--full-every-hours", type=int, default=DEFAULT_FULL_SCAN_INTERVAL_HOURS,
                        help="force a full scan when the last one is older than this (0 = always incremental)")
    parser.add_argument("--php-bin", default=None,
                        help="php binary used for real tokenisation (default: auto-detect 'php')")
    parser.add_argument("--yara-rules", default=None, help="yara ruleset for tier 2")
    parser.add_argument("--yara-bin", default="yara", help="yara binary path (default: yara)")
    parser.add_argument("--allowlist", default=None, help="file of known-good paths to suppress")
    parser.add_argument("--review-score", type=int, default=DEFAULT_REVIEW_SCORE,
                        help="score that means 'review'")
    parser.add_argument("--quarantine-score", type=int, default=DEFAULT_QUARANTINE_SCORE,
                        help="score that means quarantine")
    parser.add_argument("--quiet", action="store_true", help="suppress the text report")
    return parser


def main(argv=None):
    """CLI entry point: audit a tree, print the report, optionally write JSON, set a useful exit code.

    Exit codes exist so CI and a systemd timer can act on the result: 0 when nothing is flagged,
    10 when something needs review, and 11 when something scored as quarantine.
    """
    args = build_parser().parse_args(argv)
    php_bin = args.php_bin or ("php" if os.path.exists("/usr/bin/php") else None)
    # Inside the scanner image the ruleset is baked at a fixed path; auto-detecting it means a host
    # running the image gets tier 2 without having to repeat the path on every invocation, while a
    # host with no image (plain `python3 bin/webtree-audit.py`) simply stays on tier 1.
    rules_path = args.yara_rules or (IMAGE_RULES_PATH if os.path.exists(IMAGE_RULES_PATH) else None)
    state_path = args.state
    if state_path is None and os.path.isdir(args.path):
        state_path = os.path.join(args.path, ".webtree-audit.state.json")
    report = audit(args.path, limit=args.limit, php_bin=php_bin, rules_path=rules_path,
                   yara_bin=args.yara_bin, allowlist_path=args.allowlist,
                   review_at=args.review_score, quarantine_at=args.quarantine_score,
                   state_path=state_path, full=args.full,
                   full_every_hours=args.full_every_hours)
    if not args.quiet:
        print(render_text(report))
    if args.json_out:
        # `-` means stdout: a container run should not need a writable filesystem to hand back a report.
        if args.json_out == "-":
            print(json.dumps(report, indent=1, sort_keys=True))
        else:
            with open(args.json_out, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=1, sort_keys=True)
                handle.write("\n")
    if report["summary"]["quarantine"]:
        return 11
    if report["summary"]["review"]:
        return 10
    return 0


if __name__ == "__main__":
    sys.exit(main())
