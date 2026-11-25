#!/usr/bin/env python3
"""The feature contract between an access-log line and the per-line model.

Purpose
-------
A micro model (ONNX, a few hundred KB) is the only kind of model that can score *every* line at line
rate, and its weakest point is never the model - it is the gap between the features computed at
training time and the features computed in the tail. This module is that contract: one pure function
from a log line to a fixed-length vector, versioned, with no third-party dependencies, so the trainer
and the detector cannot disagree about what a line means.

Design notes
------------
* **No raw attacker text survives into the vector.** Every field is a bucket, a count or a class.
  The User-Agent is reduced to a length bucket and a coarse class, the path to length/depth/entropy
  and a handful of structural booleans. A model is not a place to put 400 bytes of chosen input, and
  bucketing is also what makes the same model portable across hosts whose log formats differ.
* **Deterministic by construction.** No clock, no randomness, no environment. The same string yields
  the same vector on any host, which is what lets a fixture from a real log be a regression test
  (rule 17) and what makes a model's output reproducible enough to argue with.
* **Structural flags are duplicated on purpose.** `has_dot_segment` is also a signature condition, so
  the deterministic path can act without the model, and the model can use it as a feature. The two
  consumers disagreeing about that boolean is a bug worth being able to see.
* **`FEATURE_VERSION` changes whenever the vector changes.** The ONNX model records the version it
  was trained on; a mismatch at load time is a refusal, not a best-effort guess, because a model fed
  a shifted vector produces confident nonsense.

The parser accepts the project's extended combined format (see `controller/signatures/signatures.yaml`
`log_formats`) and a plain combined line, which has no `ct=`/`cl=`/`ho=`/`proto=` tail. Missing
extensions become "absent" rather than an error, because a host that has not been given the extended
LogFormat yet must not produce a different vector shape.

Usage
-----
    from features import line_features, to_vector, FEATURE_VERSION
    record = line_features(line)      # dict, for debugging and for the claim's evidence
    vector = to_vector(record)        # list[float], the model's input
"""

import math
import re

# Bump when the vector changes shape or meaning. The model artifact records this string.
FEATURE_VERSION = "1"

# The exact order of the vector. A model is pinned to this list; adding here without retraining is a
# load-time refusal, which is the point.
FEATURES = (
    "method_class",          # 0 GET, 1 HEAD, 2 POST, 3 PUT, 4 DELETE, 5 OPTIONS, 6 other, 7 PRI
    "protocol_class",        # 0 http/1.0, 1 http/1.1, 2 h2, 3 h2c, 4 other
    "status_class",          # 0 2xx, 1 3xx, 2 4xx, 3 5xx, 4 other
    "path_len_log2",         # 0..8
    "path_depth",            # 0..6, 6 means "6 or more"
    "path_entropy_log2",     # 0..8, Shannon entropy of the path doubled and floored
    "has_double_slash",
    "has_dot_segment",       # `/./`, `/../`, or their encoded forms
    "has_percent",
    "percent_count_class",   # 0 none, 1 one, 2 two-to-four, 3 five-plus
    "has_semicolon",
    "extension_class",       # 0 none, 1 html, 2 php, 3 asp/jsp, 4 cgi/sh, 5 js, 6 json/xml, 7 env/conf, 8 other
    "query_present",
    "query_len_log2",
    "query_param_count_class",
    "ct_present",
    "cl_present",
    "cl_is_zero",
    "host_is_localhost",
    "referer_present",
    "ua_class",              # 0 absent, 1 curl/wget, 2 scanner token, 3 browser-likeness, 4 other
    "ua_len_log2",
    "body_bytes_log2",
    "resp_bytes_log2",
    "is_4xx",
    "is_5xx",
    "path_has_wp",
    "path_has_api",
)

# The regex parses both the extended and the plain combined line. Optional extensions are separate
# groups so "absent" and "empty" stay distinguishable: `cl=-` means the client sent no length, and
# that is different from a log format that does not record it.
LINE_RE = re.compile(
    r'^(?P<host>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+)(?: HTTP/(?P<version>[0-9.]+))?" '
    r'(?P<status>[0-9]{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
    r'(?P<extras>.*)$'
)

# Extensions the project's own LogFormat appends: `ct= cl= ho= proto=`. Parsed generically so a new
# extension never needs a new parser, and an attacker-supplied string that looks like `cl=6` inside
# the User-Agent cannot be mistaken for the field, because the extras group starts after the UA.
EXTRA_RE = re.compile(r'\b(ct|cl|ho|proto)=(.*?)(?= \b(?:ct|cl|ho|proto)=|$)')

SCANNER_TOKENS = (
    "nikto", "nuclei", "ffuf", "gobuster", "dirbuster", "masscan", "zmap", "nmap", "sqlmap",
    "zgrab", "wpscan", "acunetix", "nessus", "openvas", "qualys", "burp", "w3af", "hydra",
    "feroxbuster", "katana", "httpx", "subfinder", "amass",
)
CURL_TOKENS = ("curl", "wget", "python-requests", "go-http-client", "libwww", "httpie")

EXTENSION_CLASSES = (
    (".html", 1), (".htm", 1), (".php", 2), (".phtml", 2), (".php5", 2),
    (".asp", 3), (".aspx", 3), (".jsp", 3), (".do", 3),
    (".cgi", 4), (".sh", 4), (".pl", 4), (".py", 4),
    (".js", 5), (".json", 6), (".xml", 6), (".yaml", 6), (".yml", 6),
    (".env", 7), (".conf", 7), (".ini", 7), (".bak", 7), (".sql", 7),
)


def _count_class(count):
    """Bucket a small count into 0 none, 1 one, 2 two-to-four, 3 five-plus.

    Shared by the percent-encoding and query-parameter features so the two cannot drift into
    different bucket edges - a model cannot tell you which of its inputs changed meaning.
    """
    if count <= 0:
        return 0
    if count == 1:
        return 1
    if count <= 4:
        return 2
    return 3


def bucket_log2(value):
    """Map a non-negative count to 0..8 by bit length, so a 10 MB response and a 10 kB one differ by
    one step rather than swamping the model with the raw number."""
    if value <= 0:
        return 0
    return min(8, int(math.log(value, 2)) + 1)


def entropy_class(text):
    """Shannon entropy of a string, floored to an integer 0..8.

    High entropy in a path is what encoded payloads and random-looking scanner paths look like; low
    entropy is a normal word. It is a feature, never a decision on its own.
    """
    if not text:
        return 0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = float(len(text))
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log(probability, 2)
    return min(8, int(entropy))


def extension_class(path):
    """Classify the path's extension by the longest matching suffix (`.php5` before `.php`)."""
    lowered = path.lower().split("?")[0]
    best = (0, -1)
    for suffix, klass in EXTENSION_CLASSES:
        if lowered.endswith(suffix) and len(suffix) > best[1]:
            best = (klass, len(suffix))
    if best[0]:
        return best[0]
    dot = lowered.rsplit("/", 1)[-1]
    return 8 if "." in dot else 0


def ua_class(user_agent):
    """Coarse User-Agent class. The string itself never reaches the model - it is attacker-chosen."""
    lowered = user_agent.lower()
    if not lowered:
        return 0
    if any(token in lowered for token in CURL_TOKENS):
        return 1
    if any(token in lowered for token in SCANNER_TOKENS):
        return 2
    if "mozilla/" in lowered and ("chrome/" in lowered or "firefox/" in lowered or "safari/" in lowered):
        return 3
    return 4


def parse_line(line):
    """Parse one access-log line into a dict, or return None when the line is not an access line.

    Returning None rather than raising matters: a tail reads whatever is in the file, including
    startup banners, error lines and partial writes. A malformed line is a non-event.
    """
    match = LINE_RE.match(line.rstrip("\n"))
    if not match:
        return None
    record = match.groupdict()
    extras = {}
    for key, value in EXTRA_RE.findall(record.get("extras") or ""):
        value = value.strip().strip('"')
        # Apache writes `-` for "this field was not recorded". Treating that as a value makes an
        # absent Content-Length look present, which inverts the bodyless-request feature the h2
        # signatures depend on (`cl=0` is a declared zero; `cl=-` is "no header sent").
        extras[key] = "" if value == "-" else value
    record["extras"] = extras
    return record


def line_features(line):
    """Turn one log line into the named feature dict, or None if the line is not an access line."""
    record = parse_line(line)
    if record is None:
        return None

    target = record["target"]
    path, _, query = target.partition("?")
    method = record["method"]
    version = record.get("version") or ""
    status = int(record["status"])
    extras = record["extras"]
    protocol = (extras.get("proto") or ("HTTP/" + version if version else "")).upper()

    method_class = {"GET": 0, "HEAD": 1, "POST": 2, "PUT": 3, "DELETE": 4, "OPTIONS": 5,
                    "PRI": 7}.get(method, 6)
    if protocol in ("HTTP/1.0",):
        protocol_class = 0
    elif protocol in ("HTTP/1.1", "HTTP/1"):
        protocol_class = 1
    elif protocol == "H2" or protocol.endswith("/2") or protocol == "HTTP/2":
        protocol_class = 2
    elif protocol == "H2C":
        protocol_class = 3
    else:
        protocol_class = 4

    lowered_path = path.lower()
    encoded = lowered_path.replace("%2e", ".").replace("%2f", "/")
    has_dot_segment = any(segment in (".", "..") for segment in encoded.split("/"))
    percent_count = lowered_path.count("%")

    query_params = [part for part in query.split("&") if part] if query else []
    content_length = extras.get("cl")
    body_bytes = 0
    if content_length and content_length.isdigit():
        body_bytes = int(content_length)
    response_bytes = int(record["bytes"]) if record.get("bytes", "").isdigit() else 0

    return {
        "method_class": method_class,
        "protocol_class": protocol_class,
        "status_class": min(4, (status // 100) - 2) if 200 <= status < 600 else 4,
        "path_len_log2": bucket_log2(len(path)),
        "path_depth": min(6, len([part for part in path.split("/") if part])),
        "path_entropy_log2": entropy_class(path),
        "has_double_slash": 1 if "//" in path else 0,
        "has_dot_segment": 1 if has_dot_segment else 0,
        "has_percent": 1 if percent_count else 0,
        "percent_count_class": _count_class(percent_count),
        "has_semicolon": 1 if ";" in path else 0,
        "extension_class": extension_class(path),
        "query_present": 1 if query else 0,
        "query_len_log2": bucket_log2(len(query)),
        "query_param_count_class": _count_class(len(query_params)),
        "ct_present": 1 if extras.get("ct") else 0,
        "cl_present": 1 if content_length else 0,
        "cl_is_zero": 1 if content_length == "0" else 0,
        "host_is_localhost": 1 if (extras.get("ho") or "").lower().split(":")[0] == "localhost" else 0,
        "referer_present": 1 if (record.get("referer") or "") not in ("", "-") else 0,
        "ua_class": ua_class(record.get("ua") or ""),
        "ua_len_log2": bucket_log2(len(record.get("ua") or "")),
        "body_bytes_log2": bucket_log2(body_bytes),
        "resp_bytes_log2": bucket_log2(response_bytes),
        "is_4xx": 1 if 400 <= status < 500 else 0,
        "is_5xx": 1 if 500 <= status < 600 else 0,
        "path_has_wp": 1 if ("wp-" in lowered_path or lowered_path.startswith("/wp/")) else 0,
        "path_has_api": 1 if ("/api/" in lowered_path or lowered_path.startswith("/api")) else 0,
    }


def to_vector(record):
    """Flatten a feature dict into the model's input, in FEATURES order.

    A missing key raises rather than defaulting: a vector silently shorter than the model expects is
    the exact failure this module exists to prevent.
    """
    return [float(record[name]) for name in FEATURES]
