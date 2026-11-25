#!/usr/bin/env python3
"""Response-profile selection for the slow-drip responder (Bundles I1, I2, I4 and B9).

Three jobs, all of them about *which* answer the responder gives rather than how slowly it gives it:

* `load` reads and validates `tarpit/profiles/catalogue.yaml`, so a typo in a body path or a
  profile referenced by two names fails at startup instead of on the request that hits it (I1).
* `resolve_name` maps any alias used elsewhere in the project (`generic_slow`, `slow_error`,
  `api_probe`) onto the one profile id that owns it, which is what stops the responder, the
  gateway and the signature file from each inventing their own vocabulary (I4, B9).
* `select` answers "given this request, which profile, status and body?" using the original
  request context - the matched signature first, then the longest matching path prefix, then the
  vhost default - instead of serving one fixed fake path to everything (I2).
* `stream_for` answers the other half of the question - *how slowly* the selected profile's body is
  written - by resolving the catalogue's `profiles_stream_overrides` over its `stream_defaults`.
  Before this existed the block was declared but never read, so every profile dripped at the
  responder's own compiled rate and per-profile timing was decoration (I3 finding).

`load_signature_responses` is the B9 pairing read from the signature store: each variant's
`response_profile` and `verdict_to_report`. It is deliberately optional: the responder runs on a
host interpreter where PyYAML may be absent, and a responder that cannot read the pairing must keep
answering, not refuse to start.

Python 3.6-compatible (the interpreter on the oldest managed host).
"""

from __future__ import print_function

import os
import random

REQUIRED_IDENTITY = ("application", "version", "server_header")
REQUIRED_PROFILE = ("name", "media_type", "body_file", "statuses")
REQUIRED_STATUS = ("vulnerable", "absent")
# The streaming block the responder needs to drip a body. `max_response_bytes` also lives in the
# catalogue but is not listed here: the responder enforces body size through its own
# --max-body-bytes, which bounds responses served outside the catalogue too, so making the
# catalogue value authoritative would change behaviour for bodies it never selected.
STREAM_KEYS = ("min_chunk_bytes", "max_chunk_bytes", "min_chunk_delay_ms",
               "max_chunk_delay_ms", "max_response_duration_seconds")


class ProfileError(Exception):
    """Raised when the catalogue is malformed, so a bad deployment fails at startup."""


def load(path):
    """Parse and validate the catalogue at `path`; returns the catalogue dict.

    Validation is strict on purpose: every body file must exist, every alias must be unique, and
    every selection target must name a real profile. A catalogue that loads is a catalogue the
    responder can serve from without discovering a missing file mid-request.
    """
    try:
        import yaml
    except ImportError:
        raise ProfileError("PyYAML is required to read %s" % (path,))
    try:
        with open(path) as handle:
            text = handle.read()
    except OSError as exc:
        raise ProfileError("cannot read %s: %s" % (path, exc))
    try:
        data = yaml.safe_load(text)
    except Exception as exc:  # PyYAML raises several error types depending on version
        raise ProfileError("cannot parse %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ProfileError("%s must contain a mapping" % (path,))
    if str(data.get("schema")) != "1":
        raise ProfileError("%s has unsupported schema %r" % (path, data.get("schema")))

    identity = data.get("identity")
    if not isinstance(identity, dict) or not all(k in identity for k in REQUIRED_IDENTITY):
        raise ProfileError("%s: identity must define %s" % (path, ", ".join(REQUIRED_IDENTITY)))

    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ProfileError("%s: profiles must be a non-empty mapping" % (path,))
    base = os.path.dirname(os.path.abspath(path))
    seen_aliases = {}
    for pid, profile in sorted(profiles.items()):
        if not isinstance(profile, dict):
            raise ProfileError("%s: profile %s must be a mapping" % (path, pid))
        missing = [k for k in REQUIRED_PROFILE if k not in profile]
        if missing:
            raise ProfileError("profile %s is missing %s" % (pid, ", ".join(missing)))
        statuses = profile["statuses"]
        if not isinstance(statuses, dict) or not all(k in statuses for k in REQUIRED_STATUS):
            raise ProfileError("profile %s statuses must define %s" % (pid, ", ".join(REQUIRED_STATUS)))
        for key in ("body_file", "absent_body"):
            ref = profile.get(key)
            if ref is None:
                continue
            target = ref if os.path.isabs(ref) else os.path.join(base, ref)
            if not os.path.isfile(target):
                raise ProfileError("profile %s references missing body %s" % (pid, ref))
        for alias in profile.get("aliases", []) or []:
            if alias in seen_aliases:
                raise ProfileError("alias %s maps to both %s and %s" % (alias, seen_aliases[alias], pid))
            seen_aliases[alias] = pid
        for alias in (profile.get("alias_status") or {}):
            if alias not in (profile.get("aliases", []) or []) and alias != pid:
                raise ProfileError("profile %s declares a status for %r, which is not one of its "
                                   "names or aliases" % (pid, alias))

    selection = data.get("selection")
    if not isinstance(selection, dict) or "default" not in selection:
        raise ProfileError("%s: selection must define a default" % (path,))
    targets = [selection["default"]] + list((selection.get("prefixes") or {}).values())
    for target in targets:
        if target not in profiles:
            raise ProfileError("%s: selection references unknown profile %r" % (path, target))
    data["_aliases"] = seen_aliases
    data["_base"] = base
    return data


def resolve_name(catalogue, name):
    """Return the profile id a name or alias refers to, or None if the catalogue does not know it."""
    if not name:
        return None
    profiles = catalogue.get("profiles", {})
    if name in profiles:
        return name
    return catalogue.get("_aliases", {}).get(name)


def body_path(catalogue, path_ref):
    """Resolve a catalogue-relative body reference to an absolute path."""
    if path_ref is None:
        return None
    if os.path.isabs(path_ref):
        return path_ref
    return os.path.join(catalogue.get("_base", ""), path_ref)


def stream_for(catalogue, profile_id, rng=None):
    """Return how to stream `profile_id`'s body, or None when the catalogue declares no streaming.

    `select` decides *what* the responder answers; this decides *how long the answer takes to
    write*. The catalogue states streaming as ranges (1-3 byte chunks written 20-60 ms apart, capped
    at N seconds) plus a per-profile override table, and the responder used to ignore both and drip
    with its own compiled 3-byte / 50 ms / 5 s constants. That made every profile's duration a
    function of body size alone, so profile F - whose override promises 120-400 ms delays and an 8 s
    cap - actually finished in 2.769 s (measured, I3). Reading the block is what makes the declared
    fingerprint real instead of aspirational.

    One draw per response, not per chunk: a chunk size in [min_chunk_bytes, max_chunk_bytes] and a
    delay in [min_chunk_delay_ms, max_chunk_delay_ms]. Drawing once keeps the logged duration and the
    bytes actually written describing the same response, and `rng` is a parameter so a test can make
    the draw reproducible without seeding global state.

    Returns `{"chunk_size": bytes, "chunk_delay": seconds, "max_drip": seconds}` - the units
    `TarpitHandler` works in - or None when the catalogue has no `stream_defaults`, which leaves a
    pre-streaming catalogue's responder on its own constants instead of silently respeeding it.
    Raises `ProfileError` on a shape that cannot be served (min above max, non-positive duration,
    non-mapping override) because that is a catalogue bug worth failing loudly on.
    """
    defaults = catalogue.get("stream_defaults")
    if not isinstance(defaults, dict):
        return None
    overrides = catalogue.get("profiles_stream_overrides")
    if overrides is not None and not isinstance(overrides, dict):
        raise ProfileError("profiles_stream_overrides must be a mapping")
    for named, declared in (overrides or {}).items():
        if not isinstance(declared, dict):
            raise ProfileError("stream override for profile %s must be a mapping" % (named,))
    override = (overrides or {}).get(profile_id)
    merged = dict(defaults)
    merged.update(override or {})

    missing = [k for k in STREAM_KEYS if k not in merged]
    if missing:
        raise ProfileError("streaming config for profile %s is missing %s"
                           % (profile_id, ", ".join(missing)))
    low_bytes, high_bytes = int(merged["min_chunk_bytes"]), int(merged["max_chunk_bytes"])
    low_ms, high_ms = int(merged["min_chunk_delay_ms"]), int(merged["max_chunk_delay_ms"])
    cap = float(merged["max_response_duration_seconds"])
    if low_bytes < 1 or low_bytes > high_bytes:
        raise ProfileError("chunk size range %d-%d invalid for profile %s"
                           % (low_bytes, high_bytes, profile_id))
    if low_ms < 0 or low_ms > high_ms:
        raise ProfileError("chunk delay range %d-%d ms invalid for profile %s"
                           % (low_ms, high_ms, profile_id))
    if cap <= 0:
        raise ProfileError("max_response_duration_seconds must be positive for profile %s"
                           % (profile_id,))
    draw = rng if rng is not None else random
    return {"chunk_size": draw.randint(low_bytes, high_bytes),
            "chunk_delay": draw.uniform(low_ms, high_ms) / 1000.0,
            "max_drip": cap}


def select(catalogue, method, path, signature_profile=None, verdict_to_report="vulnerable"):
    """Choose the profile, status and body for one request, preserving the request's own context.

    Priority is deliberate:

    1. `signature_profile` - what the matched signature says to answer with. This is the B9
       rule: an exact exploit request gets the answer that exploit expects, not a generic body,
       because slow-and-wrong teaches a scanner it is being fooled faster than slow-and-correct.
    2. the longest matching entry in `selection.prefixes` - a request for `/api/x.json` is an
       API request whether or not a signature named it (I2).
    3. `selection.default`.

    The status then comes from the profile's `statuses` table using `verdict_to_report`, so a
    variant reported `absent` answers 404 with the profile's `absent_body` rather than claiming a
    file exists when the pairing says the honest lie is "not installed".

    Returns a dict: `profile`, `name`, `media_type`, `status`, `body_file`, `reason`.
    `reason` is machine-readable (`signature`, `path_prefix`, `default`) for the same reason the
    H4 ladder carries reason codes: the answer should be explainable after the fact.
    """
    profiles = catalogue.get("profiles", {})
    selection = catalogue.get("selection", {})
    profile_id = None
    reason = None

    if signature_profile is not None:
        profile_id = resolve_name(catalogue, signature_profile)
        if profile_id is not None:
            reason = "signature"

    if profile_id is None:
        clean = (path or "/").split("?", 1)[0].split("#", 1)[0]
        best_prefix, best_len = None, -1
        for prefix, target in (selection.get("prefixes") or {}).items():
            if clean.endswith(prefix) or clean.startswith(prefix) or clean.rstrip("/") == prefix.rstrip("/"):
                if len(prefix) > best_len:
                    best_prefix, best_len = target, len(prefix)
        if best_prefix is not None:
            profile_id, reason = best_prefix, "path_prefix"

    if profile_id is None:
        profile_id, reason = selection.get("default"), "default"

    if profile_id not in profiles:
        raise ProfileError("resolved profile %r is not defined" % (profile_id,))
    profile = profiles[profile_id]
    verdict = verdict_to_report if verdict_to_report in REQUIRED_STATUS else "vulnerable"
    # An alias may pin the status (`slow_400` must answer 400 even though the profile's default
    # error status is 404); otherwise the status comes from the profile's verdict table.
    status = int(profile.get("alias_status", {}).get(signature_profile,
                                                      profile["statuses"][verdict])) \
        if (reason == "signature" and profile.get("alias_status")) \
        else int(profile["statuses"][verdict])
    body_ref = profile["body_file"] if status == 200 else profile.get("absent_body",
                                                                      profile["body_file"])
    return {"profile": profile_id, "name": profile["name"], "media_type": profile["media_type"],
            "status": status, "body_file": body_path(catalogue, body_ref), "reason": reason,
            "verdict_to_report": verdict, "method": (method or "GET").upper()}


def load_signature_responses(path):
    """Read the B9 pairing from the signature store: variant -> (response_profile, verdict_to_report).

    Returns `{signature_id: {"default": profile, "verdict": verdict},
              "signature_id/variant_index": {"profile": ..., "verdict": ...}}`.

    Returns `{}` when the file is missing or PyYAML is unavailable - the responder keeps working
    from path-based selection rather than refusing to start, because the pairing improves the
    answer and is not what makes the service alive.
    """
    try:
        import yaml
    except ImportError:
        return {}
    try:
        with open(path) as handle:
            data = yaml.safe_load(handle.read())
    except (OSError, ValueError):
        return {}
    out = {}
    for entry in (data or {}).get("signatures", []) or []:
        if not isinstance(entry, dict) or "id" not in entry:
            continue
        signature_id = entry["id"]
        default_profile = entry.get("response_profile_default") or entry.get("response_profile")
        default_verdict = entry.get("verdict_to_report", "vulnerable")
        if default_profile:
            out[signature_id] = {"profile": default_profile, "verdict": default_verdict}
        for index, variant in enumerate(entry.get("variants", []) or []):
            if not isinstance(variant, dict):
                continue
            profile = variant.get("response_profile") or default_profile
            verdict = variant.get("verdict_to_report", default_verdict)
            if not profile:
                continue
            # Keyed three ways on purpose. The responder learns a signature from the gateway's
            # `X-Tarpit-Signature` header and from the controller's claim `source`, and those use
            # `CVE-2026-119618/probe_path`, while a caller may name only the variant or only the
            # CVE. An index-only key was the first version's bug: the header value never matched a
            # key, so every paired request silently fell back to the default profile.
            keys = ["%s/%d" % (signature_id, index)]
            if variant.get("name"):
                keys.append("%s/%s" % (signature_id, variant["name"]))
                keys.append(variant["name"])
            for key in keys:
                out[key] = {"profile": profile, "verdict": verdict}
    return out
