#!/usr/bin/env python3
"""Tests for the response-profile catalogue (Bundles I1, I2, I4) and the B9 pairing.

The catalogue is data, so the tests are mostly about the properties data can silently lose: all
seven documented profiles present, every body file actually there, no alias pointing at two
profiles, and - the one that matters most - every profile name used *elsewhere* in the project
(`controller/signatures/signatures.yaml`, `gateway/src/deception.rs`) resolving to exactly one
profile here. That check is what stops the project growing a second vocabulary for the same
deception, which is how a host ends up answering one request with two personalities.

Runs under Python 3.9 and 3.12; skips cleanly when PyYAML is unavailable.
"""

from __future__ import print_function

import importlib.util
import os
import random
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

try:
    import yaml  # noqa: F401
except ImportError:
    print("SKIP test_profiles.py: PyYAML unavailable for %s" % sys.version.split()[0])
    raise SystemExit(0)

SPEC = importlib.util.spec_from_file_location("pt_profiles",
                                              os.path.join(ROOT, "tarpit", "server", "profiles.py"))
profiles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profiles)

CATALOGUE = os.path.join(ROOT, "tarpit", "profiles", "catalogue.yaml")
SIGNATURES = os.path.join(ROOT, "controller", "signatures", "signatures.yaml")

PASS = 0
FAIL = 0


def check(condition, label):
    """Record one assertion."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s" % label)


cat = profiles.load(CATALOGUE)
check(True, "the repo catalogue loads and validates")

# --- I1: the seven documented strategies ----------------------------------------------------------
check(sorted(cat["profiles"]) == ["A", "B", "C", "D", "E", "F", "G"],
      "all seven handoff profiles A-G are defined")
for pid in sorted(cat["profiles"]):
    body = os.path.join(ROOT, "tarpit", "profiles", cat["profiles"][pid]["body_file"])
    if not os.path.isfile(body) or os.path.getsize(body) == 0:
        check(False, "profile %s body exists and is non-empty" % pid)
check(all(os.path.getsize(os.path.join(ROOT, "tarpit", "profiles", cat["profiles"][p]["body_file"])) > 0
          for p in cat["profiles"]), "every profile body exists and is non-empty")

# --- I4: the vocabulary bridge --------------------------------------------------------------------
for name, expected in [("generic_slow", "A"), ("generic", "A"), ("slow_error", "D"),
                       ("slow_404_app_shaped", "D"), ("slow_400", "D"), ("slow_json", "E"),
                       ("api_probe", "E"), ("api-probe", "E"), ("exploit-probe", "D"),
                       ("git_config", "B"), ("fake_admin", "C"), ("redirect_maze", "G"),
                       ("delayed_headers", "F")]:
    check(profiles.resolve_name(cat, name) == expected,
          "alias %s resolves to profile %s" % (name, expected))

# Every profile the signature store names must resolve here (the anti-drift assertion).
with open(SIGNATURES) as handle:
    sig = yaml.safe_load(handle.read())
names = set()
for entry in sig.get("signatures", []):
    if entry.get("response_profile"):
        names.add(entry["response_profile"])
    if entry.get("response_profile_default"):
        names.add(entry["response_profile_default"])
    for variant in entry.get("variants", []) or []:
        if variant.get("response_profile"):
            names.add(variant["response_profile"])
unresolved = sorted(n for n in names if profiles.resolve_name(cat, n) is None)
check(not unresolved,
      "every response_profile named in signatures.yaml resolves (%s)"
      % (", ".join(unresolved) if unresolved else "all %d resolved" % len(names)))

# Every profile name the Rust gateway compiles in must resolve too.
gateway_src = os.path.join(ROOT, "gateway", "src", "deception.rs")
if os.path.isfile(gateway_src):
    with open(gateway_src) as handle:
        source = handle.read()
    missing = [n for n in ("generic", "exploit-probe", "api-probe") if n not in source]
    check(not missing, "the gateway profile names are the ones the catalogue knows (%s)"
          % ", ".join(missing or ["generic, exploit-probe, api-probe"]))
    check(all(profiles.resolve_name(cat, n) for n in ("generic", "exploit-probe", "api-probe")),
          "each gateway profile name resolves to a catalogue profile")

# --- I2: selection preserves the original request context -----------------------------------------
by_sig = profiles.select(cat, "GET", "/anything", signature_profile="slow_400")
check(by_sig["profile"] == "D" and by_sig["status"] == 400 and by_sig["reason"] == "signature",
      "a signature naming slow_400 answers 400, not the profile's default 404")
by_absent = profiles.select(cat, "GET", "/anything", signature_profile="generic_slow",
                            verdict_to_report="absent")
check(by_absent["profile"] == "A" and by_absent["status"] == 404
      and by_absent["body_file"].endswith("D.error.html"),
      "a variant reported `absent` answers 404 with the absent body instead of claiming the file")
by_vuln = profiles.select(cat, "GET", "/anything", signature_profile="generic_slow",
                          verdict_to_report="vulnerable")
check(by_vuln["status"] == 200 and by_vuln["body_file"].endswith("A.env")
      and by_vuln["media_type"] == "text/plain",
      "a variant reported `vulnerable` answers 200 with the profile's own body and media type")
check(profiles.select(cat, "GET", "/api/students.json")["profile"] == "E",
      "an /api/*.json request selects E from the path, with no signature involved")
check(profiles.select(cat, "GET", "/documents/2026")["profile"] == "G",
      "the longest matching prefix wins over the default")
check(profiles.select(cat, "GET", "/totally/unknown")["profile"] == "A"
      and profiles.select(cat, "GET", "/totally/unknown")["reason"] == "default",
      "an unmatched path falls back to the configured default with reason `default`")
check(profiles.select(cat, "GET", "/anything", signature_profile="not-a-profile")["reason"]
      == "default", "an unknown signature name degrades to path/default selection rather than failing")
check(profiles.select(cat, "HEAD", "/api/x.json")["method"] == "HEAD",
      "the request method is carried through the selection for HEAD handling")
check(profiles.select(cat, "GET", "/x?y=1#z")["reason"] == "default",
      "query string and fragment are stripped before matching")

# --- B9: the pairing read from the signature store --------------------------------------------------
pairing = profiles.load_signature_responses(SIGNATURES)
check("CVE-2026-119618" in pairing, "the CVE-level pairing is present")
check(pairing.get("CVE-2026-119618/0", {}).get("verdict") == "absent"
      and profiles.resolve_name(cat, pairing["CVE-2026-119618/0"]["profile"]) == "D",
      "variant 0 (probe_path) pairs to a D-resolving profile with verdict absent, matching its 404")
check(pairing.get("CVE-2026-119618/probe_path", {}).get("verdict") == "absent"
      and profiles.resolve_name(cat, pairing["CVE-2026-119618/probe_path"]["profile"]) == "D",
      "the header form the gateway sends (`CVE-.../probe_path`) is a lookup key resolving to D")
check(pairing.get("probe_path", {}).get("verdict") == "absent",
      "the bare variant name is also a lookup key")
check(pairing.get("CVE-2026-119618/1", {}).get("verdict") == "absent",
      "variant 1 (h2c_preface_on_http1_only) reports absent, matching its 400")
check(pairing.get("CVE-2026-119618/2", {}).get("verdict") == "vulnerable",
      "variant 2 (bodyless_ct) reports vulnerable, matching its 200 .env answer")
check(all(profiles.resolve_name(cat, v["profile"]) for v in pairing.values()),
      "every profile named by the pairing resolves in the catalogue")

# --- validation failures ----------------------------------------------------------------------------
def bad_catalogue(mutate):
    """Write a mutated copy of the catalogue into a temp dir and try to load it."""
    with open(CATALOGUE) as handle:
        data = yaml.safe_load(handle.read())
    mutate(data)
    work = tempfile.mkdtemp()
    try:
        shutil.copytree(os.path.join(ROOT, "tarpit", "profiles", "bodies"),
                        os.path.join(work, "bodies"))
        with open(os.path.join(work, "catalogue.yaml"), "w") as handle:
            handle.write(yaml.safe_dump(data))
        try:
            profiles.load(os.path.join(work, "catalogue.yaml"))
            return None
        except profiles.ProfileError as exc:
            return str(exc)
    finally:
        shutil.rmtree(work, ignore_errors=True)


check(bad_catalogue(lambda d: d.pop("identity")) is not None, "a catalogue with no identity is refused")
check(bad_catalogue(lambda d: d.update(schema=2)) is not None,
      "an unknown schema version is refused rather than guessed at")
check(bad_catalogue(lambda d: d["profiles"]["A"].update(body_file="bodies/nope.env")) is not None,
      "a profile pointing at a missing body file is refused at load")
duplicate = bad_catalogue(lambda d: d["profiles"]["B"].update(aliases=["generic_slow"])) or ""
check("maps to both" in duplicate,
      "an alias claimed by two profiles is refused (%s)" % (duplicate or "no error raised",))
check(bad_catalogue(lambda d: d["selection"].update(default="Z")) is not None,
      "a default pointing at an unknown profile is refused")
check(bad_catalogue(lambda d: d["profiles"]["D"].update(alias_status={"not_an_alias": 400})) is not None,
      "an alias_status key that is not one of the profile's names is refused")

# --- streaming shape (the I3 finding): the declared drip must be the drip actually used ----------
# The catalogue used to declare chunk sizes, delays and duration caps that no code read, so every
# profile dripped at the responder's own compiled rate. These checks pin the two ways that can break
# again: an override not being applied, and a shape being accepted that cannot be served.


def stream_shape(pid, catalogue=None, seed=7):
    """Resolve one profile's streaming shape with a seeded rng so the per-response jitter is assertable."""
    return profiles.stream_for(cat if catalogue is None else catalogue, pid, rng=random.Random(seed))


shape_a = stream_shape("A")
check(shape_a is not None and 1 <= shape_a["chunk_size"] <= 3,
      "A's chunk size is drawn from the declared 1-3 byte range")
check(shape_a is not None and 0.020 <= shape_a["chunk_delay"] <= 0.060,
      "A's chunk delay is drawn from the declared 20-60 ms range")
check(shape_a is not None and shape_a["max_drip"] == 5.0, "A's duration cap is the declared 5 s")
check(stream_shape("A") == stream_shape("A"),
      "the draw is reproducible for a seeded rng, so a response's logged duration can be asserted")
shape_f = stream_shape("F")
check(shape_f is not None and 0.120 <= shape_f["chunk_delay"] <= 0.400,
      "F's override replaces the delay range with 120-400 ms instead of inheriting 20-60 ms")
check(shape_f is not None and shape_f["max_drip"] == 8.0,
      "F's override replaces the duration cap with 8 s - the value the responder used to ignore")
check(stream_shape("D")["max_drip"] == 3.0
      and 0.020 <= stream_shape("D")["chunk_delay"] <= 0.060,
      "D overrides only the duration cap (3 s) and still inherits the default chunk shape")
check(all(profiles.stream_for(cat, p, rng=random.Random(1)) is not None for p in cat["profiles"]),
      "every profile resolves a streaming shape, so no profile is left without a declared drip")

no_stream = dict(cat)
no_stream.pop("stream_defaults")
check(profiles.stream_for(no_stream, "A") is None,
      "a catalogue with no stream_defaults yields None so the responder keeps its own constants")


def stream_rejects(label, **changes):
    """Return True when stream_for refuses a streaming block built by patching the real one."""
    patched = dict(cat)
    for key, value in changes.items():
        patched[key] = value
    try:
        profiles.stream_for(patched, "A")
    except profiles.ProfileError:
        return True
    return False


check(stream_rejects("chunk range", stream_defaults=dict(cat["stream_defaults"],
                                                         min_chunk_bytes=9, max_chunk_bytes=3)),
      "a chunk range with min above max is refused rather than silently served")
check(stream_rejects("duration cap", stream_defaults=dict(cat["stream_defaults"],
                                                          max_response_duration_seconds=0)),
      "a zero duration cap is refused")
check(stream_rejects("negative delay", stream_defaults=dict(cat["stream_defaults"],
                                                            min_chunk_delay_ms=-1)),
      "a negative chunk delay is refused")
check(stream_rejects("missing key",
                     stream_defaults={k: v for k, v in cat["stream_defaults"].items()
                                      if k != "max_chunk_bytes"}),
      "a streaming block missing max_chunk_bytes is refused")
check(stream_rejects("non-mapping override",
                     stream_defaults=cat["stream_defaults"],
                     profiles_stream_overrides=dict(cat["profiles_stream_overrides"], D="nope")),
      "a per-profile override that is not a mapping is refused")

print("test_profiles.py: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
