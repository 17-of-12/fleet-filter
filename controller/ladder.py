#!/usr/bin/env python3
"""H4 escalation ladder - how long a repeat-offender address is tarpitted, and why.

Owner policy of 2026-11-16 sets the floor: "quarantine durations should be at least 72 hours if
it's active exploit attempt activity, 24 hours for broad scanning sweeps." That replaced the spec's
original 15m -> 30m -> 60m rungs, which had been in place since H4 and which the owner's rule makes
unusable - a 15-minute lease is not 24 hours, however it escalates. The rungs now read 24h -> 48h ->
72h for suspect verdicts, with `confirmed` taking 72h directly, so every verdict honours the floor
while repeat scan offenders still escalate and the ceiling still equals the exploit lease.

What "drop" means is still selectable, because the spec never defined it and the two readings
conflict: release the address (its quarantines end) or hard-block it (the firewall sense, which the
owner has ruled out as a default). `cap` remains the default - the address stops escalating at the
top rung instead of being released or hard-blocked.

Only `suspect` verdicts walk the ladder. A `confirmed` verdict is a fact, not a suspicion, and takes
its own 24h lease directly - escalating a confirmed address through suspect rungs would shorten a
lease that evidence already justified.

Every decision carries a machine-readable `reason_code` so the controller's JSONL audit line can say
why a lease got the length it did, which is what makes the ladder auditable after the fact rather than
inferred from TTLs.

Python 3.6-compatible (the interpreter on the oldest managed host).
"""

from __future__ import print_function

# Rung number -> (label, ttl_seconds). Rung 1 is the first suspicion; each repeat claim escalates.
# Owner rule 2026-11-16: a scanning sweep earns at least 24h; the ceiling matches the exploit lease.
RUNGS = {1: ("24h", 86400), 2: ("48h", 172800), 3: ("72h", 259200)}
TOP_RUNG = max(RUNGS)

# What the terminal rung ("drop") actually does to the address.
TERMINAL_MODES = ("cap", "release", "hardblock")

# A confirmed lease: active exploit activity, so the owner's 72h floor (rule of 2026-11-16).
# Repeated here so the module has no import cycle with the controller.
CONFIRMED_TTL = 259200


# What the controller uses when the caller does not choose a terminal mode. `cap` is the default
# because the owner has ruled out hard blocks as a default; see the module docstring.
DEFAULT_TERMINAL = "cap"


class LadderError(ValueError):
    """Raised when the ladder is asked for a rung it does not define."""


def resolve(prior_claims, verdict="suspect", terminal=DEFAULT_TERMINAL, confirmed_ttl=CONFIRMED_TTL):
    """Return the rung, TTL and reason code for a claim given how often that address was seen before.

    Args:
        prior_claims: number of earlier claims recorded for this address (0 for a first sighting).
        verdict: "suspect" walks the ladder; "confirmed" takes the confirmed lease directly.
        terminal: what to do once the ladder is exhausted - "cap" (stay at the top rung), "release"
                  (end the quarantine) or "hardblock" (hold it for the confirmed TTL).
        confirmed_ttl: the lease length a confirmed verdict earns.

    Returns a dict with `rung`, `ttl`, `reason_code`, `action` and `prior_claims`.
    """
    if prior_claims is None or int(prior_claims) < 0:
        raise LadderError("prior_claims must be a non-negative integer, got %r" % (prior_claims,))
    if verdict not in ("suspect", "confirmed"):
        raise LadderError("verdict must be 'suspect' or 'confirmed', got %r" % (verdict,))
    if terminal not in TERMINAL_MODES:
        raise LadderError("terminal must be one of %s, got %r" % (", ".join(TERMINAL_MODES), terminal))
    prior_claims = int(prior_claims)

    if verdict == "confirmed":
        return {"rung": "confirmed", "ttl": int(confirmed_ttl), "reason_code": "confirmed_lease",
                "action": "quarantine", "prior_claims": prior_claims}

    if prior_claims < TOP_RUNG:
        label, ttl = RUNGS[prior_claims + 1]
        reason = "first_observation" if prior_claims == 0 else "repeat_observation"
        return {"rung": label, "ttl": ttl, "reason_code": reason, "action": "quarantine",
                "prior_claims": prior_claims}

    # Ladder exhausted: the spec's fourth rung. `cap` keeps the top lease, `release` ends it,
    # `hardblock` holds it as long as a confirmed verdict would.
    if terminal == "cap":
        # The label comes from RUNGS rather than a literal: the 15m/30m/60m wording was replaced by
        # the owner's 24h/48h/72h rule, and a hardcoded "60m" here survived that change once.
        return {"rung": RUNGS[TOP_RUNG][0], "ttl": RUNGS[TOP_RUNG][1],
                "reason_code": "ladder_exhausted_cap", "action": "quarantine",
                "prior_claims": prior_claims}
    if terminal == "release":
        return {"rung": "dropped", "ttl": 0, "reason_code": "ladder_exhausted_release",
                "action": "release", "prior_claims": prior_claims}
    return {"rung": "hardblock", "ttl": int(confirmed_ttl), "reason_code": "ladder_exhausted_hardblock",
            "action": "quarantine", "prior_claims": prior_claims}
