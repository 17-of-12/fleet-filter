#!/usr/bin/env python3
"""Tests for how `Store.claim` treats a claim whose lease has already lapsed (PTN-09).

The claim table keeps rows after their `expires_at` passes - `active()` filters them, `purge`
deletes them - so `claim()` has to decide what an expired row *means*. It used to treat it as a
standing verdict: a new `suspect` observation was compared against the expired `confirmed` one,
found weaker, and only extended the expiry, which left the address labelled `confirmed` on evidence
that had expired. That is the review's PTN-09, reproduced in isolation and now covered here.

Runs under Python 3.9 and 3.12; skips cleanly when PyYAML is unavailable.
"""

from __future__ import print_function

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

try:
    import yaml  # noqa: F401
except ImportError:
    print("SKIP test_claim_expiry.py: PyYAML unavailable for %s" % sys.version.split()[0])
    raise SystemExit(0)

SPEC = importlib.util.spec_from_file_location("adaptive_tarpit",
                                              os.path.join(ROOT, "controller", "adaptive-tarpit.py"))
at = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(at)

PASS = 0
FAIL = 0


def check(condition, label, detail=""):
    """Record one assertion and print it, accumulating instead of raising on the first failure."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print("ok   %s" % label)
    else:
        FAIL += 1
        print("FAIL %s %s" % (label, detail))


def fresh_store(work, name="state.db"):
    """Return an empty, writable store inside `work`."""
    return at.Store(os.path.join(work, name))


def age_claim(store, ip, claim_key, seconds_ago=10):
    """Move a claim's lease into the past the way an expired lease looks in a live store."""
    verdict = row(store, ip, claim_key)["verdict"]
    expires_at = at.now() - int(seconds_ago)
    store.conn.execute(
        "UPDATE claims SET created_at = ?, expires_at = ? WHERE ip = ? AND claim_key = ?",
        (expires_at - at.DEFAULT_TTL[verdict], expires_at, ip, claim_key),
    )
    store.conn.commit()


def row(store, ip, claim_key):
    """Read one stored claim row as a dict, so assertions can name the field they check."""
    row = store.conn.execute(
        "SELECT verdict, source, author, created_at, expires_at FROM claims WHERE ip = ?"
        " AND claim_key = ?", (ip, claim_key)).fetchone()
    return {"verdict": row[0], "source": row[1], "author": row[2],
            "created_at": row[3], "expires_at": row[4]}


def main():
    """Exercise every expiry case PTN-09 covers and exit non-zero if any of them regress."""
    with tempfile.TemporaryDirectory() as work:
        store = fresh_store(work)

        # 1. the control case: a live confirmed claim is never downgraded by a weaker observation.
        store.claim("198.51.100.60", "confirmed", source="sig-a", author="pi")
        live = store.claim("198.51.100.60", "suspect", source="sig-a", author="pi")
        check(live == "unchanged", "a live confirmed claim plus a suspect claim is unchanged", live)
        check(row(store, "198.51.100.60", "sig-a")["verdict"] == "confirmed",
              "the live confirmed verdict is what stays stored")

        # 2. PTN-09: the same pair, but the confirmed lease had expired.
        store.claim("198.51.100.61", "confirmed", source="sig-b", author="pi")
        check(any(e["ip"] == "198.51.100.61" for e in store.active()),
              "sanity: the fresh confirmed claim is active before it is aged", str(store.active()))
        age_claim(store, "198.51.100.61", "sig-b")
        check(all(e["ip"] != "198.51.100.61" for e in store.active()),
              "aging the lease removes the address from active()", str(store.active()))
        moment = at.now()
        revived = store.claim("198.51.100.61", "suspect", source="sig-b", author="pi")
        check(revived == "revived", "a suspect claim on an expired confirmed row revives it", revived)
        stored = row(store, "198.51.100.61", "sig-b")
        check(stored["verdict"] == "suspect",
              "the revived address is suspect, not confirmed on expired evidence", str(stored))
        check(stored["created_at"] >= moment,
              "the revived window is dated from the new observation, not the expired one", str(stored))
        check(stored["expires_at"] - stored["created_at"] == at.DEFAULT_TTL["suspect"],
              "the revived lease lasts exactly the suspect TTL", str(stored))
        active = [e for e in store.active() if e["ip"] == "198.51.100.61"]
        check(len(active) == 1 and active[0]["verdict"] == "suspect",
              "active() reports the new verdict for the revived address", str(active))

        # 3. the other direction: an expired suspect row and a new confirmed claim.
        store.claim("198.51.100.62", "suspect", source="sig-c", author="pi")
        age_claim(store, "198.51.100.62", "sig-c")
        revived = store.claim("198.51.100.62", "confirmed", source="sig-c", author="pi")
        check(revived == "revived", "a confirmed claim on an expired suspect row revives it", revived)
        check(row(store, "198.51.100.62", "sig-c")["verdict"] == "confirmed",
              "the new stronger verdict is stored")
        check(row(store, "198.51.100.62", "sig-c")["expires_at"] -
              row(store, "198.51.100.62", "sig-c")["created_at"] == at.DEFAULT_TTL["confirmed"],
              "the confirmed TTL applies from now, not from the expired suspect claim")

        # 4. a different identity is a separate claim, so expiry handling must not touch it.
        other = store.claim("198.51.100.61", "suspect", source="sig-d", author="pi")
        check(other == "added", "a new claim_key on the same address is still an add", other)
        check(row(store, "198.51.100.61", "sig-d")["verdict"] == "suspect",
              "the unrelated claim is stored independently of the revived one")

        # 5. idempotency survives revival: claiming the same live identity twice is a no-op.
        repeat = store.claim("198.51.100.61", "suspect", source="sig-b", author="pi")
        check(repeat == "unchanged", "repeating a claim on the freshly revived row is unchanged", repeat)

        # 6. an explicit TTL is honoured on the revival path too, not just on the add path.
        store.claim("198.51.100.63", "confirmed", source="sig-e", author="pi", ttl=60)
        age_claim(store, "198.51.100.63", "sig-e", 5)
        store.claim("198.51.100.63", "suspect", source="sig-e", author="pi", ttl=120)
        revived_row = row(store, "198.51.100.63", "sig-e")
        check(revived_row["expires_at"] - revived_row["created_at"] == 120,
              "an explicit ttl is honoured when reviving", str(revived_row))

    print("test_claim_expiry.py: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


main()
