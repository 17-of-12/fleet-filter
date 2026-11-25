#!/usr/bin/env python3
"""Regression tests for defects found by the two read-only security reviews.

Each test names the failure it prevents, because the failure is the part that is easy to forget:
a bypass reason that carried a newline, a claim the traffic source could write, and a policy digest
that arrived from the same host as the policy it described.
"""

import importlib.util
import os
import unittest
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load(name, relative):
    """Import a script whose filename is not a valid module identifier."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relative))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BypassReasonTest(unittest.TestCase):
    """A reason is free text and the map is a line-oriented format; the two must not meet raw."""

    @classmethod
    def setUpClass(cls):
        """Load the controller once."""
        cls.controller = load("ff_adaptive_tarpit", "controller/adaptive-tarpit.py")

    def test_a_newline_in_a_reason_cannot_add_a_map_line(self):
        """`\\n0.0.0.0/0 0` in a reason put the whole estate into bypass."""
        flattened = self.controller.one_line("audit requested\n0.0.0.0/0 0")
        self.assertNotIn("\n", flattened)
        self.assertEqual(flattened.split(" 0")[0], "audit requested")

    def test_whitespace_collapses_rather_than_disappearing(self):
        """The words must survive: a reason that reads differently is not evidence."""
        self.assertEqual(self.controller.one_line("  disk  \t full \n now "), "disk full now")

    def test_render_map_emits_no_reason_newline(self):
        """The rendered artifact is the thing that was injected into, so assert on it."""
        leases = [{"ip": "10.0.0.5", "quota_hits": 99, "last_seen": 0}]
        bypass = {"set_at": "now", "expires_epoch": None, "expired": False,
                  "reason": "y\n0.0.0.0/0 0"}
        rendered = self.controller.render_map(leases, [], bypass=bypass)
        # In bypass mode every lease really does render 0, so the property is not "no `0` line" -
        # it is that the attacker's text never leaves the comment it was written into.
        self.assertEqual(rendered.count("# E5 BYPASS ACTIVE"), 1)
        injected = [line for line in rendered.splitlines() if "0.0.0.0/0 0" in line]
        self.assertTrue(injected, "the reason is still recorded")
        for line in injected:
            self.assertTrue(line.startswith("#"), "reason text escaped into map data: %r" % line)


class ClaimTrustTest(unittest.TestCase):
    """The responder cannot verify a signature match, so it can only trust the peer that sent it."""

    @classmethod
    def setUpClass(cls):
        """Load the responder once."""
        cls.server = load("ff_tarpit_server", "tarpit/server/server.py")

    def handler(self, peer, header):
        """A request handler reduced to the two attributes the guard reads."""
        return SimpleNamespace(
            client_address=(peer, 1234),
            headers={"X-Tarpit-Signature": header},
            signature_header="X-Tarpit-Signature",
            signature_trusted_peers=("127.0.0.1", "::1"),
        )

    def test_a_remote_client_cannot_assert_a_signature(self):
        """Otherwise the source of the traffic writes the claim that decides its quarantine."""
        handler = self.handler("203.0.113.9", "CVE-2021-41773:cgi_encoded_dotdot")
        self.assertEqual(self.server.TarpitHandler._claimed_signature(handler), "")

    def test_the_local_gateway_can_still_assert_one(self):
        """The gateway is the component that actually matched the rule."""
        handler = self.handler("127.0.0.1", "CVE-2021-41773:cgi_encoded_dotdot")
        self.assertEqual(
            self.server.TarpitHandler._claimed_signature(handler),
            "CVE-2021-41773:cgi_encoded_dotdot",
        )


if __name__ == "__main__":
    unittest.main()
