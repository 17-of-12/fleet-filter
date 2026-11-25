#!/usr/bin/env python3
"""PT-07 slot accounting: who owns a semaphore, and what happens behind a proxy.

Purpose
-------
The responder bounds concurrency twice - a global handler pool and a per-address cap. The
benchmark in `data/results/worker-economics-2026-11-15.md` showed the per-address cap being
applied to the *socket peer*, which behind an Apache loopback proxy is the proxy itself: every
real client shared one 4-slot semaphore, so the deployed ceiling was 4 concurrent drips while
`--max-threads 32` sat unused. These tests lock in the corrected rule - the slot belongs to the
forwarded client when the peer is a trusted proxy, and to the peer otherwise - because the bug
was invisible to any test that did not run the responder behind a proxy.

What it checks
--------------
* `_peer_slot` returns None for a trusted proxy and a shared semaphore for a direct peer.
* `client_slot` gives each address its own semaphore with `per_ip_max` capacity.
* `_proxied_slot` resolves the forwarded identity through `X-Tarpit-Client` (PT-10).
* A direct (untrusted) peer gets no handler-side slot, so the accept path is not double-charged.
* Acquiring `per_ip_max` slots exhausts an address; releasing restores it.
"""

import http.client
import importlib.util
import os
import sys
import threading
import unittest
from email.message import Message

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = importlib.util.spec_from_file_location("tarpit_server", REPO + "/tarpit/server/server.py")
server_module = importlib.util.module_from_spec(SPEC)
sys.modules["tarpit_server"] = server_module
SPEC.loader.exec_module(server_module)

BoundedThreadingServer = server_module.BoundedThreadingServer
TarpitHandler = server_module.TarpitHandler


def make_server(max_threads=32, per_ip_max=4, trusted=("127.0.0.1", "::1")):
    """Return a bound-but-idle server on an ephemeral port with the given limits."""
    BoundedThreadingServer.max_threads = max_threads
    BoundedThreadingServer.per_ip_max = per_ip_max
    BoundedThreadingServer.trusted_proxies = tuple(trusted)
    return BoundedThreadingServer(("127.0.0.1", 0), TarpitHandler)


def make_handler(server, peer, forwarded=None):
    """Build a handler without running the request cycle, as the server would for `peer`."""
    handler = TarpitHandler.__new__(TarpitHandler)
    handler.server = server
    handler.client_address = (peer, 41000)
    handler.headers = Message()
    if forwarded is not None:
        handler.headers["X-Tarpit-Client"] = forwarded
    handler.request_version = "HTTP/1.1"
    handler.command = "GET"
    handler.path = "/ai.html"
    return handler


class PeerSlotTest(unittest.TestCase):
    """The accept-time rule: which address a socket peer owns a slot for."""

    def test_trusted_peer_defers_the_decision(self):
        """A trusted proxy peer owns no peer slot; the handler decides from the forwarded header."""
        server = make_server()
        try:
            self.assertIsNone(server._peer_slot("127.0.0.1"))
            self.assertIsNone(server._peer_slot("::1"))
        finally:
            server.server_close()

    def test_direct_peer_owns_a_shared_semaphore(self):
        """Two connections from one direct address share one semaphore, not two."""
        server = make_server(per_ip_max=4)
        try:
            first = server._peer_slot("203.0.113.9")
            second = server._peer_slot("203.0.113.9")
            self.assertIsNotNone(first)
            self.assertIs(first, second)
        finally:
            server.server_close()

    def test_empty_peer_owns_nothing(self):
        """A missing peer address cannot own a slot (socketserver passes None on some paths)."""
        server = make_server()
        try:
            self.assertIsNone(server._peer_slot(None))
            self.assertIsNone(server._peer_slot("-"))
        finally:
            server.server_close()


class ClientSlotTest(unittest.TestCase):
    """The handler-side rule: each resolved client address owns its own capacity."""

    def test_addresses_do_not_share_a_semaphore(self):
        """Two clients get separate semaphores, which is what per_ip_max is supposed to mean."""
        server = make_server(per_ip_max=2)
        try:
            a = server.client_slot("203.0.113.1")
            b = server.client_slot("203.0.113.2")
            self.assertIsNot(a, b)
            self.assertTrue(a.acquire(blocking=False))
            self.assertTrue(a.acquire(blocking=False))
            self.assertFalse(a.acquire(blocking=False), "203.0.113.1 exceeded per_ip_max=2")
            self.assertTrue(b.acquire(blocking=False), "203.0.113.2 must not be capped by .1")
        finally:
            server.server_close()

    def test_release_restores_capacity(self):
        """Releasing a slot returns the address to service (the leak class that shrinks a pool)."""
        server = make_server(per_ip_max=1)
        try:
            slot = server.client_slot("203.0.113.3")
            self.assertTrue(slot.acquire(blocking=False))
            self.assertFalse(slot.acquire(blocking=False))
            slot.release()
            self.assertTrue(slot.acquire(blocking=False))
        finally:
            server.server_close()


class ProxiedSlotTest(unittest.TestCase):
    """PT-10 identity resolution feeding PT-07 accounting."""

    def test_forwarded_client_owns_the_slot_behind_a_proxy(self):
        """Behind a trusted proxy the slot belongs to X-Tarpit-Client, not to 127.0.0.1."""
        server = make_server(per_ip_max=4)
        try:
            handler = make_handler(server, "127.0.0.1", forwarded="203.0.113.7")
            self.assertIs(handler._proxied_slot(), server.client_slot("203.0.113.7"))
        finally:
            server.server_close()

    def test_untrusted_peer_does_not_take_a_second_slot(self):
        """A direct peer is already charged at accept time; the handler must not double-charge."""
        server = make_server()
        try:
            handler = make_handler(server, "203.0.113.8")
            self.assertIsNone(handler._proxied_slot())
        finally:
            server.server_close()

    def test_forged_header_from_an_untrusted_peer_is_ignored(self):
        """PT-10: a client cannot claim a different identity by sending the header itself."""
        server = make_server()
        try:
            handler = make_handler(server, "203.0.113.8", forwarded="198.51.100.110")
            self.assertEqual(handler._client_ip(), "203.0.113.8")
        finally:
            server.server_close()

    def test_non_ipv4_forwarded_value_falls_back_to_the_peer(self):
        """A malformed forwarded value degrades to the peer rather than becoming a slot key."""
        server = make_server()
        try:
            handler = make_handler(server, "127.0.0.1", forwarded="not-an-ip")
            self.assertEqual(handler._client_ip(), "127.0.0.1")
            self.assertIsNone(handler._proxied_slot())
        finally:
            server.server_close()


class ServerSmokeTest(unittest.TestCase):
    """The server still accepts and answers, so the slot refactor did not break the socket path."""

    def test_health_answers_over_a_real_connection(self):
        """B6 health endpoint answers on a live socket with the configured fingerprint."""
        server = make_server()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            worker = threading.Thread(target=server.handle_request)
            worker.daemon = True
            worker.start()
            conn.request("GET", "/health", headers={"User-Agent": "fleet-filter-test/1.0"})
            response = conn.getresponse()
            body = response.read().decode("utf-8")
            conn.close()
            worker.join(timeout=10)
            self.assertEqual(response.status, 200)
            self.assertIn('"status": "ok"', body)
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
