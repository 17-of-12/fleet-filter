#!/usr/bin/env python3
"""
Fleet-Filter test responder (lab-web01.lab).

Stdlib-only slow-drip HTTP backend. Deliberately not Flask: the product is the
*timing* of the response, and WSGI gets in the way of byte-exact chunked writes
while a raw socket gives exact control. Upstream reference implementation is
crumrine/web-tarpit (Node); this exists so the Apache redirection path can be
tested on lab-web01 without adding a Node runtime to the host.

Review remediation applied (Fleet-Filter-code-review-2026-11-14.md):
  PT-03  no longer reads live DocumentRoot bytes; serves reviewed profiles, rejects
         symlinks, and uses realpath/commonpath so a sibling prefix cannot escape
  PT-06  request bodies are drained or the connection is closed, so keep-alive peers
         cannot make the next request parse out of the previous body
  PT-07  bounded thread pool, per-IP concurrency cap, socket timeouts, bounded body
         and response sizes, streaming drip with no chunk list, explicit overload
  PT-10  logs the trusted original client (X-Tarpit-Client from Apache) instead of
         the proxy address, and only trusts it from a configured trusted proxy
  PT-12  X-Tarpit marker header is opt-in (--advertise), off by default

Revert: delete /opt/tarpit/server.py, /etc/systemd/system/tarpit-test.service,
then `systemctl disable --now tarpit-test`.

Operational note: the profile index (responses/index.json) and every other setting is
read once at startup, so changing a reviewed profile or the index requires
`systemctl restart tarpit-test` - the same contract Apache has for its own config.
"""

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

# server.py is deployed as a single file (/opt/tarpit/server.py), so its own directory has to be on
# the path for the sibling profile module to import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import profiles as profile_mod  # noqa: E402  (I1/I2/B9 response-profile selection)

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python 3.6 (lab-web01's /usr/bin/python3 is 3.6.8)
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        """Backport shim: ThreadingHTTPServer only exists in the stdlib from 3.7+."""

        daemon_threads = True

# Default bodies for the reviewed response profiles. Kept short so the drip completes
# inside max_drip while still looking like a real page; the real captured bodies
# (see --error-dir / --responses-dir) take precedence when present.
NOT_FOUND_BODY = (
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
    "<html><head><title>404 Not Found</title></head>\n"
    "<body><h1>Not Found</h1>\n"
    "<p>The requested URL was not found on this server.</p>\n</body></html>\n"
)

# The real lab-web01 vhost answers 403 (not 404) for `/`, because /var/www/html has
# no index.html and Options -Indexes applies. A tarpit that answers 404 where the
# real server answers 403 is teaching the client something is wrong (see
# docs/DETECTION-INPUTS.md 4: answer correctly *and* slowly).
FORBIDDEN_BODY = (
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
    "<html><head><title>403 Forbidden</title></head>\n"
    "<body><h1>Forbidden</h1>\n"
    "<p>You don't have permission to access this resource.</p>\n</body></html>\n"
)

OK_BODY = "<!DOCTYPE HTML>\n<html><head><title>Document</title></head>\n<body>Document</body></html>\n"

# PT-03: extensions the real server *executes* rather than serves. Their bytes never
# exist in the real response, so a tarpit that returns file contents for them hands out
# application source the real vhost never would.
EXECUTABLE_EXTENSIONS = (".php", ".phtml", ".phpt", ".php5", ".php7", ".pl", ".py", ".cgi", ".asp", ".aspx")

OVERLOAD_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Connection: close\r\n"
    b"Content-Length: 0\r\n\r\n"
)

# Guards the X-Tarpit-Client / X-Forwarded-For trust path (PT-10): a value that is not a
# clean IPv4 is ignored rather than logged as an arbitrary attacker-controlled string.
# `\A/\Z` with `[0-9]` rather than `^/$` with `\d`: `$` also matches before a trailing
# newline and `\d` is Unicode-aware, so the old form believed "1.2.3.4\n" and "1.2.3.٤".
IPV4_OK = re.compile(r"\A[0-9]{1,3}(?:\.[0-9]{1,3}){3}\Z")


def valid_ipv4(value):
    """Return True for a literal dotted-quad IPv4 whose octets are all in range.

    Mirrors the controller's `validate_ip`. The two validators used to disagree (the responder
    accepted `999.1.1.1`, the controller refused to store it), which produced claims that were
    filed by the responder and then silently dropped at drain time - a failure with no log
    line explaining it. One shared rule removes that class of gap.
    """
    if not IPV4_OK.match(value):
        return False
    return all(int(octet) <= 255 for octet in value.split("."))


class BoundedThreadingServer(ThreadingHTTPServer):
    """PT-07: cap concurrent handlers globally and per client address.

    `ThreadingHTTPServer` allocates a thread per connection with no ceiling, so the
    defender's cost scales with the attacker's connection count - the exact economics
    the project says must be measured and bounded. A slot is taken *before* a thread is
    created; when the pool is full the connection gets a cheap 503 and is closed without
    allocating a handler thread or starting a slow drip.
    """

    max_threads = 32
    per_ip_max = 4
    trusted_proxies = ("127.0.0.1", "::1")

    def __init__(self, *args, **kwargs):
        """Set up the two semaphores before the base class starts accepting connections.

        Order matters: the base `__init__` begins serving, so both the global pool and the
        per-IP table must already exist or the first request races on missing state.
        """
        self._slots = threading.BoundedSemaphore(self.max_threads)
        self._ip_lock = threading.Lock()
        self._ip_slots = {}
        super(BoundedThreadingServer, self).__init__(*args, **kwargs)

    def _ip_slot(self, ip):
        """Return (creating if needed) the per-IP semaphore that caps this address's concurrency.

        One semaphore per address is what stops a single scanner from consuming the whole
        pool while other clients are still being served. Entries are never reclaimed - the
        key space is bounded by active peers plus historical addresses.
        """
        with self._ip_lock:
            sem = self._ip_slots.get(ip)
            if sem is None:
                sem = threading.BoundedSemaphore(max(1, self.per_ip_max))
                self._ip_slots[ip] = sem
            return sem

    def client_slot(self, ip):
        """Return the per-address semaphore a resolved client owns (public handler entry)."""
        return self._ip_slot(ip)

    def _peer_slot(self, peer):
        """Return the semaphore the socket peer owns, or None when the handler must decide.

        A trusted proxy multiplexes many real clients through one address. Holding that one
        semaphore at accept time applies `per_ip_max` to every client behind the proxy, so the
        measured ceiling becomes 4 for the whole proxied population instead of 4 per address.
        For trusted peers the per-IP decision is deferred to the handler, which knows the
        forwarded identity; only the global pool is enforced here.
        """
        if not peer or peer == "-":
            return None
        if peer in self.trusted_proxies:
            return None
        return self._ip_slot(peer)

    def process_request(self, request, client_address, server=None):
        """Acquire a slot before spawning a handler thread, then hand off to the base class.

        This is where PT-07's bounds are actually enforced: acquiring here rather than
        inside the thread means an over-limit peer never costs a thread, and the two
        rejection paths (global pool exhausted, per-IP cap reached) answer with the
        cheapest possible response instead of queueing.

        `server` was a positional arg on socketserver.BaseServer.process_request in 3.6
        and was removed in 3.7, so it must stay optional to work on both runtimes
        (lab-web01 runs 3.9, build01 runs 3.12, the service unit may run either).
        """
        ip = client_address[0] if client_address else "-"
        if not self._slots.acquire(blocking=False):
            self._reject(request, ip, "global")
            return
        ip_sem = self._peer_slot(ip)
        if ip_sem is not None and not ip_sem.acquire(blocking=False):
            self._slots.release()
            self._reject(request, ip, "per-ip")
            return
        try:
            if server is None:
                super(BoundedThreadingServer, self).process_request(request, client_address)
            else:
                super(BoundedThreadingServer, self).process_request(request, client_address, server)
        except Exception:
            self._slots.release()
            if ip_sem is not None:
                ip_sem.release()
            raise

    def process_request_thread(self, request, client_address):
        """Run the handler, then release both semaphores no matter how the handler exits.

        The `finally` is the only thing preventing a permanent slot leak: a handler that
        raises would otherwise leak a global slot and, over time, shrink the pool to zero.
        """
        try:
            super(BoundedThreadingServer, self).process_request_thread(request, client_address)
        finally:
            self._slots.release()
            # Release exactly what process_request acquired: a deferred (trusted-proxy) peer
            # never took a peer slot, and releasing one it does not own raises BoundedSemaphore.
            slot = self._peer_slot(client_address[0] if client_address else None)
            if slot is not None:
                slot.release()

    def _reject(self, request, ip, reason):
        """Overload path: cheapest possible answer, no thread, no drip."""
        try:
            request.sendall(OVERLOAD_RESPONSE)
        except OSError:
            pass
        self.shutdown_request(request)
        if getattr(self, "log_overload", True):
            sys.stdout.write(json.dumps({"ts": round(time.time(), 3), "client": ip,
                                         "event": "overload", "reason": reason}) + "\n")
            sys.stdout.flush()


class TarpitHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Must match the real vhost's banner byte-for-byte. lab-web01's real :80/:443
    # answer `Server: Apache/2.4.37 (Oracle Linux Server) OpenSSL/1.1.1k`; a bare
    # `Apache/2.4.37 (Oracle Linux Server)` (or the default `BaseHTTPServer/0.6
    # Python/3.9`) is a fingerprint a client can diff against the unmapped path.
    # Override with --server-banner per host; the controller should generate it.
    server_version = "Apache/2.4.37 (Oracle Linux Server) OpenSSL/1.1.1k"
    sys_version = ""
    timeout = 10  # PT-07: a stalled client must not pin a handler thread forever

    # PT-03: the responder answers from reviewed profiles, never from live app files.
    docroot = "/var/www/html"          # consulted for the status code only
    docroot_real = "/var/www/html"
    responses_dir = "/opt/tarpit/responses"
    error_dir = "/opt/tarpit/errors"   # legacy location of captured real error bodies
    responses_index = {}               # exact path -> profile filename
    catalogue = None                   # I1 catalogue (tarpit/profiles/catalogue.yaml) when configured
    signature_responses = {}           # B9 pairing: signature id -> {profile, verdict_to_report}
    read_docroot = False               # opt-in: serve reviewed static bytes from the docroot
    max_file_bytes = 262144
    max_body_bytes = 65536
    executable_extensions = EXECUTABLE_EXTENSIONS

    chunk_size = 3
    chunk_delay = 0.05
    max_drip = 5.0
    marker_header = "X-Tarpit"
    charset = "UTF-8"                # I4 identity charset; the catalogue can override it
    marker_value = "test"              # PT-12: empty string omits the header entirely
    trusted_proxies = ("127.0.0.1", "::1")
    keep_alive = True

    # Bundle B6 - a health endpoint that answers immediately and never slow-drips. Without it there
    # is no way to ask "is the responder alive" without paying the drip, so a monitor either times
    # out or becomes a slow client that holds a handler slot for max_drip seconds on every check.
    # The path is configurable because the Stage 2 gateway and the container front this service and
    # may already own /health for their own purposes.
    health_path = "/health"
    started_at = time.time()
    _served_lock = threading.Lock()
    _served = 0
    _inflight = 0

    # Bundle L4 - reporting Tier 1 hits back to the controller.
    claim_spool = ""                  # directory to file claims in; "" disables reporting
    claim_min_interval = 300          # seconds between repeat claims for one (ip, signature)
    claim_author = ""                 # defaults to the hostname when empty
    signature_header = "X-Tarpit-Signature"
    # Only a peer that is already inside the trust boundary may assert that a signature fired: the
    # controller and the gateway on this host. A value from anywhere else is ignored, not recorded.
    signature_trusted_peers = ("127.0.0.1", "::1")
    _claim_lock = threading.Lock()
    _claim_seen = {}                  # (ip, signature) -> epoch last filed

    def _claimed_signature(self):
        """The signature this request claims, when the claim comes from a trusted peer.

        The header is what the gateway sends after matching a rule. The responder cannot verify the
        match itself, so trust is the only control it has - and trusting every client made the claim
        record writable by the thing it is supposed to describe.
        """
        peer = self.client_address[0]
        if peer not in self.signature_trusted_peers:
            return ""
        return (self.headers.get(self.signature_header) or "").strip()

    # ---- profile plumbing -------------------------------------------------------

    def _profile_body(self, status):
        """PT-03: reviewed bytes for this status, never live application source."""
        for directory in (self.responses_dir, self.error_dir):
            path = os.path.join(directory, "%d.html" % status)
            body = self._read_bounded(path)
            if body is not None:
                return body
        return {200: OK_BODY, 403: FORBIDDEN_BODY}.get(status, NOT_FOUND_BODY)

    def _read_bounded(self, path):
        """Read a reviewed profile file, refusing symlinks and oversized content."""
        try:
            if not os.path.isfile(path) or os.path.islink(path):
                return None
            size = os.path.getsize(path)
            if size > self.max_file_bytes:
                with open(path, "rb") as handle:
                    return handle.read(self.max_file_bytes).decode("utf-8", "replace")
            with open(path, "rb") as handle:
                return handle.read().decode("utf-8", "replace")
        except OSError:
            return None

    def _docroot_status(self, path):
        """Ask the filesystem what the real vhost would answer, without reading it.

        PT-03 fixes three separate escapes in the previous implementation:
          * `candidate.startswith(docroot)` accepted siblings such as `/tmp/www-backup`
            for docroot `/tmp/www` - replaced with a realpath/commonpath containment test;
          * `os.path.isfile` followed symlinks, so `docroot/link -> /etc/passwd` was
            served - symlinks are now refused outright;
          * any regular file was returned verbatim, so a `.php` file Apache *executes*
            was disclosed as source - executable extensions now never yield their bytes.
        """
        if not self.docroot or not os.path.isdir(self.docroot_real):
            return 404, None
        target = os.path.normpath(os.path.join(self.docroot_real, path.lstrip("/")))
        real = os.path.realpath(target)
        try:
            contained = os.path.commonpath([real, self.docroot_real]) == self.docroot_real
        except ValueError:  # cannot happen on POSIX, but never widen the boundary on error
            contained = False
        if not contained:
            return 403, None                      # symlink or prefix escape
        if os.path.islink(target):
            return 403, None                      # unreadable through a link we cannot vet
        ext = os.path.splitext(target)[1].lower()
        if os.path.isfile(target):
            if ext in self.executable_extensions:
                return 200, None                  # real server executes it: no bytes to leak
            return 200, target
        if os.path.isdir(target):
            index = os.path.join(target, "index.html")
            if os.path.isfile(index) and not os.path.islink(index):
                return 200, index
            return 403, None                      # Options -Indexes in force
        return 404, None

    def _catalogue_selection(self, path):
        """Ask the I1 catalogue what this request deserves; returns None when it cannot answer.

        The matched signature (the B9 pairing) wins over the path, and the path wins over the
        default, so a request keeps the personality of the thing that triggered it instead of being
        served a fixed fake body whatever it asked for (I2). A catalogue error or an unreadable body
        degrades to the legacy resolution rather than failing the request: the responder's job is to
        answer, so a profile defect should cost plausibility, not availability.
        """
        if self.catalogue is None:
            return None
        signature = self._claimed_signature()
        pairing = self.signature_responses.get(signature) or {}
        try:
            return profile_mod.select(self.catalogue, self.command, path,
                                      signature_profile=pairing.get("profile"),
                                      verdict_to_report=pairing.get("verdict", "vulnerable"))
        except profile_mod.ProfileError:
            return None

    def _resolve(self):
        """Return (status, body, media_type, stream) for the current request.

        Resolution order is the documented one: the profile catalogue (I1/I2/B9) when configured,
        then the reviewed per-path index, then the live docroot's status, then the per-status
        reviewed body. Every step degrades to the next rather than failing the request.

        `stream` is the catalogue's streaming shape for the selected profile (`profiles.stream_for`),
        or None whenever the answer did not come from the catalogue: a docroot or per-status body is
        served with the handler's own constants, because nothing else declared how it should drip.
        Resolving it here rather than inside `_drip` keeps the duration logged for a response and the
        bytes written to it on one decision instead of two draws.
        """
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        selection = self._catalogue_selection(path)
        if selection is not None:
            body = self._read_bounded(selection["body_file"]) if selection["body_file"] else None
            if body is not None:
                return (selection["status"], body, selection["media_type"],
                        profile_mod.stream_for(self.catalogue, selection["profile"]))
        candidates = [path]
        if path.endswith("/"):
            candidates.append(path.rstrip("/") or "/")
        else:
            candidates.append(path + "/")
        for candidate in candidates:
            profile = self.responses_index.get(candidate)
            if profile:
                body = self._read_bounded(os.path.join(self.responses_dir, profile)) \
                    or self._read_bounded(profile)
                if body is not None:
                    return 200, body, "text/html", None
        status, readable = self._docroot_status(path)
        if self.read_docroot and readable and status == 200:
            body = self._read_bounded(readable)
            if body is not None:
                return 200, body, "text/html", None
        return status, self._profile_body(status), "text/html", None

    # ---- request framing --------------------------------------------------------

    def _drain_body(self):
        """PT-06: consume the request body, or close the connection trying.

        The previous implementation answered POST without reading the body, so on a
        keep-alive connection the leftover bytes became the next request line (a 4-byte
        body produced `501 Unsupported method ('ABCDGET')`). Either the body is consumed
        within the size budget or the connection is closed, so framing can never desync.
        """
        transfer = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in transfer:
            return self._drain_chunked()
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return True  # no body framing on GET/HEAD: nothing to drain
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            return False
        if length < 0:
            return False
        if length > self.max_body_bytes:
            return False  # too big to swallow: close instead of leaving it in the stream
        if length:
            try:
                if self.rfile.read(length) is None:
                    return False
            except OSError:
                return False
        return True

    def _drain_chunked(self):
        """Bounded chunked-body drain. Any framing anomaly closes the connection."""
        try:
            remaining = self.max_body_bytes
            while remaining > 0:
                line = self.rfile.readline(64)
                if not line:
                    return False
                token = line.strip().split(b";")[0]
                try:
                    size = int(token, 16)
                except ValueError:
                    return False
                if size == 0:
                    self.rfile.readline(64)  # final CRLF (or trailers we do not need)
                    return True
                to_read = min(size, remaining)
                got = self.rfile.read(to_read)
                if got is None or len(got) < to_read:
                    return False
                remaining -= to_read
                self.rfile.readline(64)      # CRLF after each chunk
            return False  # body exceeded the budget
        except (OSError, ValueError):
            return False

    # ---- identity ---------------------------------------------------------------

    def _client_ip(self):
        """PT-10: report the quarantined client, not the proxy that forwarded to us.

        Under an Apache loopback proxy `self.client_address` is 127.0.0.1, which made
        every backend log line indistinguishable and blocked per-source accounting. The
        vhost now sets `X-Tarpit-Client` from `%{REMOTE_ADDR}` and overwrites inbound
        `X-Forwarded-For`, and this method only trusts those headers when the socket peer
        is a configured trusted proxy - an attacker cannot forge their way past a
        loopback-only backend that ignores headers from anyone else.
        """
        peer = self.client_address[0] if self.client_address else "-"
        if peer in self.trusted_proxies:
            value = self.headers.get("X-Tarpit-Client")
            if not value and self.headers.get("X-Forwarded-For"):
                value = self.headers.get("X-Forwarded-For").split(",")[-1]
            if value:
                value = value.strip()
                if valid_ipv4(value):
                    return value
        return peer

    # ---- response ---------------------------------------------------------------

    def _file_signature_claim(self):
        """Bundle L4: report a Tier 1 signature hit into the controller's claim spool.

        Called before the response is written, not after. The observation - "this address
        sent a request matching an exploit signature" - is true whether or not the client
        waits for the slow answer, and a scanner hanging up mid-drip is the normal outcome;
        filing after the drip would lose most observations, which is the same class of bug
        as PT-01 (state that only sometimes survives).

        The responder writes a file instead of opening the SQLite store, so the process that
        faces the network still has no write path to authoritative state
        (DETECTION-INPUTS.md 9, "one writer"). `adaptive-tarpit drain-spool` folds the file
        into the claim table, and the same mechanism is what Bundle R specifies for the
        Stage 2 gateway - one contract, two producers.

        The verdict is `confirmed` because a Path A signature match is the categorical case:
        the owner's rule is that sending exploit code is 100% certainty, so it takes the
        24-hour confirmed TTL rather than the suspect ladder. The duration itself stays the
        controller's decision - the claim omits `ttl` so the store applies its own policy.
        """
        if not self.claim_spool:
            return
        signature = self._claimed_signature()
        if not signature:
            # Only signature-matched requests carry this header. A request from an already
            # quarantined address is served without it, so quarantining never renews itself
            # through this path.
            return
        client = self._client_ip()
        if not client or client == "-":
            return

        moment = int(time.time())
        key = (client, signature)
        with self._claim_lock:
            last = self._claim_seen.get(key)
            if last is not None and moment - last < self.claim_min_interval:
                return
            self._claim_seen[key] = moment

        claim = {
            "subject_ip": client,
            "verdict": "confirmed",
            "source": "tarpit-responder",
            "author": self.claim_author or socket.gethostname(),
            "claim_key": "signature:%s" % signature,
            "evidence": {
                "signature": signature,
                "method": self.command,
                "path": self.path,
                "observed_at": moment,
            },
        }
        # Filename carries the epoch and both identities so a queue can be read without
        # opening the files, and `drain-spool`'s oldest-first ordering matches submission
        # order. Written as .tmp then renamed: a producer that wrote in place would let the
        # consumer read a partial JSON document.
        name = "%d-%s.json" % (moment, _safe_filename("%s-%s" % (client, signature)))
        try:
            os.makedirs(self.claim_spool, exist_ok=True)
            tmp = os.path.join(self.claim_spool, name + ".tmp")
            with open(tmp, "w") as handle:
                json.dump(claim, handle, sort_keys=True)
            os.replace(tmp, os.path.join(self.claim_spool, name))
        except OSError as exc:
            # Reporting is best-effort: a full or read-only spool must not turn a working
            # tarpit response into a 500.
            sys.stderr.write("claim spool write failed: %s\n" % exc)

    def _proxied_slot(self):
        """Return the per-client slot the accept path could not decide, or None if none applies.

        The server keys its per-IP semaphore to the socket peer, which behind a trusted proxy is
        the proxy rather than the client. When the peer is trusted and the forwarded identity
        differs from it, the handler takes the slot belonging to the real client so `per_ip_max`
        bounds one address instead of every client that shares the proxy.
        """
        server = getattr(self, "server", None)
        if not isinstance(server, BoundedThreadingServer):
            return None
        peer = self.client_address[0] if self.client_address else "-"
        if peer not in server.trusted_proxies:
            return None            # the accept path already holds the correct slot
        client = self._client_ip()
        if client == peer:
            return None
        return server.client_slot(client)

    def _reject_overload(self, started):
        """Answer 503 with no drip when this client already holds every slot (PT-07).

        Mirrors the accept-time rejection so an over-limit client gets the same cheap answer
        whichever path caught it; the response is written without a profile lookup so the
        rejection itself cannot become a second source of cost.
        """
        self.close_connection = True
        self.send_response(503)
        self.send_header("Content-Length", "0")
        if self.marker_value:
            self.send_header(self.marker_header, self.marker_value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.log_request_full(503, 0, time.time() - started, False)

    def _drip(self, body_bytes, stream=None):
        """Stream the body in small slices; no chunk list is materialised (PT-07).

        `stream` is the shape resolved by `profiles.stream_for` (chunk_size / chunk_delay /
        max_drip). Without it the handler uses its own class constants, which is what keeps
        non-catalogue responses - and catalogues written before streaming was declared - behaving
        exactly as they did before.
        """
        if not body_bytes:
            slices = [b""]
        else:
            slices = memoryview(body_bytes)
        chunk_size = stream["chunk_size"] if stream else self.chunk_size
        chunk_delay = stream["chunk_delay"] if stream else self.chunk_delay
        max_drip = stream["max_drip"] if stream else self.max_drip
        total = len(body_bytes) or 1
        n_chunks = max(1, (total + chunk_size - 1) // chunk_size)
        delay = min(chunk_delay, max_drip / float(n_chunks))
        try:
            if not body_bytes:
                self.wfile.write(b"")
            else:
                for offset in range(0, total, chunk_size):
                    self.wfile.write(bytes(slices[offset:offset + chunk_size]))
                    self.wfile.flush()
                    if delay:
                        time.sleep(delay)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Client gave up waiting - the normal outcome for a tarpitted scanner.
            return False
        return True

    def _health_json(self):
        """B6: the health payload - facts a monitor can assert on, nothing that varies randomly.

        Carrying the fingerprint knobs in the answer means a mis-deployed responder (wrong banner,
        wrong drip settings, reporting disabled) is visible from its own health response instead of
        only from a diff of the systemd unit, which is the failure that actually happens.
        """
        return json.dumps({
            "status": "ok",
            "service": "adaptive-tarpit-responder",
            "uptime_seconds": int(time.time() - self.started_at),
            "requests_served": self._served,
            "inflight": self._inflight,
            "fingerprint": {
                "server": self.server_version,
                "chunk_size": self.chunk_size,
                "chunk_delay": self.chunk_delay,
                "max_drip": self.max_drip,
                "claim_spool": bool(self.claim_spool),
            },
        }, sort_keys=True)

    def _respond_json(self, started, body):
        """Answer 200 with JSON immediately - no drain, no drip, no profile lookup (B6)."""
        body_bytes = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body_bytes)
        self.log_request_full(200, len(body_bytes), time.time() - started, True)

    def _serve(self, include_body=True):
        """Build and deliver the response for the current request.

        Order is load-bearing: the request body is drained *before* anything is written,
        because answering first would strand unread bytes in the socket and desynchronise
        the next pipelined request on a keep-alive connection (PT-06). For HEAD the delay
        is applied before the headers are flushed rather than after, since sleeping after
        an empty body lets a timing scanner see a ~15 ms answer from a "slow" server.
        """
        started = time.time()
        self._count_request()
        if self.path.split("?", 1)[0].rstrip("/") == (self.health_path or "").rstrip("/"):
            # B6: the one path that is neither profiled nor dripped, and files no claim - a
            # monitoring probe must not become a claim author or consume a slow-drip slot.
            self._respond_json(started, self._health_json())
            return
        slot = self._proxied_slot()
        if slot is not None and not slot.acquire(blocking=False):
            self._reject_overload(started)
            return
        try:
            self._file_signature_claim()
            framed = self._drain_body()
            if not framed:
                self.close_connection = True
            elif not self.keep_alive:
                self.close_connection = True
            status, body, media_type, stream = self._resolve()
            body_bytes = body.encode("utf-8")
            # The catalogue's shape for this profile when it declares one; the handler's own
            # constants govern only the responses the catalogue did not select.
            chunk_size = stream["chunk_size"] if stream else self.chunk_size
            chunk_delay = stream["chunk_delay"] if stream else self.chunk_delay
            max_drip = stream["max_drip"] if stream else self.max_drip
            duration = min(max_drip,
                           chunk_delay * max(1, (len(body_bytes) + chunk_size - 1) // chunk_size))
            if not include_body:
                # HEAD has no body to trickle, so the cost is applied before the response
                # is flushed. Sleeping afterwards lets curl return in ~15 ms off a
                # "slow" server, which is itself a tell.
                time.sleep(duration)
            self.send_response(status)
            self.send_header("Content-Type", "%s; charset=%s" % (media_type, self.charset))
            self.send_header("Content-Length", str(len(body_bytes)))
            if self.marker_value:  # PT-12: only advertise when explicitly configured
                self.send_header(self.marker_header, self.marker_value)
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            if include_body:
                delivered = self._drip(body_bytes, stream)
            else:
                delivered = True
            self.log_request_full(status, len(body_bytes), time.time() - started, delivered)
        finally:
            if slot is not None:
                slot.release()

    def do_GET(self):
        """GET -> profiled slow response (the normal scanner request shape)."""
        self._serve(include_body=True)

    def do_HEAD(self):
        """HEAD -> headers only, but still slow: a scanner timing a HEAD must not get a fast answer either."""
        self._serve(include_body=False)

    def do_POST(self):
        """POST -> slow response; the body was already drained by _serve (PT-06)."""
        self._serve(include_body=True)

    def do_PUT(self):
        """PUT -> slow response, same path as POST (exploit probes use non-GET methods)."""
        self._serve(include_body=True)

    def do_DELETE(self):
        """DELETE -> slow response, so the method set does not itself fingerprint the tarpit."""
        self._serve(include_body=True)

    def do_OPTIONS(self):
        """OPTIONS -> slow response; answering it (rather than 501) avoids the fingerprint of a minimal server."""
        self._serve(include_body=True)

    def _count_request(self):
        """B6: increment the served-request counter shared by every handler thread."""
        with TarpitHandler._served_lock:
            TarpitHandler._served += 1

    def log_request_full(self, status, size, elapsed, delivered):
        """Emit one structured access record per request.

        Logs both `peer` (the socket address, i.e. the proxy when fronted by Apache) and
        `client` (the restored origin address, PT-10), plus `delivered` so a response the
        client abandoned mid-drip is distinguishable from one it read to the end.
        """
        sys.stdout.write(json.dumps({
            "ts": round(time.time(), 3),
            "peer": "%s:%s" % (self.client_address[0], self.client_address[1]),
            "client": self._client_ip(),
            "method": self.command,
            "path": self.path,
            "status": status,
            "bytes": size,
            "seconds": round(elapsed, 3),
            "delivered": delivered,
            "keepalive": not self.close_connection,
        }) + "\n")
        sys.stdout.flush()

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib override
        """Suppress the stdlib's stderr access log; log_request_full is the only log line."""
        return


def _safe_filename(value):
    """Reduce an arbitrary string to something safe to embed in a filename.

    Claim filenames carry the client address and the signature reference, and either can
    contain characters the filesystem will not accept (`:` from an IPv6 address, `/` from a
    signature reference). Truncation bounds the name, because a producer that lets a header
    value flow into a path should not be able to create a 4 KB filename.
    """
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:80]


def build_index(responses_dir):
    """Load the reviewed path->profile index (PT-03: an explicit public-file allowlist)."""
    path = os.path.join(responses_dir, "index.json")
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if isinstance(value, str)}


def main():
    """Parse the service configuration and start the bounded server.

    Every knob here is a deployment decision captured in the systemd unit rather than a
    default in code, because the responder's fingerprint (banner, chunk size, drip cap)
    has to match the real vhost on the specific host it fronts.
    """
    parser = argparse.ArgumentParser(description="Fleet-Filter slow-drip responder")
    parser.add_argument("--bind", default="127.0.0.1", help="bind address (default loopback only)")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--docroot", default="/var/www/html",
                        help="real vhost DocumentRoot, consulted for the status code only")
    parser.add_argument("--responses-dir", default="/opt/tarpit/responses",
                        help="reviewed response profiles: <status>.html plus index.json")
    parser.add_argument("--error-dir", default="/opt/tarpit/errors",
                        help="legacy captured error bodies, named <status>.html")
    parser.add_argument("--profiles", default="",
                        help="I1 response-profile catalogue (tarpit/profiles/catalogue.yaml); "
                             "empty keeps the legacy per-status responses")
    parser.add_argument("--signature-store", default="",
                        help="B9 pairing source: the controller signature store, read for each "
                             "variant's response_profile and verdict_to_report")
    parser.add_argument("--read-docroot", action="store_true",
                        help="serve reviewed static bytes from the docroot (default off: "
                             "PT-03 - the responder must not expose live application files)")
    parser.add_argument("--max-file-bytes", type=int, default=262144,
                        help="largest profile/response body served")
    parser.add_argument("--max-body-bytes", type=int, default=65536,
                        help="largest request body drained before the connection closes")
    parser.add_argument("--server-banner", default=None,
                        help="Server header to emit; must match the real vhost on this host")
    parser.add_argument("--chunk-size", type=int, default=3, help="bytes per write")
    parser.add_argument("--chunk-delay", type=float, default=0.05, help="seconds between chunks")
    parser.add_argument("--max-drip", type=float, default=5.0, help="hard cap on response duration")
    parser.add_argument("--max-threads", type=int, default=32, help="PT-07 global handler cap")
    parser.add_argument("--per-ip-max", type=int, default=4, help="PT-07 concurrent handlers per client")
    parser.add_argument("--advertise", default="",
                        help="PT-12 value for the X-Tarpit marker header; empty omits it")
    parser.add_argument("--no-keep-alive", action="store_true",
                        help="close every connection after one response (safest framing)")
    parser.add_argument("--health-path", default="/health",
                        help="B6: path answered immediately with a JSON health document (no drip, "
                             "no claim); set empty to disable the endpoint")
    parser.add_argument("--trusted-proxy", action="append", default=None,
                        help="peer address whose forwarding headers may be trusted (repeatable)")
    parser.add_argument("--claim-spool", default="",
                        help="Bundle L4: directory to file Tier 1 signature claims in for "
                             "`adaptive-tarpit drain-spool`; empty disables reporting")
    parser.add_argument("--claim-min-interval", type=int, default=300,
                        help="minimum seconds between repeat claims for one (client, signature)")
    parser.add_argument("--author", default="",
                        help="author recorded on filed claims (default: this hostname)")
    args = parser.parse_args()

    TarpitHandler.docroot = args.docroot
    TarpitHandler.docroot_real = os.path.realpath(args.docroot)
    TarpitHandler.responses_dir = os.path.abspath(args.responses_dir)
    TarpitHandler.error_dir = os.path.abspath(args.error_dir)
    TarpitHandler.responses_index = build_index(TarpitHandler.responses_dir)
    if args.profiles:
        # A catalogue that cannot be parsed is a deployment error rather than a runtime fallback:
        # answering with the wrong profile is exactly the failure the catalogue exists to prevent,
        # so the service refuses to start instead of quietly serving the legacy body.
        try:
            TarpitHandler.catalogue = profile_mod.load(args.profiles)
        except profile_mod.ProfileError as exc:
            sys.stderr.write("profiles: %s\n" % (exc,))
            return 1
        TarpitHandler.charset = TarpitHandler.catalogue.get("identity", {}).get("charset", "UTF-8")
        TarpitHandler.signature_responses = profile_mod.load_signature_responses(args.signature_store)
    else:
        TarpitHandler.catalogue = None
        TarpitHandler.signature_responses = {}
    TarpitHandler.read_docroot = args.read_docroot
    TarpitHandler.max_file_bytes = max(1, args.max_file_bytes)
    TarpitHandler.max_body_bytes = max(0, args.max_body_bytes)
    TarpitHandler.health_path = args.health_path
    if args.server_banner:
        TarpitHandler.server_version = args.server_banner
    TarpitHandler.chunk_size = max(1, args.chunk_size)
    TarpitHandler.chunk_delay = args.chunk_delay
    TarpitHandler.max_drip = args.max_drip
    TarpitHandler.marker_value = args.advertise
    TarpitHandler.keep_alive = not args.no_keep_alive
    TarpitHandler.claim_spool = os.path.abspath(args.claim_spool) if args.claim_spool else ""
    TarpitHandler.claim_min_interval = max(0, args.claim_min_interval)
    TarpitHandler.claim_author = args.author
    if args.trusted_proxy:
        TarpitHandler.trusted_proxies = tuple(args.trusted_proxy)

    BoundedThreadingServer.max_threads = max(1, args.max_threads)
    BoundedThreadingServer.per_ip_max = max(1, args.per_ip_max)
    # The server needs the same trust list as the handler: it decides *which* address a slot
    # belongs to, and answering that from the socket peer alone is what made every proxied
    # client share one semaphore.
    if args.trusted_proxy:
        BoundedThreadingServer.trusted_proxies = tuple(args.trusted_proxy)

    httpd = BoundedThreadingServer((args.bind, args.port), TarpitHandler)
    httpd.daemon_threads = True
    sys.stdout.write("tarpit-test listening on %s:%d profiles=%s docroot=%s(status_only=%s) "
                     "max_threads=%d per_ip_max=%d\n"
                     % (args.bind, args.port, TarpitHandler.responses_dir, TarpitHandler.docroot_real,
                        not TarpitHandler.read_docroot, BoundedThreadingServer.max_threads,
                        BoundedThreadingServer.per_ip_max))
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    sys.exit(main())
