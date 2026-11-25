#!/usr/bin/env python3
"""Render a complete gateway policy for one deployment topology.

Why a renderer rather than three hand-maintained example files: the `[detection]` table is
generated from the signature store, and a hand-copied example goes stale the first time a
signature is added. Shipping examples that no longer match the store is worse than shipping none,
because they look authoritative. Here the topologies own the topology-specific decisions and the
store owns the detection surface, so a re-render is the only way to produce one.

The topologies are the shapes this component is actually deployed in, and each one changes what
the gateway can see:

  edge-tls         The gateway is the TLS endpoint. It sees the client address directly, and it
                   sees HTTP/2 when the client negotiates it.
  behind-lb-plain  A load balancer terminates TLS and speaks plaintext HTTP/1.1 to the pool. The
                   gateway must trust the balancer's forwarding header or every client collapses
                   into one source. It never sees HTTP/2, so protocol shapes cannot fire.
  behind-lb-tls    A load balancer terminates the client's TLS and re-encrypts to the pool. The
                   gateway terminates that second connection: it keeps the client address from the
                   forwarding header and still sees HTTP/2.

Every topology carries the detection surface, the spool and the quarantine map, so a rendered policy
is runnable rather than illustrative. Values that must change per site are arguments, and the
rendered file names the topology in a header so an operator reading the installed policy knows which
shape it describes.
"""

import argparse
import importlib.util
import sys
import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RENDERER = REPO / "bin" / "render-gateway-detection.py"
STORE = REPO / "controller" / "signatures" / "signatures.yaml"

# The topologies as data. Each entry states the facts the rest of the file depends on, so the
# invariants in tests/unit/test_topologies.py are assertions about this table rather than about three
# files that could each drift in a different direction.
TOPOLOGIES = {
    "edge-tls": {
        "summary": "gateway terminates TLS; it is the edge",
        "tls": True,
        "trusted_proxies": False,
        "alpn": ["h2", "http/1.1"],
        "bind": "0.0.0.0:443",
        "consequences": [
            "the peer address is the client address; no forwarding header is believed",
            "HTTP/2 is visible, so protocol shapes can fire",
            "the gateway holds the certificate and owns its renewal",
            "the private key lives on this host, which makes it secret-bearing",
        ],
    },
    "behind-lb-plain": {
        "summary": "load balancer terminates TLS and speaks plaintext HTTP/1.1 to the pool",
        "tls": False,
        "trusted_proxies": True,
        "alpn": ["http/1.1"],
        "bind": "0.0.0.0:8080",
        "consequences": [
            "the forwarding header from a configured proxy is believed; every other peer is itself",
            "HTTP/2 is not visible here - it ended at the balancer, so protocol shapes cannot fire",
            "no certificate on this host; the balancer owns renewal",
            "the balancer-to-pool segment is cleartext and must be on a trusted network",
        ],
    },
    "behind-lb-tls": {
        "summary": "load balancer terminates the client's TLS and re-encrypts to the pool",
        "tls": True,
        "trusted_proxies": True,
        "alpn": ["h2", "http/1.1"],
        "bind": "0.0.0.0:8443",
        "consequences": [
            "the forwarding header from a configured proxy is believed; every other peer is itself",
            "HTTP/2 is visible when the balancer negotiates it to the pool, so protocol shapes apply",
            "this host holds a certificate too - usually an internal one - and renews it",
            "two TLS legs means two places a certificate can expire",
        ],
    },
}


def load_detection_renderer():
    """Import bin/render-gateway-detection.py, whose name is not a valid module identifier."""
    spec = importlib.util.spec_from_file_location("render_gateway_detection", RENDERER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render_policy(topology_name, host, backend, cert=None, key=None, trusted_proxies=(),
                  version=None, spool_dir="/var/lib/fleet-filter-gateway/spool",
                  map_path="/etc/fleet-filter/quarantine.map", source_commit="unknown",
                  generated_at=None,
                  bind=None):
    """Render one complete policy bundle for `topology_name`.

    Raises ValueError when the arguments contradict the topology: a certificate on a profile that
    terminates nothing, a trusted proxy on the edge profile, and so on. Those contradictions are the
    ones that produce a policy which parses and then behaves as something other than what its name
    says, so they are refused rather than tolerated.
    """
    if topology_name not in TOPOLOGIES:
        raise ValueError(
            "unknown topology %r; choose one of %s"
            % (topology_name, ", ".join(sorted(TOPOLOGIES)))
        )
    topology = TOPOLOGIES[topology_name]

    if topology["tls"] and not (cert and key):
        raise ValueError("%s terminates TLS and needs --cert and --key" % topology_name)
    if not topology["tls"] and (cert or key):
        raise ValueError(
            "%s does not terminate TLS; drop --cert/--key or use behind-lb-tls" % topology_name
        )
    if topology["trusted_proxies"] and not trusted_proxies:
        raise ValueError(
            "%s sits behind a load balancer and needs at least one --trusted-proxy prefix"
            % topology_name
        )
    if not topology["trusted_proxies"] and trusted_proxies:
        raise ValueError(
            "%s is the edge; a trusted proxy there would let a client name itself" % topology_name
        )

    detection = load_detection_renderer()
    store_text = STORE.read_text()
    detection_section, _, _ = detection.render(store_text, str(STORE), generated_at=generated_at)

    header = [
        "# Gateway policy - topology: %s" % topology_name,
        "# %s" % topology["summary"],
        "#",
        "# Generated by bin/render-topology.py; edit the topology or the inputs, not this file.",
        "# The [detection] table comes from controller/signatures/signatures.yaml.",
        "#",
        "# What this topology means for what the gateway can see:",
    ]
    header += ["#   * %s" % line for line in topology["consequences"]]
    header += [
        "#",
        "# Re-render rather than editing by hand: a hand-edited policy and the topology it claims to",
        "# be are the two things this file is supposed to keep together.",
        "",
    ]

    # The topology supplies a default bind; a deployment supplies the real one. Both are needed: the
    # example files must be runnable as themselves, and the published file must bind where that host
    # actually listens - an ignored bind field is a policy that starts on the wrong port.
    listener = ['[listener]', 'bind = "%s"' % (bind or topology["bind"])]
    if topology["tls"]:
        listener += ['tls_cert = "%s"' % cert, 'tls_key = "%s"' % key]
    listener.append("alpn = [%s]" % ", ".join('"%s"' % protocol for protocol in topology["alpn"]))
    if topology["trusted_proxies"]:
        listener.append(
            "trusted_proxies = [%s]"
            % ", ".join('"%s"' % prefix for prefix in trusted_proxies)
        )

    # `generated_at` and `source_commit` are required by the parser: a policy that cannot say when
    # it was produced and from which tree cannot be told apart from one somebody edited in place.
    body = [
        "[policy]",
        "schema_version = 1",
        'version = "%s"' % (version or ("%s-%s" % (topology_name, host))),
        # Deterministic when asked: the public export renders these files on every publish, and a
        # timestamp that moves on every render turns a no-op release into three modified files.
        'generated_at = "%s"' % (generated_at or
                                  datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        'source_commit = "%s"' % source_commit,
        'mode = "serve"',
        "",
    ]
    body += listener
    body += [
        "",
        "[limits]",
        "# 0 disables a limit. The per-source cap is not applied to a trusted proxy, which",
        "# multiplexes every client onto one address.",
        "max_connections = 512",
        "max_connections_per_source = 16",
        "max_body_bytes = 8388608",
        "max_headers = 100",
        "header_read_timeout_secs = 30",
        "",
        "[routing]",
        'default_backend = "%s"' % backend,
        "forward_headers = true",
        "",
        "[quarantine]",
        'map = "%s"' % map_path,
        "map_ttl = 300",
        "map_memo_ttl = 300",
        'fallback = "allow"',
        'on_quarantined = "inline"',
        "",
        "[spool]",
        'dir = "%s"' % spool_dir,
        "min_interval = 300",
        "max_entries = 10000",
        "",
        "[posture]",
        "# What a request is allowed to be before it is refused as malformed. `min_tls_version` is",
        "# only consulted on a TLS listener; on a plaintext one the balancer is the TLS endpoint.",
        'active = "standard"',
        'methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]',
        "header_names = []",
        "content_types = []",
        "max_path_bytes = 4096",
        "max_query_bytes = 4096",
        "max_path_segments = 128",
        'min_tls_version = "1.2"',
        "admission_cap_per_authority = 0",
        "",
        "[deception]",
        "# The budget is the control: `max_concurrent_drips` keeps a scanner burst from turning a",
        "# deliberate slowdown into a memory problem, and surplus requests are refused, not queued.",
        'detected_profile = "exploit-probe"',
        'quarantined_profile = "generic"',
        "max_concurrent_drips = 32",
        "max_drip_ms = 8000",
        "per_connection_max_bytes = 65536",
        "",
    ]
    return "\n".join(header + body) + "\n" + detection_section + "\n"


def main(argv=None):
    """Command line entry point: `--list`, or render one topology to stdout or `--out`."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="list the shipped topologies")
    parser.add_argument("--topology", help="which topology to render")
    parser.add_argument("--host", default="gateway.example.edu", help="site identity for the version string")
    parser.add_argument("--backend", default="http://127.0.0.1:8080", help="upstream origin")
    parser.add_argument("--cert", help="certificate path (topologies that terminate TLS)")
    parser.add_argument("--key", help="key path (topologies that terminate TLS)")
    parser.add_argument(
        "--trusted-proxy",
        action="append",
        default=[],
        help="prefix whose forwarding header is believed; repeatable",
    )
    parser.add_argument("--spool-dir", default="/var/lib/fleet-filter/spool")
    parser.add_argument("--map", dest="map_path", default="/etc/fleet-filter/quarantine.map")
    parser.add_argument("--source-commit", default="unknown", help="tree the policy was rendered from")
    parser.add_argument("--out", help="write here instead of stdout")
    args = parser.parse_args(argv)

    if args.list:
        for name in sorted(TOPOLOGIES):
            print("%-16s %s" % (name, TOPOLOGIES[name]["summary"]))
        return 0

    if not args.topology:
        parser.error("--topology is required unless --list is given")

    try:
        rendered = render_policy(
            args.topology,
            args.host,
            args.backend,
            cert=args.cert,
            key=args.key,
            trusted_proxies=args.trusted_proxy,
            spool_dir=args.spool_dir,
            map_path=args.map_path,
            source_commit=args.source_commit,
        )
    except ValueError as error:
        print("render-topology: %s" % error, file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
