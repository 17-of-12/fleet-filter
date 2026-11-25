"""The shipped topologies are validated examples, not illustrations.

Three things are checked, and each has already been the failure mode somewhere in this repo:

  * drift - a committed policy that no longer matches what the renderer produces from the current
    signature store. Hand-copied examples go stale the first time a signature is added, and a stale
    example is worse than none because it looks authoritative.
  * impossible combinations - a certificate on a profile that terminates nothing, or a trusted proxy
    on the edge profile. Both parse, and both then behave as something other than what their name
    says.
  * the binary rejecting the file - the renderer's own idea of a valid policy is not evidence. The
    gateway's parser is, so every shipped topology is run through `--show-policy` when the binary is
    available.
"""

import importlib.util
import re
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RENDERER = REPO / "bin" / "render-topology.py"
TOPOLOGIES_DIR = REPO / "deploy" / "topologies"
GATEWAY = Path.home() / ".cache" / "fleet-filter-gateway" / "target" / "release" / "fleet-filter-gateway"

# The arguments each shipped example was rendered with. Kept here rather than in the policy file so a
# re-render in a test cannot quietly adopt different inputs.
EXAMPLE_INPUTS = {
    "edge-tls": {
        "host": "gateway.example.edu",
        "cert": "/etc/fleet-filter/tls/gateway.crt",
        "key": "/etc/fleet-filter/tls/gateway.key",
        "trusted_proxies": (),
    },
    "behind-lb-plain": {
        "host": "origin.example.edu",
        "cert": None,
        "key": None,
        "trusted_proxies": ("10.0.0.0/8", "10.30.0.0/16"),
    },
    "behind-lb-tls": {
        "host": "origin.example.edu",
        "cert": "/etc/fleet-filter/tls/pool.crt",
        "key": "/etc/fleet-filter/tls/pool.key",
        "trusted_proxies": ("10.0.0.0/8",),
    },
}

# Both the policy table and the generated detection block record when they were rendered.
VOLATILE = re.compile(r"^(generated_at|source_commit) = |^#\s+generated_at: ")


def load_renderer():
    """Import bin/render-topology.py, whose name is not a valid module identifier."""
    spec = importlib.util.spec_from_file_location("render_topology", RENDERER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def without_volatile_fields(text):
    """Strip the lines that change on every render, so drift means something else changed."""
    return "\n".join(line for line in text.splitlines() if not VOLATILE.match(line))


class TopologyTest(unittest.TestCase):
    def setUp(self):
        """Load the renderer once per test and read the shipped files."""
        self.renderer = load_renderer()
        self.shipped = {}
        for name in EXAMPLE_INPUTS:
            path = TOPOLOGIES_DIR / name / "policy.toml"
            self.assertTrue(path.exists(), "missing shipped topology: %s" % path)
            self.shipped[name] = path.read_text()

    def render(self, name):
        """Render a topology with the inputs the shipped example was produced from."""
        inputs = EXAMPLE_INPUTS[name]
        return self.renderer.render_policy(
            name,
            inputs["host"],
            "http://127.0.0.1:8080",
            cert=inputs["cert"],
            key=inputs["key"],
            trusted_proxies=inputs["trusted_proxies"],
            source_commit="test",
        )

    def test_the_spool_directory_is_one_the_unit_may_write(self):
        """A spool under a path the unit cannot write drops detections without an error.

        ProtectSystem=strict plus ReadWritePaths is what makes /usr and /var read-only to the
        process. A rendered policy naming a spool outside the writable path validated, installed and
        reloaded cleanly, and then silently failed to record anything - the failure mode a detector
        can least afford.
        """
        unit = (REPO / "systemd" / "fleet-filter-gateway.service").read_text()
        allowed = [
            line.split("=", 1)[1].strip()
            for line in unit.splitlines()
            if line.startswith("ReadWritePaths=")
        ]
        self.assertTrue(allowed, "the unit must declare ReadWritePaths")
        for name in EXAMPLE_INPUTS:
            text = self.shipped[name]
            spool = [
                line.split('"')[1]
                for line in text.splitlines()
                if line.strip().startswith("dir = ")
            ]
            self.assertTrue(spool, "%s has no [spool] dir" % name)
            for path in spool:
                self.assertTrue(
                    any(path == root or path.startswith(root.rstrip("/") + "/") for root in allowed),
                    "%s spools to %s, outside the unit's %s" % (name, path, allowed),
                )

    def test_every_shipped_topology_matches_a_fresh_render(self):
        """Drift guard: the shipped file must be what the renderer produces today."""
        for name in EXAMPLE_INPUTS:
            with self.subTest(topology=name):
                self.assertEqual(
                    without_volatile_fields(self.shipped[name]),
                    without_volatile_fields(self.render(name)),
                    "deploy/topologies/%s/policy.toml is stale; re-render it" % name,
                )

    def test_the_topology_decides_whether_tls_and_proxy_trust_are_present(self):
        """A profile that claims no TLS must have none, and a balancer profile must trust one.

        This is the check that stops the shipped examples from describing a topology they are not:
        an `alpn = ["h2", "http/1.1"]` on a cleartext listener cannot start, and a TLS block on the
        plaintext profile would silently make it a second `behind-lb-tls`.
        """
        edge = self.shipped["edge-tls"]
        self.assertIn("tls_cert", edge)
        self.assertNotIn("trusted_proxies", edge)
        self.assertIn('alpn = ["h2", "http/1.1"]', edge)

        plain = self.shipped["behind-lb-plain"]
        self.assertNotIn("tls_cert", plain)
        self.assertIn("trusted_proxies", plain)
        # A plaintext listener that advertises h2 is a listener that cannot start; h2 needs TLS here.
        self.assertIn('alpn = ["http/1.1"]', plain)

        reencrypt = self.shipped["behind-lb-tls"]
        self.assertIn("tls_cert", reencrypt)
        self.assertIn("trusted_proxies", reencrypt)
        self.assertIn('alpn = ["h2", "http/1.1"]', reencrypt)

    def test_contradictory_inputs_are_refused(self):
        """A profile whose flags contradict it is refused, not rendered into a misleading file."""
        with self.assertRaises(ValueError):
            self.renderer.render_policy("edge-tls", "h", "http://127.0.0.1:1")
        with self.assertRaises(ValueError):
            self.renderer.render_policy(
                "behind-lb-plain", "h", "http://127.0.0.1:1",
                cert="/x.crt", key="/x.key", trusted_proxies=("10.0.0.0/8",),
            )
        with self.assertRaises(ValueError):
            # The edge profile believing a forwarding header would let a client name itself.
            self.renderer.render_policy(
                "edge-tls", "h", "http://127.0.0.1:1",
                cert="/x.crt", key="/x.key", trusted_proxies=("10.0.0.0/8",),
            )
        with self.assertRaises(ValueError):
            self.renderer.render_policy("behind-lb-plain", "h", "http://127.0.0.1:1")
        with self.assertRaises(ValueError):
            self.renderer.render_policy("no-such-topology", "h", "http://127.0.0.1:1")

    def test_the_gateway_binary_accepts_every_shipped_topology(self):
        """The parser is the authority; skip only when no binary has been built."""
        if not GATEWAY.exists():
            self.skipTest("gateway binary not built")
        for name in EXAMPLE_INPUTS:
            with self.subTest(topology=name):
                result = subprocess.run(
                    [str(GATEWAY), "--policy", str(TOPOLOGIES_DIR / name / "policy.toml"),
                     "--show-policy"],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("policy version=%s" % name, result.stdout)

    def test_every_topology_carries_the_detection_surface(self):
        """A shipped policy without detection would be a proxy, which is not what this ships."""
        for name in EXAMPLE_INPUTS:
            with self.subTest(topology=name):
                text = self.shipped[name]
                self.assertIn("[detection]", text)
                self.assertIn("prefixes = [", text)
                self.assertIn("body_markers = [", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
