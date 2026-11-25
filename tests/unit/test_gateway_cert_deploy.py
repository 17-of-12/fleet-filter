"""The gateway certificate handover, tested at the points where it can take a listener down.

The interesting behaviour of bin/gateway-cert-deploy.sh is not the happy path - copying a file
works - it is the refusals and the rollback. Each test below names the failure it prevents, because
a test that only proves the copy happened would pass on a script that installs a mismatched pair or
leaves a listener on a certificate nobody verified.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "bin" / "gateway-cert-deploy.sh"


def make_pair(directory: Path, name: str, days: int, cn: str, san: str = "DNS:127.0.0.1") -> tuple:
    """A self-signed certificate and key, or a different key under the same name."""
    cert = directory / f"{name}.crt"
    key = directory / f"{name}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-days", str(days), "-subj", f"/CN={cn}", "-addext", f"subjectAltName={san}",
        ],
        check=True, capture_output=True,
    )
    return cert, key


class CertDeployTest(unittest.TestCase):
    def setUp(self):
        """A destination directory, a policy naming it, and a certificate already installed."""

        self.tmp = Path(tempfile.mkdtemp(prefix="cert-deploy-test-"))
        self.installed = self.tmp / "installed"
        self.installed.mkdir()
        self.dest_cert = self.installed / "cert.crt"
        self.dest_key = self.installed / "cert.key"
        # A policy naming the destination, so the script reads its target the way it does in service.
        self.policy = self.tmp / "policy.toml"
        self.policy.write_text(
            f'bind = "127.0.0.1:1"\n'
            f'tls_cert = "{self.dest_cert}"\n'
            f'tls_key = "{self.dest_key}"\n'
        )
        self.current_cert, self.current_key = make_pair(self.tmp, "current", 90, "current.example")
        shutil.copy(self.current_cert, self.dest_cert)
        shutil.copy(self.current_key, self.dest_key)
        os.chmod(self.dest_key, 0o600)

    def tearDown(self):
        """Remove the temporary tree; nothing here touches a live listener."""

        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_hook(self, *args):
        """Run the hook against the fixture policy, with the arguments a test needs."""

        return subprocess.run(
            [str(SCRIPT), "--policy", str(self.policy), *args],
            capture_output=True, text=True,
        )

    def test_a_matching_pair_is_installed_and_the_key_is_private(self):
        """A good renewal replaces the material without widening the key's permissions."""

        cert, key = make_pair(self.tmp, "new", 90, "new.example")
        result = self.run_hook("--cert", str(cert), "--key", str(key), "--no-verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            subprocess.run(
                ["openssl", "x509", "-in", str(self.dest_cert), "-noout", "-subject"],
                capture_output=True, text=True,
            ).stdout.strip(),
            "subject=CN=new.example",
        )
        # The key must not become group- or world-readable by being copied.
        self.assertEqual(os.stat(self.dest_key).st_mode & 0o077, 0)
        # Rollback copies are kept until verification succeeds, and --no-verify never prunes them.
        self.assertTrue(Path(f"{self.dest_cert}.prev").exists())

    def test_a_mismatched_key_is_refused_and_nothing_is_replaced(self):
        """A mismatched pair must leave the working certificate in place, not break the listener."""

        cert, _ = make_pair(self.tmp, "new", 90, "new.example")
        _, other_key = make_pair(self.tmp, "other", 90, "other.example")
        result = self.run_hook("--cert", str(cert), "--key", str(other_key), "--no-verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not match", result.stderr)
        # The listener still has the certificate it started with.
        self.assertEqual(
            subprocess.run(
                ["openssl", "x509", "-in", str(self.dest_cert), "-noout", "-subject"],
                capture_output=True, text=True,
            ).stdout.strip(),
            "subject=CN=current.example",
        )

    def test_a_certificate_inside_the_expiry_window_is_refused(self):
        """A short-dated certificate means issuance went wrong upstream, so it is not installed."""

        cert, key = make_pair(self.tmp, "short", 1, "short.example")
        result = self.run_hook("--cert", str(cert), "--key", str(key), "--no-verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expires within", result.stderr)

    def test_a_certificate_for_the_wrong_host_is_refused(self):
        """A renewal for the wrong name looks successful and is not, so the host is checked."""

        cert, key = make_pair(self.tmp, "wrong", 90, "wrong.example", "DNS:wrong.example")
        result = self.run_hook(
            "--cert", str(cert), "--key", str(key), "--no-verify", "--expect-host", "right.example"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not cover", result.stderr)

    def test_a_policy_without_tls_installs_nothing_and_succeeds(self):
        """A cleartext deployment has nothing to install, which is a success, not an error."""

        plain = self.tmp / "plain.toml"
        plain.write_text('bind = "127.0.0.1:1"\n')
        cert, key = make_pair(self.tmp, "new", 90, "new.example")
        result = subprocess.run(
            [str(SCRIPT), "--policy", str(plain), "--cert", str(cert), "--key", str(key)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no tls_cert/tls_key", result.stderr)

    def test_reload_is_required_unless_verification_is_skipped(self):
        """Installing without reloading is only allowed when it is asked for explicitly."""

        cert, key = make_pair(self.tmp, "new", 90, "new.example")
        result = self.run_hook("--cert", str(cert), "--key", str(key))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--unit or --pid", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
