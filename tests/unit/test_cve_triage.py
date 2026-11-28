"""The CVE triage funnel is deterministic, so its decisions can be pinned exactly.

Each test below is a decision the funnel makes that would be wrong in a way nobody notices: a
version outside the vulnerable range admitted because the range was ignored, a local-only bug
treated as a front-proxy problem, a KEV-listed CVE dropped because its EPSS happened to be low, or
a description keyword overriding a CPE that says something else. Those are the four ways a triage
funnel fails silently - it does not crash, it just stops telling you about the thing that mattered.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
TRIAGE = REPO / "bin" / "cve-triage.py"
ESTATE = REPO / "config" / "estate.yaml"


def load_triage():
    """Import bin/cve-triage.py, whose name is not a valid module identifier."""
    spec = importlib.util.spec_from_file_location("cve_triage", TRIAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cve(cve_id, vendor, product, criteria, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="A vulnerability", bounds=None):
    """Build one NVD 2.0 record, with the CPE range fields the real feed uses."""
    match = {"vulnerable": True, "criteria": criteria}
    if bounds:
        match.update(bounds)
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"vectorString": vector}}]},
        "configurations": [] if criteria is None else [{"nodes": [{"cpeMatch": [match]}]}],
    }


APACHE_OLD = "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*"
APACHE_RANGE = "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*"


class TriageTest(unittest.TestCase):
    def setUp(self):
        """Load the module and the shipped estate definition."""
        self.triage = load_triage()
        self.estate = yaml.safe_load(ESTATE.read_text())

    def run_funnel(self, cves, kev=(), epss=None, poc=None):
        """Triage records against the shipped estate with a fixed EPSS map."""
        return self.triage.triage(
            cves, set(kev), epss or {}, self.estate, poc or {}, threshold=0.1,
        )

    def test_estate_fragments_merge_and_keep_every_version(self):
        """Two hosts on different versions must produce one entry holding both.

        Writing the file by hand meant the last editor won: a host on 2.4.49 and another on 2.4.66
        collapsed to whichever was typed, so a CVE affecting only the older one was either missed or
        reported as irrelevant depending on the order.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "a.yaml").write_text(
                "estate:\n  - name: a\n    vendor: apache\n    product: httpd\n    running: [\"2.4.49\"]\n")
            (tmp / "b.yaml").write_text(
                "estate:\n  - name: b\n    vendor: apache\n    product: httpd\n    running: [\"2.4.66\"]\n"
                "keywords: [\"apache http server\"]\n")
            merged = self.triage.load_estate(str(tmp))
        self.assertEqual(len(merged["estate"]), 1)
        self.assertEqual(merged["estate"][0]["running"], ["2.4.49", "2.4.66"])
        self.assertEqual(merged["keywords"], ["apache http server"])

    def test_a_product_with_an_unknown_version_is_still_a_candidate(self):
        """An unversioned image must not silence the product; the queue marks it as unversioned."""
        record = cve("CVE-2026-0020", "nginx", "nginx", "cpe:2.3:a:nginx:nginx:1.27:*:*:*:*:*:*:*")
        estate = {"estate": [{"name": "nginx", "vendor": "nginx", "product": "nginx", "running": []}],
                  "keywords": []}
        queue, _ = self.triage.triage([record], set(), {"CVE-2026-0020": 0.9}, estate, {}, threshold=0.1)
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["matched_via"], "cpe-unversioned")

    def test_a_version_inside_the_vulnerable_range_is_queued(self):
        """A range that excludes the deployed version at the top must still admit it below."""
        record = cve(
            "CVE-2026-0001", "apache", "httpd", APACHE_RANGE,
            bounds={"versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.67"},
        )
        queue, excluded = self.run_funnel([record], epss={"CVE-2026-0001": 0.5})
        self.assertEqual([item["id"] for item in queue], ["CVE-2026-0001"])
        self.assertEqual(excluded, [])

    def test_a_version_the_estate_does_not_run_is_still_reachable_when_declared_by_name(self):
        """The estate declares Apache by name, so a 2.4.70+ CVE is still an Apache CVE here.

        This asserts the opposite of what it asserted before the change, and that is the point: a
        proxy outlives a patch cycle, so a directory of deployed versions was making the estate's
        opinion about CVEs for versions it has not shipped yet. The bug is not in 2.4.66 - it is in
        whatever 2.4.xx the host runs the week this lands.
        """
        record = cve(
            "CVE-2026-0002", "apache", "httpd", APACHE_RANGE,
            bounds={"versionStartIncluding": "2.4.70", "versionEndExcluding": "2.4.80"},
        )
        queue, excluded = self.run_funnel([record], epss={"CVE-2026-0002": 0.9})
        self.assertEqual([item["id"] for item in queue], ["CVE-2026-0002"])
        self.assertEqual(excluded, [])

    def test_a_pinned_entry_still_uses_its_version_list(self):
        """Breadth is a choice per entry: a product declared with versions is still gated by them."""
        record = cve(
            "CVE-2026-0003", "apache", "httpd", APACHE_RANGE,
            bounds={"versionStartIncluding": "2.4.70", "versionEndExcluding": "2.4.80"},
        )
        pinned = {"estate": [{"name": "apache httpd", "vendor": "apache",
                              "product": "httpd", "running": ["2.4.66"]}], "keywords": []}
        matched, _, detail = load_triage().estate_match(record, pinned, [])
        self.assertFalse(matched)
        self.assertIn("no estate product", detail)

    def test_a_local_only_bug_is_not_a_front_proxy_problem(self):
        """AV:L means the attacker is already on the host; the proxy changes nothing."""
        record = cve(
            "CVE-2026-0003", "apache", "httpd", APACHE_OLD,
            vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        )
        queue, excluded = self.run_funnel([record], epss={"CVE-2026-0003": 0.9})
        self.assertEqual(queue, [])
        self.assertEqual(excluded[0]["reason"], "AV=L")

    def test_an_authenticated_bug_is_removed_but_a_low_privilege_one_is_not(self):
        """PR:H is out of scope for the proxy; PR:L stays, because a leaked account is common."""
        high = cve("CVE-2026-0004", "wordpress", "wordpress", APACHE_OLD,
                   vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
        low = cve("CVE-2026-0005", "wordpress", "wordpress", APACHE_OLD,
                  vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        queue, excluded = self.run_funnel([high, low], epss={"CVE-2026-0005": 0.5})
        self.assertEqual([item["id"] for item in queue], ["CVE-2026-0005"])
        self.assertEqual(excluded[0]["reason"], "PR=H")

    def test_kev_membership_beats_a_low_epss_score(self):
        """Exploitation in the wild is not a probability; a low EPSS does not cancel it."""
        record = cve("CVE-2026-0006", "apache", "httpd", APACHE_OLD)
        queue, _ = self.run_funnel([record], kev={"CVE-2026-0006"}, epss={"CVE-2026-0006": 0.0})
        self.assertEqual(len(queue), 1)
        self.assertTrue(queue[0]["kev"])

    def test_without_exploit_evidence_it_is_excluded_with_the_score_named(self):
        """A rejection names the score that caused it, so the threshold can be argued with.

        An exclusion that only says "not exploited" is unfalsifiable: nobody can tell whether the
        rule was 0.1, an absent PoC index, or a bug.
        """
        record = cve("CVE-2026-0007", "apache", "httpd", APACHE_OLD)
        queue, excluded = self.run_funnel([record], epss={"CVE-2026-0007": 0.01})
        self.assertEqual(queue, [])
        self.assertIn("0.010", excluded[0]["reason"])

    def test_a_description_keyword_is_used_only_when_the_record_has_no_cpe(self):
        """A phrase match is weaker than a CPE, so a CPE that names another product wins."""
        no_cpe = cve("CVE-2026-0008", None, None, None,
                     description="A flaw in the apache http server allows memory corruption")
        wrong_cpe = cve("CVE-2026-0009", "redis", "redis", "cpe:2.3:a:redis:redis:7.0:*:*:*:*:*:*:*",
                        description="A flaw in the apache http server allows memory corruption")
        queue, excluded = self.run_funnel(
            [no_cpe, wrong_cpe], epss={"CVE-2026-0008": 0.5, "CVE-2026-0009": 0.5},
        )
        self.assertEqual([item["id"] for item in queue], ["CVE-2026-0008"])
        self.assertEqual(queue[0]["matched_via"], "keyword")
        self.assertEqual(excluded[0]["reason"], "no estate product in the record's CPEs")

    def test_the_queue_order_is_a_total_order_and_kev_comes_first(self):
        """Feed order must not leak into the queue, or two runs of the same day disagree.

        KEV first because it is the only signal that says an attack already happened; EPSS next as a
        ranking within that; the id last so ties are broken by something stable.
        """
        records = [
            cve("CVE-2026-0012", "php", "php", APACHE_OLD),
            cve("CVE-2026-0011", "php", "php", APACHE_OLD),
            cve("CVE-2026-0010", "php", "php", APACHE_OLD),
        ]
        queue, _ = self.run_funnel(
            records, kev={"CVE-2026-0012"},
            epss={"CVE-2026-0010": 0.9, "CVE-2026-0011": 0.2, "CVE-2026-0012": 0.01},
        )
        self.assertEqual([item["id"] for item in queue], ["CVE-2026-0012", "CVE-2026-0010", "CVE-2026-0011"])

    def test_version_comparison_orders_numbers_not_strings(self):
        """2.4.9 is older than 2.4.10; lexical comparison gets that backwards."""
        self.assertLess(self.triage.parse_version("2.4.9"), self.triage.parse_version("2.4.10"))
        self.assertIsNone(self.triage.parse_version("no digits here"))

    def test_a_replay_produces_the_same_queue_twice(self):
        """Determinism: the CLI's queue file must be identical across runs on the same inputs."""
        record = cve("CVE-2026-0013", "apache", "httpd", APACHE_OLD)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "nvd.json").write_text(json.dumps({"vulnerabilities": [{"cve": record}]}))
            (tmp / "kev.json").write_text(json.dumps({"vulnerabilities": []}))
            (tmp / "epss.csv").write_text(
                "#model_version:v2026.11.24\ncve,epss,percentile\nCVE-2026-0013,0.500000,0.99\n"
            )
            outputs = []
            for run in ("a", "b"):
                subprocess.run(
                    [sys.executable, str(TRIAGE), "--nvd-json", str(tmp / "nvd.json"),
                     "--kev", str(tmp / "kev.json"), "--epss", str(tmp / "epss.csv"),
                     "--estate", str(ESTATE), "--now", "2026-11-25T00:00:00+00:00",
                     "--out-dir", str(tmp / run)],
                    check=True, capture_output=True, text=True,
                )
                outputs.append((tmp / run / "queue.json").read_text())
            self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class AnyVersion(unittest.TestCase):
    """An estate entry that declares a product without a version matches any CVE naming it."""

    def setUp(self):
        """The module under test, imported once per test."""
        self.triage_module = load_triage()

    def triage(self, estate):
        """Run the reachable stage against one synthetic CVE and return (matched, via)."""
        cve = {"id": "CVE-2099-0001", "descriptions": [{"value": "wordpress thing"}],
               "configurations": [{"nodes": [{"cpeMatch": [{
                   "vulnerable": True, "criteria": "cpe:2.3:a:wordpress:wordpress:5.0:*:*:*:*:*:*:*"}]}]}]}
        return self.triage_module.estate_match(cve, {"estate": estate}, [])

    def test_any_version_matches_a_cve_for_a_version_we_do_not_run(self):
        """The point of the flag: a 5.0 CVE is still a WordPress CVE on a 6.9 site."""
        matched, via, _ = self.triage([{"name": "wp", "vendor": "wordpress",
                                        "product": "wordpress", "any_version": True}])
        self.assertTrue(matched)
        self.assertEqual(via, "cpe-any-version")

    def test_a_pinned_version_still_has_to_contain_the_running_version(self):
        """The flag must not weaken the precise entries: a version list still gates the match."""
        matched, _, detail = self.triage([{"name": "wp", "vendor": "wordpress",
                                           "product": "wordpress", "running": ["6.9"]}])
        self.assertFalse(matched)
        self.assertIn("no estate product", detail)

    def test_a_different_product_is_still_excluded(self):
        """Breadth is per entry, not global: WordPress declared does not admit Drupal CVEs."""
        cve = {"id": "CVE-2099-0002", "descriptions": [{"value": "drupal"}],
               "configurations": [{"nodes": [{"cpeMatch": [{
                   "vulnerable": True, "criteria": "cpe:2.3:a:drupal:drupal:9.0:*:*:*:*:*:*:*"}]}]}]}
        matched, _, _ = self.triage_module.estate_match(cve, {"estate": [
            {"name": "wp", "vendor": "wordpress", "product": "wordpress", "any_version": True}]}, [])
        self.assertFalse(matched)
