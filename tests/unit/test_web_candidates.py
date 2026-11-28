"""The web-candidate list must say how it decided, and must not count weak evidence as strong."""

import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "web_candidates", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "web-candidates.py")
WEB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WEB)

SURFACE = ({("drupal", "drupal")}, ["http request"])


def record(cve_id, criteria=None, description="A vulnerability", vector="NETWORK"):
    """One NVD record, optionally with a CPE and a CVSS vector."""
    entry = {"id": cve_id, "descriptions": [{"value": description}], "configurations": []}
    if criteria:
        entry["configurations"] = [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                              "criteria": criteria}]}]}]
    if vector:
        entry["metrics"] = {"cvssMetricV31": [{"cvssData": {
            "attackVector": vector, "privilegesRequired": "NONE", "userInteraction": "NONE"}}]}
    return entry


class Candidates(unittest.TestCase):
    """A row is included on one of two kinds of evidence, and each says which."""

    def test_a_cpe_named_product_is_reported_as_cpe(self):
        """Strong evidence: NVD names software that speaks HTTP."""
        rows = WEB.candidates([record("CVE-1", "cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*")],
                              set(), {}, SURFACE[0], SURFACE[1], require_surface=True)
        self.assertEqual([r["via"] for r in rows], ["cpe"])

    def test_a_description_match_is_labelled_keyword(self):
        """Weak evidence is still evidence, but it must not look like a CPE match."""
        rows = WEB.candidates([record("CVE-2", None, "The server mishandles an http request body")],
                              set(), {}, SURFACE[0], SURFACE[1], require_surface=True)
        self.assertEqual([r["via"] for r in rows], ["keyword"])

    def test_unrelated_software_is_not_listed(self):
        """ffmpeg has no signal and is not web-facing, so it is not listed - for both reasons.

        Without a signal the gate in candidates() drops it; with a signal, `require_surface=True`
        still refuses a product the declared surface does not name. Asserting only the first would
        pass even if the surface rule were deleted.
        """
        ffmpeg = record("CVE-3", "cpe:2.3:a:ffmpeg:ffmpeg:6.0:*:*:*:*:*:*:*", "A demuxer bug")
        self.assertEqual(WEB.candidates([ffmpeg], set(), {}, SURFACE[0], SURFACE[1]), [])
        self.assertEqual(WEB.candidates([ffmpeg], set(), {"CVE-3": 0.5}, SURFACE[0], SURFACE[1],
                                        require_surface=True), [])

    def test_a_cpe_that_is_not_marked_vulnerable_is_not_cpe_evidence(self):
        """A node can name a product to exclude it; that must not be reported as a CPE match."""
        entry = record("CVE-9", "cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*")
        entry["configurations"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"] = False
        rows = WEB.candidates([entry], set(), {"CVE-9": 0.5}, SURFACE[0], SURFACE[1])
        self.assertEqual([r["via"] for r in rows], ["product"])

    def test_a_cpe_match_outranks_a_keyword_match(self):
        """Evidence strength orders the list before KEV or EPSS do, so weak rows cannot bury strong."""
        strong = record("CVE-10", "cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*")
        weak = record("CVE-11", None, "An http request body is mishandled")
        rows = WEB.candidates([weak, strong], set(), {"CVE-10": 0.2, "CVE-11": 0.9},
                              SURFACE[0], SURFACE[1])
        self.assertEqual([r["id"] for r in rows], ["CVE-10", "CVE-11"])

    def test_kev_rows_sort_first(self):
        """A KEV listing outranks a higher EPSS score when deciding what to read next."""
        plain = record("CVE-4", "cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*")
        listed = record("CVE-5", "cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*")
        rows = WEB.candidates([plain, listed], {"CVE-5"}, {"CVE-4": 0.9}, SURFACE[0], SURFACE[1])
        self.assertEqual(rows[0]["id"], "CVE-5")

    def test_an_undeclared_product_is_listed_when_it_is_being_exploited(self):
        """The point of the default: no human had to bless this product for it to appear."""
        rows = WEB.candidates([record("CVE-7", "cpe:2.3:a:xen-orchestra:xen_orchestra:5.0:"
                                       "*:*:*:*:*:*:*")], {"CVE-7"}, {}, SURFACE[0], SURFACE[1])
        self.assertEqual([r["via"] for r in rows], ["product"])

    def test_an_undeclared_product_without_a_signal_is_not_listed(self):
        """Ranking needs a signal to rank on; without one the list would be the whole feed."""
        rows = WEB.candidates([record("CVE-8", "cpe:2.3:a:somebody:their_app:1.0:"
                                       "*:*:*:*:*:*:*")], set(), {"CVE-8": 0.001},
                              SURFACE[0], SURFACE[1])
        self.assertEqual(rows, [])

    def test_a_record_without_a_vector_still_lists(self):
        """No CVSS is missing information, not a reason to hide the row."""
        rows = WEB.candidates([record("CVE-6", "cpe:2.3:a:drupal:drupal:7.0:*:*:*:*:*:*:*",
                                      vector=None)], set(), {"CVE-6": 0.5}, SURFACE[0], SURFACE[1])
        self.assertEqual(rows[0]["av"], "-")


if __name__ == "__main__":
    unittest.main()
