"""The dispatch report must read as coverage status, not as a list of things that went wrong."""

import contextlib
import importlib.util
import io
import pathlib
import unittest

REPORT = importlib.util.spec_from_file_location(
    "dispatch", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "cve-dispatch.py")
DISPATCH = importlib.util.module_from_spec(REPORT)
REPORT.loader.exec_module(DISPATCH)


def render(skipped, recorded=True):
    """The report text for a set of decisions, so the wording can be asserted."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        DISPATCH.report([], skipped, set(), recorded=recorded)
    return out.getvalue()


class Wording(unittest.TestCase):
    """A covered CVE must not read like a gap; the words carry the meaning."""

    def test_a_queued_item_is_not_a_problem(self):
        """Steady state: the CVE is in the queue. That is work in progress, not something to fix."""
        text = render([("CVE-A", "already queued"), ("CVE-B", "already tracked in lab/exploits/")])
        self.assertIn("Queued: 1 already in the work queue", text)
        self.assertIn("0 needing attention", text)
        self.assertIn("Nothing is uncovered", text)

    def test_covered_and_waiting_are_named_as_such(self):
        """Two covered entries and one waiting: the report says so in the reader's words."""
        text = render([("CVE-A", "already tracked in lab/exploits/"),
                       ("CVE-C", "no reference code and not KEV-listed")])
        self.assertIn("Tracked: 1 with a signature", text)
        self.assertIn("Waiting: 1 for a PoC", text)

    def test_the_word_skipped_never_appears(self):
        """Skipped implies missed; the report must not use it for covered or waiting work."""
        text = render([("CVE-A", "already tracked in lab/exploits/"),
                       ("CVE-B", "no reference code and not KEV-listed")])
        self.assertNotIn("skipped", text.lower())

    def test_a_dry_run_does_not_claim_a_cve_is_watched(self):
        """Nothing was recorded, so nothing is being watched yet - say that instead of going green."""
        text = render([("CVE-C", "no reference code and not KEV-listed")], recorded=False)
        self.assertIn("Dry run: nothing was written", text)
        self.assertNotIn("is being watched for a PoC", text)

    def test_a_dry_run_does_not_promise_work_it_did_not_queue(self):
        """New CVEs in a dry run are not queued, so the line must not say an agent will pick them up."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            DISPATCH.report(["CVE-NEW"], [], set(), recorded=False)
        text = out.getvalue()
        self.assertIn("would be queued (dry run: nothing written)", text)
        self.assertNotIn("an agent will pick this up", text)

    def test_a_dry_run_with_nothing_waiting_does_not_invent_a_ledger_entry(self):
        """A dry run with nothing waiting prints "No action" rather than naming a ledger entry."""
        text = render([], recorded=False)
        self.assertNotIn("recorded as waiting", text)
        self.assertIn("No action", text)

    def test_nothing_new_is_stated_positively(self):
        """A quiet day says "none", not an empty section a reader has to interpret."""
        text = render([("CVE-A", "already tracked in lab/exploits/")])
        self.assertIn("New: none", text)


if __name__ == "__main__":
    unittest.main()
