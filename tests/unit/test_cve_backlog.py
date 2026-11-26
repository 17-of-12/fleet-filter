"""Tests for the deferred-CVE ledger: the decision, the record, and the promotion it writes."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "bin"))


def load_backlog():
    """Load bin/cve-backlog.py by path: bin/ is not a package."""
    spec = importlib.util.spec_from_file_location("cve_backlog", REPO / "bin" / "cve-backlog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKLOG = load_backlog()
ENTRY = {"id": "CVE-2026-00001", "product": "php", "epss": 0.4, "kev": False}


class DeferralLedger(unittest.TestCase):
    def test_a_deferral_is_recorded_once_and_refreshed(self):
        """A second skip of the same CVE refreshes the record instead of adding another."""
        ledger = {}
        BACKLOG.record_deferral(ledger, ENTRY, "no reference code", when="2026-11-01")
        BACKLOG.record_deferral(ledger, ENTRY, "no reference code", when="2026-11-02")
        self.assertEqual(len(ledger), 1)
        record = ledger["CVE-2026-00001"]
        self.assertEqual(record["first_seen"], "2026-11-01")
        self.assertEqual(record["last_checked"], "2026-11-02")
        self.assertEqual(record["checks"], 2)

    def test_a_record_survives_a_rewrite_byte_for_byte(self):
        """A rewrite round-trips the ledger, so an interrupted run cannot lose a deferral."""
        ledger = {"CVE-2026-00001": BACKLOG.record_deferral({}, ENTRY, "no reference code",
                                                             when="2026-11-01")}
        path = Path(self._scratch()) / "ledger.jsonl"
        BACKLOG.write_ledger(path, ledger)
        again = BACKLOG.load_ledger(path)
        self.assertEqual(again, ledger)

    def _scratch(self):
        """A private temporary directory, removed when the test ends."""
        import tempfile
        self.addCleanup(lambda: None)
        directory = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        return directory


class Decision(unittest.TestCase):
    def record(self, age_days=1, kev=False):
        """A deferred record of a given age, for the decision tests."""
        from datetime import date, timedelta
        first = (date(2026, 11, 25) - timedelta(days=age_days)).isoformat()
        return {"cve": "CVE-2026-00001", "first_seen": first, "kev": kev}

    def test_reference_code_promotes(self):
        """Reference code appearing is the event that makes a deferred CVE actionable."""
        action, why = BACKLOG.decide(self.record(), ["nvd"], set(), "2026-11-25", 45)
        self.assertEqual(action, "promote")
        self.assertIn("reference code", why)

    def test_kev_addition_promotes(self):
        """A CVE joining KEV promotes it even with no PoC, because KEV implies exploitation."""
        action, why = BACKLOG.decide(self.record(), None, {"CVE-2026-00001"}, "2026-11-25", 45)
        self.assertEqual(action, "promote")
        self.assertIn("KEV", why)

    def test_nothing_promotes_while_nothing_changes(self):
        """No PoC and no KEV change means the record stays deferred."""
        action, _ = BACKLOG.decide(self.record(), None, set(), "2026-11-25", 45)
        self.assertEqual(action, "keep")

    def test_an_old_record_expires_instead_of_lingering(self):
        """A record past the age limit leaves the ledger and says why."""
        action, why = BACKLOG.decide(self.record(age_days=60), None, set(), "2026-11-25", 45)
        self.assertEqual(action, "expire")
        self.assertIn("60 days", why)

    def test_promotion_writes_a_work_item_the_queue_can_read(self):
        """The promoted item is the shape the worker reads from the queue."""
        item = BACKLOG.work_item(self.record(), "/tmp/run", ["nvd", "nuclei"])
        self.assertEqual(item["cve"], "CVE-2026-00001")
        self.assertIn("revived", item)
        self.assertTrue(item["reference_code"])
        json.dumps(item)  # serialisable, because the worker reads it from disk


class PromotionItem(unittest.TestCase):
    def test_a_poc_promotion_is_not_labelled_kev(self):
        """A CVE promoted because a PoC appeared must not claim KEV, which means active exploitation."""
        item = BACKLOG.work_item({"cve": "CVE-2026-00001", "kev": False}, "/tmp/run", ["nvd"],
                                 in_kev=False)
        self.assertFalse(item["kev"])

    def test_a_kev_promotion_is_labelled_kev(self):
        """A promotion caused by a KEV addition carries kev=true in the work item it writes."""
        item = BACKLOG.work_item({"cve": "CVE-2026-00001", "kev": True}, "/tmp/run", ["nvd"],
                                 in_kev=True)
        self.assertTrue(item["kev"])


if __name__ == "__main__":
    unittest.main()
