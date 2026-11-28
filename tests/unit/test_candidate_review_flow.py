"""The candidate-review stage, driven end to end with recorded decisions instead of an agent.

This is the chain from candidate json to work queue: the part where a judgement becomes a queued
session, and the part that was only ever exercised by hand on live candidates.
"""

import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "bin" / "candidate-review.sh"

CANDIDATES = {"queue": [
    {"id": "CVE-2099-0001", "product": "drupal/drupal", "kev": True, "epss": 0.5,
     "description": "Missing authentication for a critical function"},
    {"id": "CVE-2099-0002", "product": "n-able/mail_assure", "kev": True, "epss": 0.02,
     "description": "Authenticated API user can redirect an LDAP sync"},
]}

DECISIONS = [
    {"id": "CVE-2099-0001", "decision": "accept", "reason": "",
     "why": "install.php is reachable unauthenticated at a fixed URI"},
    {"id": "CVE-2099-0002", "decision": "reject", "reason": "needs-authentication",
     "why": "PR:H; the proxy cannot tell an API user from an authorised one"},
]


class Flow(unittest.TestCase):
    """Accepted candidates become queue items; rejected ones never do."""

    def setUp(self):
        """A scratch queue, ledger and log, so nothing touches the real work queue."""
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.queue = self.tmp / "workqueue"
        self.queue.mkdir()
        self.decisions = self.tmp / "decisions.jsonl"
        self.ledger = self.tmp / "ledger.jsonl"
        self.candidates = self.tmp / "candidates.json"
        self.candidates.write_text(json.dumps(CANDIDATES))
        self.replay = self.tmp / "replay.jsonl"
        self.replay.write_text("\n".join(json.dumps(d) for d in DECISIONS) + "\n")

    def tearDown(self):
        """Remove the scratch tree."""
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self):
        """Run the review stage with the recorded decisions, and fail loudly if it did not run.

        Asserting the exit status here is the difference between testing the stage and testing that a
        file is absent: a script that dies before it writes anything also leaves the queue empty, and
        would have passed every absence-only assertion forever.
        """
        result = subprocess.run(
            ["bash", str(SCRIPT), str(self.candidates), "--replay", str(self.replay)],
            capture_output=True, text=True, env={
                "PATH": "/usr/bin:/bin", "FLEET_FILTER_REPO": str(REPO),
                "FLEET_FILTER_QUEUE": str(self.queue),
                "FLEET_FILTER_DECISIONS": str(self.ledger),
                "FLEET_FILTER_REVIEW_LOG": str(self.tmp / "logs"),
            }, timeout=120)
        self.assertEqual(result.returncode, 0,
                         msg="candidate-review.sh exited %s:\n%s" % (result.returncode, result.stderr))
        return result

    def test_an_accepted_candidate_becomes_a_queue_item_the_worker_can_read(self):
        """A missing key makes the worker prompt fail at json.load, so the shape is a contract."""
        self.run_script()
        item = json.loads((self.queue / "CVE-2099-0001.json").read_text())
        for field in ("cve", "product", "kev", "epss", "definition_of_done"):
            self.assertIn(field, item)
        self.assertEqual(item["cve"], "CVE-2099-0001")
        self.assertIn("install.php", item["decision"])

    def test_a_rejected_candidate_does_not_reach_the_queue(self):
        """Rejecting is a decision, and the whole point is that no session starts."""
        self.run_script()
        self.assertFalse((self.queue / "CVE-2099-0002.json").exists())

    def test_both_outcomes_are_recorded_with_their_reason(self):
        """A rejection with no reason is an opinion; the ledger has to carry the category."""
        self.run_script()
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 2)
        rejected = next(r for r in rows if r["id"] == "CVE-2099-0002")
        self.assertEqual(rejected["reason"], "needs-authentication")
        self.assertTrue(rejected["at"])

    def test_an_unanswered_candidate_is_recorded_as_missing_not_accepted(self):
        """Silence must not start work: a candidate the review did not decide is not queued."""
        self.replay.write_text(json.dumps(DECISIONS[1]) + "\n")
        self.run_script()
        self.assertFalse((self.queue / "CVE-2099-0001.json").exists())
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines() if line.strip()]
        self.assertEqual(next(r for r in rows if r["id"] == "CVE-2099-0001")["decision"], "missing")


if __name__ == "__main__":
    unittest.main()
