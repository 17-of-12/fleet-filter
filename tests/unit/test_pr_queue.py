"""Who may enter the unattended review queue, and in which mode."""

import importlib.util
import pathlib
import unittest
from datetime import datetime, timedelta, timezone

SPEC = importlib.util.spec_from_file_location(
    "queue", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "prs-needing-review.py")
QUEUE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUEUE)


def pull(fork=None, author=None, branch="release/x", title="signatures: x"):
    """A pull request shaped like the API's, with the fields classify() reads."""
    return {"head": {"ref": branch, "repo": {"full_name": fork or QUEUE.REPO}},
            "user": {"login": author or QUEUE.BOT}, "title": title}


def state(gate="success", verdict=None, finished=None):
    """A check-run map, as checks() returns it."""
    return {"gate": (gate, None), "agent-review": (verdict, finished)}


class Queue(unittest.TestCase):
    """Provenance cannot be typed: the head repository and the author decide."""

    def test_a_fork_is_refused(self):
        """A branch name proves nothing; an external head never reaches the review session."""
        ok, why = QUEUE.classify(pull(fork="someone/fleet-filter"), state())
        self.assertFalse(ok)
        self.assertIn("fork", why)

    def test_a_human_author_is_refused(self):
        """Only the release App opens work this queue may touch."""
        ok, _ = QUEUE.classify(pull(author="a-person"), state())
        self.assertFalse(ok)

    def test_a_red_or_missing_gate_is_refused(self):
        """There is no point reviewing a tree that has not passed the gate."""
        self.assertFalse(QUEUE.classify(pull(), state(gate="failure"))[0])
        self.assertFalse(QUEUE.classify(pull(), state(gate=None))[0])

    def test_a_misnamed_branch_is_refused(self):
        """Dependabot and feature branches are not release work."""
        self.assertFalse(QUEUE.classify(pull(branch="dependabot/x", title="chore(deps): x"), state())[0])

    def test_a_fresh_pull_request_needs_a_review(self):
        """A pull request with no agent-review check is selected in review mode."""
        self.assertEqual(QUEUE.classify(pull(), state()), (True, "review"))

    def test_a_pass_without_a_merge_is_finished_not_reviewed(self):
        """A posted pass whose merge failed is stranded otherwise - nothing else looks at it."""
        self.assertEqual(QUEUE.classify(pull(), state(verdict="success")), (True, "merge"))

    def test_a_failure_backs_off_instead_of_re_reviewing_every_tick(self):
        """A ten-minute timer must not spend an agent session on the same FAIL each tick."""
        recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        old = (datetime.now(timezone.utc) - timedelta(minutes=90)).isoformat()
        self.assertTrue(QUEUE.recent_failure(("failure", recent), 30))
        self.assertFalse(QUEUE.recent_failure(("failure", old), 30))
        self.assertFalse(QUEUE.recent_failure(("success", recent), 30))


if __name__ == "__main__":
    unittest.main()
