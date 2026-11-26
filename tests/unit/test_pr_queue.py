"""Who may enter the unattended review queue, and in which mode."""

import contextlib
import importlib.util
import io
import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "queue", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "prs-needing-review.py")
QUEUE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUEUE)


def pull(fork=None, author=None, branch="release/x", title="signatures: x", sha="0" * 40, number=None):
    """A pull request shaped like the API's, with the fields classify() and main() each read."""
    result = {"head": {"ref": branch, "sha": sha, "repo": {"full_name": fork or QUEUE.REPO}},
              "user": {"login": author or QUEUE.BOT}, "title": title}
    if number is not None:
        result["number"] = number
    return result


def state(gate="success", verdict=None, finished=None):
    """A check-run map, as checks() returns it."""
    return {"gate": (gate, None), "agent-review": (verdict, finished)}


def minutes_ago(minutes):
    """A check-run completion stamp, as the API formats it."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


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
        """An App-authored branch that is neither `release/*` nor `signatures:` is not release work.

        The dependabot-shaped branch here is paired with the App author on purpose: a pull request
        actually authored by dependabot is covered in DependabotBumps below, and it is not refused.
        """
        self.assertFalse(QUEUE.classify(pull(branch="dependabot/x", title="chore(deps): x"), state())[0])

    def test_a_fresh_pull_request_needs_a_review(self):
        """A pull request with no agent-review check is selected in review mode."""
        self.assertEqual(QUEUE.classify(pull(), state()), (True, "review"))

    def test_a_pass_without_a_merge_is_finished_not_reviewed(self):
        """A posted pass whose merge failed is stranded otherwise - nothing else looks at it."""
        self.assertEqual(QUEUE.classify(pull(), state(verdict="success")), (True, "merge"))

    def test_a_failure_backs_off_instead_of_re_reviewing_every_tick(self):
        """A ten-minute timer must not spend an agent session on the same FAIL each tick."""
        self.assertTrue(QUEUE.recent_failure(("failure", minutes_ago(5)), 30))
        self.assertFalse(QUEUE.recent_failure(("failure", minutes_ago(90)), 30))
        self.assertFalse(QUEUE.recent_failure(("success", minutes_ago(5)), 30))


class DependabotBumps(unittest.TestCase):
    """A version bump is mechanical: the deterministic check decides it, not a session."""

    def test_a_dependabot_bump_is_checked_by_machine(self):
        """No verdict yet on a dependabot/* branch means mode `machine`, not mode `review`."""
        bump = pull(author="dependabot[bot]", branch="dependabot/pip/pyjwt-2.15.0",
                    title="chore(deps): bump pyjwt from 2.10.1 to 2.15.0")
        self.assertEqual(QUEUE.classify(bump, state()), (True, "machine"))

    def test_a_dependabot_bump_with_a_pass_is_merged(self):
        """The verdict exists already, so finishing it needs no second check."""
        bump = pull(author="dependabot[bot]", branch="dependabot/pip/pyjwt-2.15.0",
                    title="chore(deps): bump pyjwt from 2.10.1 to 2.15.0")
        self.assertEqual(QUEUE.classify(bump, state(verdict="success")), (True, "merge"))

    def test_a_dependabot_bump_needs_a_green_gate_too(self):
        """A red tree is not merged by a green pin check either."""
        bump = pull(author="dependabot[bot]", branch="dependabot/pip/pyjwt-2.15.0",
                    title="chore(deps): bump pyjwt from 2.10.1 to 2.15.0")
        self.assertFalse(QUEUE.classify(bump, state(gate="failure"))[0])

    def test_an_author_named_dependabot_on_another_branch_is_refused(self):
        """The branch has to be dependabot's own, so the author claim cannot be typed by hand."""
        odd = pull(author="dependabot[bot]", branch="feature/x", title="chore(deps): x")
        ok, why = QUEUE.classify(odd, state())
        self.assertFalse(ok)
        self.assertIn("dependabot branch", why)


class Selection(unittest.TestCase):
    """The queue names one pull request, and the failure timer must not name the same one forever."""

    def _select(self, pulls, states):
        """What the queue prints and returns, with the three API calls replaced by given answers."""
        with mock.patch.object(QUEUE, "token", return_value="t"), \
                mock.patch.object(QUEUE, "get_all_pages", return_value=pulls), \
                mock.patch.object(QUEUE, "checks", side_effect=lambda sha, value: states[sha]):
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = QUEUE.main([])
        return code, captured.getvalue().strip()

    def test_a_refused_bump_does_not_starve_the_prs_behind_it(self):
        """A bump refused five minutes ago is skipped, so the next pull request still gets worked."""
        refused = pull(number=21, author="dependabot[bot]", branch="dependabot/pip/pyjwt-2.15.0",
                       title="chore(deps): x", sha="sha-21")
        waiting = pull(number=22, branch="release/y", sha="sha-22")
        states = {"sha-21": state(verdict="failure", finished=minutes_ago(5)), "sha-22": state()}
        self.assertEqual(self._select([waiting, refused], states), (0, "22 review"))

    def test_a_refused_bump_is_not_re_posted_on_the_next_tick(self):
        """With nothing but the refused bump open, the queue is empty until the backoff expires."""
        refused = pull(number=21, author="dependabot[bot]", branch="dependabot/pip/pyjwt-2.15.0",
                       title="chore(deps): x", sha="sha-21")
        states = {"sha-21": state(verdict="failure", finished=minutes_ago(5))}
        self.assertEqual(self._select([refused], states), (1, ""))

    def test_a_refused_release_pr_still_backs_off(self):
        """The timer applies to every mode that would redo work, not only to the one it started with."""
        failed = pull(number=20, branch="release/z", sha="sha-20")
        states = {"sha-20": state(verdict="failure", finished=minutes_ago(5))}
        self.assertEqual(self._select([failed], states), (1, ""))

    def test_a_bump_awaiting_a_verdict_is_selected_in_machine_mode(self):
        """main() prints the mode classify() chose, so a fresh bump reaches the check."""
        bump = pull(number=21, author="dependabot[bot]", branch="dependabot/pip/pyjwt-2.15.0",
                    title="chore(deps): x", sha="sha-21")
        self.assertEqual(self._select([bump], {"sha-21": state()}), (0, "21 machine"))

    def test_a_pass_waiting_only_on_a_merge_is_never_backed_off(self):
        """Finishing a merge is not a redo, so a fresh pass is picked seconds after it posted."""
        waiting = pull(number=22, branch="release/y", sha="sha-22")
        states = {"sha-22": state(verdict="success", finished=minutes_ago(0))}
        self.assertEqual(self._select([waiting], states), (0, "22 merge"))


if __name__ == "__main__":
    unittest.main()
