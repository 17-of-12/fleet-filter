"""Where `recut-pr.py` creates the replacement branch: the pull request's head, not FETCH_HEAD.

The script says it works from the pull request's own commits, and the first version took the sha from
`FETCH_HEAD` after fetching `main` and `pull/N/head` in one call. Git records the fetched refs in that
order, so FETCH_HEAD was main: the re-cut branch was created at main, the reviewed content stayed
behind, and the new pull request would have been refused with "no commits between main and
release/recut-N". The API answer is used by name instead, which is the only answer that is the
pull request's head by definition.
"""

import importlib.util
import pathlib
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "recut_pr", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "recut-pr.py")
RECUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECUT)

OLD = "the-old-base-sha"
HEAD = "the-pull-request-head-sha"
MAIN = "the-current-main-sha"


def pull(base=OLD, head=HEAD):
    """The pull request as the API answers it, with the two shas the script reads."""
    return {"number": 23, "title": "Deps: PyJWT 2.15.0", "body": "b",
            "base": {"sha": base}, "head": {"sha": head, "ref": "release/deps-pyjwt-2-15"}}


def answers(path, method="GET", body=None):
    """The GitHub answers the script asks for: the pull request, main's ref, and the new PR number."""
    if path.startswith("/pulls/23") and method == "GET":
        return pull()
    if path == "/git/refs/heads/main":
        return {"object": {"sha": MAIN}}
    if path == "/pulls" and method == "POST":
        return {"number": 24}
    return None


class RecutBranch(unittest.TestCase):
    """The re-cut branch has to be the pull request's head, rebased; anything else loses the work."""

    def _run(self, argv, as_pull=None, rebase=None):
        """Run main() with the GitHub API and the git runner replaced by recorders."""
        asked = as_pull or pull()
        commands = []

        def fake_api(path, method="GET", body=None):
            """Answer the three endpoints main() calls with the shas this test controls."""
            if path.startswith("/pulls/23") and method == "GET":
                return asked
            if path == "/git/refs/heads/main":
                return {"object": {"sha": MAIN}}
            if path == "/pulls" and method == "POST":
                return {"number": 24}
            return None

        def fake_run(args, cwd=None, check=True):
            """Record every git command instead of running it, so the command list is the assertion."""
            commands.append(list(args))
            return ""

        with mock.patch.object(RECUT, "api", side_effect=fake_api), \
                mock.patch.object(RECUT, "run", side_effect=fake_run), \
                mock.patch.object(RECUT.os.path, "isdir", return_value=True), \
                mock.patch.object(RECUT.subprocess, "run",
                                  return_value=rebase or mock.Mock(returncode=0, stdout="", stderr="")):
            code = RECUT.main(argv)
        return code, commands

    def test_the_branch_is_created_at_the_pull_requests_own_head(self):
        """Re-cutting #23 moves release/recut-23 to pull/23/head, not to main's tip."""
        code, commands = self._run(["--pr", "23"])
        self.assertEqual(code, 0)
        self.assertIn(["git", "checkout", "--quiet", "-B", "release/recut-23", HEAD], commands)
        self.assertNotIn(["git", "checkout", "--quiet", "-B", "release/recut-23", "FETCH_HEAD"], commands)
        self.assertIn(["git", "fetch", "--quiet", "origin", "main", "pull/23/head"], commands)
        self.assertIn(["git", "push", "--quiet", "origin", "release/recut-23"], commands)

    def test_a_conflicting_rebase_leaves_the_branch_alone(self):
        """A conflict is exit 1 with the branch never pushed, not a half-rebased release."""
        code, commands = self._run(["--pr", "23"], rebase=mock.Mock(returncode=1, stdout="",
                                                                    stderr="CONFLICT (add/add)"))
        self.assertEqual(code, 1)
        self.assertNotIn(["git", "push", "--quiet", "origin", "release/recut-23"], commands)

    def test_a_current_base_is_left_alone(self):
        """Nothing is re-cut while the recorded base is already current; exit 2 says so."""
        code, commands = self._run(["--pr", "23"], as_pull=pull(base=MAIN))
        self.assertEqual(code, 2)
        self.assertEqual(commands, [])


if __name__ == "__main__":
    unittest.main()
