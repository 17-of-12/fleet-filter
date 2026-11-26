"""The stale-base refusal in `bin/publish-review.py`: what it refuses, what it must not.

Why this suite exists
---------------------
The PR that added the check also added the exit code the worker codes against, and no test named it:
the refusal path was verified by reading. Reading is how the first version shipped a `sys.exit(...)`
that exited 1 - the code meaning "no verdict possible" - so a merge attempt on a moved main looked like
a generic failure instead of the one case `bin/recut-pr.py` knows how to fix. These tests pin the exit
code, the fact that nothing is posted when it refuses, and the paths that must keep working.

The module's `call` and `token` are stubbed, so nothing here touches GitHub; the requests the stub
records are the assertion, not the printed text.
"""

import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "publish_review", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "publish-review.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)

OLD_MAIN = "a" * 40
MOVED_MAIN = "b" * 40
HEAD_SHA = "c" * 40


class Api:
    """Stands in for `PUBLISH.call`: answers the endpoints `main()` reads and records every request."""

    def __init__(self, base_sha, main_sha, merge_status=200, check_status=201):
        """Canned answers for the pull request, the `main` ref, the merge and the check run."""
        self.base_sha = base_sha
        self.main_sha = main_sha
        self.merge_status = merge_status
        self.check_status = check_status
        self.calls = []

    def __call__(self, path, token_value, method="GET", body=None):
        """Route one API path to its canned answer, recording the request first."""
        self.calls.append((method, path))
        if path.endswith("/check-runs"):
            return self.check_status, {"id": 1}
        if path.endswith("/merge") and method == "PUT":
            return self.merge_status, {"message": "merged"}
        if path.endswith("/git/refs/heads/main"):
            return (200, {"object": {"sha": self.main_sha}}) if self.main_sha else (404, "no main")
        return 200, {"number": 22, "head": {"ref": "release/x", "sha": HEAD_SHA},
                     "base": {"sha": self.base_sha}}


def run(argv, base_sha=OLD_MAIN, main_sha=MOVED_MAIN, merge_status=200):
    """Run `main(argv)` against a stubbed API; return (exit code, printed output, requests made)."""
    api = Api(base_sha, main_sha, merge_status=merge_status)
    with mock.patch.object(PUBLISH, "token", return_value="t"), \
            mock.patch.object(PUBLISH, "call", api):
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = PUBLISH.main(argv)
    return code, captured.getvalue(), api.calls


class StaleBase(unittest.TestCase):
    """Main moved after the branch was cut, so the checked commit is not the mergeable one."""

    def test_a_pass_on_a_stale_base_exits_three(self):
        """Exit 3 is the worker's signal to re-cut; exit 1 (the old `sys.exit`) was only "failed"."""
        code, printed, _ = run(["--pr", "22", "--verdict", "pass", "--machine", "--no-merge",
                                "--notes", "machine-checked: clean"])
        self.assertEqual(code, 3)
        self.assertIn("base is stale", printed)

    def test_a_stale_refusal_posts_no_check_and_merges_nothing(self):
        """Refusing before the check run exists is what leaves the queue without a verdict to back off."""
        _, _, calls = run(["--pr", "22", "--verdict", "pass", "--machine", "--no-merge",
                           "--notes", "machine-checked: clean"])
        self.assertEqual(calls, [("GET", "/repos/%s/%s/pulls/22" % (PUBLISH.OWNER, PUBLISH.REPO)),
                                 ("GET", "/repos/%s/%s/git/refs/heads/main"
                                  % (PUBLISH.OWNER, PUBLISH.REPO))])

    def test_a_merge_only_on_a_stale_base_exits_three(self):
        """The finish-a-pass path asks the same question and gets the same answer."""
        code, printed, calls = run(["--pr", "22", "--merge-only"])
        self.assertEqual(code, 3)
        self.assertIn("base is stale", printed)
        self.assertNotIn(("PUT", "/repos/%s/%s/pulls/22/merge" % (PUBLISH.OWNER, PUBLISH.REPO)), calls)

    def test_a_refusal_on_a_stale_base_still_posts(self):
        """Only a pass can be re-cut: a `fail` verdict needs no mergeable commit to be true."""
        code, _, calls = run(["--pr", "22", "--verdict", "fail", "--machine",
                              "--notes", "machine-checked: refused - not a pin"])
        self.assertEqual(code, 0)
        self.assertIn(("POST", "/repos/%s/%s/check-runs" % (PUBLISH.OWNER, PUBLISH.REPO)), calls)

    def test_a_current_base_posts_and_merges(self):
        """With main where the PR was cut from, the pass posts the check and merges it."""
        code, printed, calls = run(["--pr", "22", "--verdict", "pass", "--machine",
                                    "--notes", "machine-checked: clean"],
                                   base_sha=MOVED_MAIN, main_sha=MOVED_MAIN)
        self.assertEqual(code, 0)
        self.assertIn(("POST", "/repos/%s/%s/check-runs" % (PUBLISH.OWNER, PUBLISH.REPO)), calls)
        self.assertIn(("PUT", "/repos/%s/%s/pulls/22/merge" % (PUBLISH.OWNER, PUBLISH.REPO)), calls)
        self.assertIn("merged #22", printed)

    def test_a_missing_main_ref_is_not_called_stale(self):
        """An unreadable `main` is not evidence of staleness, so it must not refuse the merge."""
        code, _, _ = run(["--pr", "22", "--verdict", "pass", "--machine", "--no-merge",
                          "--notes", "machine-checked: clean"], main_sha="")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
