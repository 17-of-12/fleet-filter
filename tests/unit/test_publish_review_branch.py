"""A merged release branch is deleted, a non-release head is left alone, and the merge survives a failure.

Why this suite exists
---------------------
`delete_release_branch` was added by extracting code that used to live inline in the `--merge-only`
path, and the extraction is what fixed the second merge path (the verdict path) never deleting the
branch it had just merged. That is exactly the kind of change that reads fine and is verified by
reading: the guard, the URL it builds and the "never fail a merge" promise are all checkable without
touching GitHub, so the module-level `call` is stubbed and the requests are asserted instead.
"""

import importlib.util
import io
import pathlib
import re
import unittest
from contextlib import redirect_stdout

SPEC = importlib.util.spec_from_file_location(
    "publish_review", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "publish-review.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)


class StubCall:
    """Stands in for `PUBLISH.call`: records the requests, returns a canned status."""

    def __init__(self, status=200, body=None):
        """Remember the status the API should appear to return; start with no requests recorded."""
        self.status = status
        self.body = {"message": "ok"} if body is None else body
        self.calls = []

    def __call__(self, path, token_value, method="GET", body=None):
        """Match `PUBLISH.call`'s signature, record the request, and hand back the canned status."""
        self.calls.append((method, path))
        return self.status, self.body


def with_stub(pr, status=200):
    """Run `delete_release_branch` against one pull request shape, returning (requests, printed)."""
    stub = StubCall(status=status)
    original = PUBLISH.call
    PUBLISH.call = stub
    try:
        with redirect_stdout(io.StringIO()) as printed:
            PUBLISH.delete_release_branch("token-value", pr)
    finally:
        PUBLISH.call = original
    return stub.calls, printed.getvalue()


class DeleteReleaseBranch(unittest.TestCase):
    """The three promises of `delete_release_branch`: the right ref, only release refs, never fatal."""

    def test_a_merged_release_branch_is_deleted_at_its_ref(self):
        """A head under `release/` produces exactly one DELETE on that ref."""
        calls, printed = with_stub({"head": {"ref": "release/2026-11-26T041500Z"}})
        self.assertEqual(calls, [("DELETE", "/repos/%s/%s/git/refs/heads/release/2026-11-26T041500Z"
                                 % (PUBLISH.OWNER, PUBLISH.REPO))])
        self.assertIn("release/2026-11-26T041500Z", printed)
        self.assertIn("200", printed)

    def test_main_and_dependency_branches_are_never_deleted(self):
        """The guard is the only thing between a wrong `head.ref` and a deleted branch."""
        for ref in ("main", "dependabot/pip/cryptography-42.0.0", "cve/CVE-2026-129474", ""):
            with self.subTest(ref=ref):
                calls, printed = with_stub({"head": {"ref": ref}})
                self.assertEqual(calls, [])
                self.assertEqual(printed, "")

    def test_a_pull_request_without_a_head_is_not_an_error(self):
        """`head` missing or null yields no request rather than an AttributeError."""
        for pr in ({}, {"head": None}, {"head": {}}):
            with self.subTest(pr=pr):
                calls, printed = with_stub(pr)
                self.assertEqual(calls, [])
                self.assertEqual(printed, "")

    def test_a_refused_delete_is_reported_and_the_caller_still_succeeds(self):
        """A 404 from the delete is printed, not raised: a merge that happened stays a success."""
        calls, printed = with_stub({"head": {"ref": "release/2026-11-26T041500Z"}}, status=404)
        self.assertEqual(len(calls), 1)
        self.assertIn("404", printed)

    def test_both_merge_paths_call_it(self):
        """The bug this function fixed was one path deleting the branch and the other not."""
        source = pathlib.Path(SPEC.origin).read_text(encoding="utf-8")
        # `(?<!def )` keeps the definition itself out of the count, so this counts call sites only.
        call_sites = len(re.findall(r"(?<!def )delete_release_branch\(token_value, pr\)", source))
        self.assertEqual(call_sites, 2, "expected one call in the --merge-only path and one in the "
                                       "verdict path; found %d" % call_sites)


if __name__ == "__main__":
    unittest.main()
