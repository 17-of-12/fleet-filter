"""The re-cut keeps the content and stops on a conflict - tested on a throwaway repository."""

import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "recut", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "recut-pr.py")
RECUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECUT)


def git(repo, *args):
    """Run git in the fixture repository, returning stdout."""
    return subprocess.run(["git"] + list(args), cwd=repo, capture_output=True, text=True,
                          check=True).stdout.strip()


class Rebase(unittest.TestCase):
    """A stale branch, rebased onto a moved main, without touching GitHub."""

    def setUp(self):
        """A repository with main, a feature branch, and one commit added to each."""
        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, True)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        (pathlib.Path(self.repo) / "base.txt").write_text("base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base")
        git(self.repo, "checkout", "-q", "-b", "feature")
        (pathlib.Path(self.repo) / "feature.txt").write_text("feature\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "feature")
        self.head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "main")
        (pathlib.Path(self.repo) / "main.txt").write_text("moved\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "main moved")
        git(self.repo, "remote", "add", "origin", self.repo)
        git(self.repo, "fetch", "-q", "origin")

    def test_a_stale_branch_is_rebased_and_keeps_its_change(self):
        """The re-cut carries the same content onto the new base, as a linear history."""
        ok, message = RECUT.rebase_onto(self.repo, self.head, "recut")
        self.assertTrue(ok, message)
        self.assertEqual(git(self.repo, "branch", "--show-current"), "recut")
        self.assertEqual(git(self.repo, "log", "--format=%s", "-1"), "feature")
        self.assertTrue((pathlib.Path(self.repo) / "main.txt").exists(), "main's commit is present")
        self.assertTrue((pathlib.Path(self.repo) / "feature.txt").exists(), "the change survived")

    def test_a_conflict_stops_and_leaves_no_half_applied_rebase(self):
        """Dropping a change silently is worse than failing: the rebase is aborted."""
        (pathlib.Path(self.repo) / "base.txt").write_text("feature side\n")
        git(self.repo, "checkout", "-q", "feature")
        git(self.repo, "commit", "-qam", "touch base")
        head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "main")
        (pathlib.Path(self.repo) / "base.txt").write_text("main side\n")
        git(self.repo, "commit", "-qam", "touch base on main")
        # The rebase targets origin/main, so the fixture must refresh it the way the real script does.
        git(self.repo, "fetch", "-q", "origin")
        ok, message = RECUT.rebase_onto(self.repo, head, "conflict")
        self.assertFalse(ok)
        self.assertTrue(message, "the conflict text is reported")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "", "the rebase was aborted")


if __name__ == "__main__":
    unittest.main()
