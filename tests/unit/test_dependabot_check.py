"""What the deterministic dependency-bump check will call a clean bump, and what it refuses."""

import importlib.util
import pathlib
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "dependabot_check",
    pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "dependabot-check.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def diff(name, *lines):
    """One file of a pull request's file list, with the patch's own header lines in front.

    The headers are written the way `git format-patch` writes them. The API's `patch` field is thinner -
    measured on /pulls/22/files, it starts at the `@@ ... @@` line and sends no `--- a/` or `+++ b/` -
    so the fixture carries both shapes: the extra lines must be skipped as headers, and the `@@` line the
    API does send must be skipped too, without the skip swallowing a deleted line that merely starts
    with `--`.
    """
    return (name, ["+++ b/%s" % name, "--- a/%s" % name, "@@ -1,2 +1,2 @@"] + list(lines))


class Verdict(unittest.TestCase):
    """Every changed line is a pin, and the pins added are the pins removed."""

    def test_a_pip_bump_is_clean(self):
        """The case the check exists for: one distribution, one version moved."""
        self.assertEqual(
            CHECK.verdict([diff("requirements-dev.txt", "+PyJWT==2.15.0", "-PyJWT==2.10.1")]),
            (True, "every changed line in requirements-dev.txt is a version pin"))

    def test_a_pinned_action_sha_bump_is_clean(self):
        """Actions are pinned as `owner/repo@<40 hex>` plus a `# vN` comment; the slash is the name."""
        self.assertTrue(CHECK.verdict([diff(
            ".github/workflows/checks.yml",
            "+        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7",
            "-        uses: actions/checkout@38cb216a1b03431b0c71054e35238d04e0d1e652  # v6")])[0])

    def test_a_version_tag_action_bump_is_clean(self):
        """A workflow pinned to a tag rather than a SHA is still a version change."""
        self.assertTrue(CHECK.verdict([diff(".github/workflows/x.yml",
                                           "+uses: actions/cache@v6", "-uses: actions/cache@v4")])[0])

    def test_an_action_pinned_to_a_branch_is_refused(self):
        """`@main` is a moving branch, not a version, so it is not a bump."""
        self.assertFalse(CHECK.verdict([diff(".github/workflows/x.yml",
                                             "+uses: someone/tool@main", "-uses: someone/tool@old")])[0])

    def test_a_cargo_package_version_bump_is_clean(self):
        """The `[package]` version line: the name is in the header above it, so only the form is checkable.

        This is the shape the first version's cargo test exercised - and the line dependabot does not
        edit when it bumps a dependency, which is what `test_a_cargo_dependency_line_bump_is_clean`
        now covers as well.
        """
        self.assertTrue(CHECK.verdict([diff("gateway/Cargo.toml",
                                            '+version = "0.1.3"', '-version = "0.1.2"')])[0])

    def test_a_cargo_dependency_line_bump_is_clean(self):
        """`tokio = { version = \"=1.54.1\", ... }` is the line a cargo bump actually edits here.

        gateway/Cargo.toml pins its dependencies as inline tables, so a version-key-only matcher read
        the real bump as "not a version pin" and refused every cargo PR forever.
        """
        self.assertTrue(CHECK.verdict([diff(
            "gateway/Cargo.toml",
            '-tokio = { version = "=1.54.1", default-features = false, features = ["rt"] }',
            '+tokio = { version = "=1.54.2", default-features = false, features = ["rt"] }')])[0])

    def test_a_cargo_lock_bump_with_its_checksum_is_clean(self):
        """A lockfile bump changes the checksum too; a diff that only read `version` refused it.

        The checksum is the package's bytes, so it moves whenever the version does, and it is only a
        pin in a `.lock` - which is why the same line in a text file is not (see the `notes.txt` case).
        """
        self.assertTrue(CHECK.verdict([diff(
            "gateway/Cargo.lock", 'name = "tokio"', '-version = "1.54.1"', '+version = "1.54.2"',
            '-checksum = "b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3"',
            '+checksum = "0f2a3e5b0c1d4e8a9f6b7c8d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f"')])[0])

    def test_a_pin_whose_version_did_not_move_is_refused(self):
        """`+PyJWT==2.15.0` over `-PyJWT==2.15.0` changes nothing, so it is not a bump.

        The first version compared only which pins existed on each side, so an edited comment on an
        unchanged pin - `+uses: x/y@sha  # v666 edited` over the same sha - read as clean.
        """
        ok, why = CHECK.verdict([("requirements.txt", ["+PyJWT==2.15.0", "-PyJWT==2.15.0"])])
        self.assertFalse(ok)
        self.assertIn("no version moved", why)

    def test_an_edited_comment_on_an_unchanged_action_pin_is_refused(self):
        """The sha is the version of an action pin; a comment edit beside it moved nothing."""
        self.assertFalse(CHECK.verdict([diff(
            ".github/workflows/x.yml",
            "+uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v666 edited",
            "-uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v6")])[0])

    def test_a_version_line_in_a_text_file_that_is_not_a_requirement_is_refused(self):
        """`version = \"1.2.3\"` is a dependency line in a .toml and prose in a .txt.

        The shape list always said the version-key form belonged to Cargo.toml/pyproject.toml; the code
        applied it to every allowed extension, so `notes.txt` passed on it.
        """
        ok, why = CHECK.verdict([("notes.txt", ['+version = "1.2.3"', '-version = "1.2.2"'])])
        self.assertFalse(ok)
        self.assertIn("not a version pin", why)

    def test_a_deleted_line_that_looks_like_a_header_is_still_read(self):
        """A deleted `--` renders as `----`, and the old header test swallowed it without reading it.

        Headers name the file (`--- a/<path>`), so only those are skipped now; a content line that
        merely starts with `---` is classified like any other change.
        """
        ok, why = CHECK.verdict([(".github/workflows/x.yml",
                                  ["--- a/.github/workflows/x.yml", "+++ b/.github/workflows/x.yml",
                                   "@@ -1,3 +1,2 @@", "----", "-uses: x/y@v1", "+uses: x/y@v2"])])
        self.assertFalse(ok)
        self.assertIn("not a version pin: ----", why)

    def test_a_script_edit_is_refused(self):
        """A file that is not a dependency file cannot be a dependency bump, however it is written."""
        ok, why = CHECK.verdict([diff("bin/publish-review.py", "+x = 1", "-x = 2")])
        self.assertFalse(ok)
        self.assertIn("not a dependency file", why)

    def test_a_comment_edit_riding_along_is_refused(self):
        """A changed comment is not a version pin, which is what stops prose riding on a bump."""
        ok, _ = CHECK.verdict([diff("requirements-dev.txt", "+PyJWT==2.15.0", "-PyJWT==2.10.1",
                                    "+# now with jwt")])
        self.assertFalse(ok)

    def test_a_file_with_no_patch_is_refused(self):
        """A binary change has no patch, and zero lines proves nothing about the content.

        The first version of the check turned an absent patch into an empty list and called the file a
        clean bump without reading a line of it.
        """
        ok, why = CHECK.verdict([("Cargo.lock", None)])
        self.assertFalse(ok)
        self.assertIn("no patch", why)

    def test_a_file_of_an_unknown_kind_is_refused_before_the_patch_is_read(self):
        """The extension is checked first, so `assets/blob.bin` is refused without reading its diff."""
        ok, why = CHECK.verdict([("assets/blob.bin", None)])
        self.assertFalse(ok)
        self.assertIn("not a dependency file", why)

    def test_a_new_dependency_is_refused(self):
        """`+newdep==1.2.3` with nothing removed changes what exists, not which version is used."""
        ok, why = CHECK.verdict([("requirements.txt", ["+newdep==1.2.3"])])
        self.assertFalse(ok)
        self.assertIn("which dependencies exist", why)

    def test_a_swapped_dependency_is_refused(self):
        """Every line is a pin, but the names differ on the two sides: one in, one out."""
        ok, _ = CHECK.verdict([("requirements.txt", ["+python-jose==3.3.0", "-pyjwt==2.10.1"])])
        self.assertFalse(ok)

    def test_the_same_name_spelled_differently_is_still_one_dependency(self):
        """PEP 503 folds case and separators, so `+PyJWT` over `-pyjwt` is a bump rather than a swap."""
        self.assertTrue(CHECK.verdict([("requirements.txt", ["+PyJWT==2.15.0", "-pyjwt==2.10.1"])])[0])

    def test_a_pull_request_with_no_files_is_refused(self):
        """A pull request that touches nothing is refused rather than passed with an empty file list."""
        self.assertEqual(CHECK.verdict([]), (False, "the pull request changes no files"))

    def test_a_multi_file_grouped_bump_is_clean(self):
        """dependabot groups an ecosystem's bumps into one pull request; every file must pair up."""
        self.assertTrue(CHECK.verdict([diff("requirements-dev.txt", "+PyJWT==2.15.0", "-PyJWT==2.10.1"),
                                       diff("gateway/Cargo.lock", '+version = "1.4.0"',
                                            '-version = "1.3.9"')])[0])


class ExitStatus(unittest.TestCase):
    """The worker codes against 0 clean, 1 refused, 2 could not run."""

    def test_the_exit_codes_are_named(self):
        """The three states are distinct constants, so a crash cannot be posted as a refusal."""
        self.assertEqual((CHECK.EXIT_CLEAN, CHECK.EXIT_REFUSED, CHECK.EXIT_CANNOT_RUN), (0, 1, 2))

    def test_an_unexpected_error_exits_cannot_run_not_refused(self):
        """An uncaught exception exits 1, which is the code a refusal answers with.

        The first version let `item["filename"]` on a malformed API entry raise out of main(), so the
        worker read exit 1 and posted "machine-checked: refused" for a diff it never read.
        """
        with mock.patch.object(CHECK, "token", return_value="t"), \
                mock.patch.object(CHECK, "changed_files", side_effect=RuntimeError("boom")):
            self.assertEqual(CHECK.main(["--pr", "21"]), CHECK.EXIT_CANNOT_RUN)

    def test_a_file_entry_without_a_filename_exits_cannot_run(self):
        """The API shape is checked before the line is, so a malformed entry is 2 and not 1."""
        with mock.patch.object(CHECK, "_get_all_pages", return_value=[{"patch": "+x"}]):
            with self.assertRaises(SystemExit) as raised:
                CHECK.changed_files(21, "t")
            self.assertEqual(raised.exception.code, CHECK.EXIT_CANNOT_RUN)

    def test_a_file_list_too_long_to_read_is_an_error_not_a_partial_verdict(self):
        """Fetching stops at a page ceiling; past it the answer is 2, not a verdict on the half read.

        `limit=10` pages used to be returned as if complete, which moved the "judged on its first
        hundred files" bug from 100 files to 1000 and kept it silent.
        """
        with mock.patch.object(CHECK, "_get", return_value=[{"filename": "a.txt", "patch": ""}]
                              * CHECK.PAGE_SIZE):
            with self.assertRaises(SystemExit) as raised:
                CHECK._get_all_pages("/repos/x/pulls/1/files", "t", limit=2)
            self.assertEqual(raised.exception.code, CHECK.EXIT_CANNOT_RUN)

    def test_a_diff_bigger_than_one_page_is_read_in_full(self):
        """1005 files are read to the last one, and a non-pin on page 11 refuses the whole pull request.

        The first version's single call judged 105-file PRs on their first hundred; the fix judged them
        on their first thousand. Either way the answer must be "read everything, refuse", not "clean".
        """
        def fake_get(path, value):
            """Ten full pages plus five entries on the eleventh; entry 1003 is not a version pin."""
            page = int(path.rsplit("page=", 1)[1])
            count = CHECK.PAGE_SIZE if page <= 10 else 5
            return [{"filename": "evil.py" if (page - 1) * CHECK.PAGE_SIZE + i == 1002
                     else "f%d.txt" % ((page - 1) * CHECK.PAGE_SIZE + i),
                     "patch": "+import os" if (page - 1) * CHECK.PAGE_SIZE + i == 1002
                     else "+a==1.0\n-a==0.9"}
                    for i in range(count)]

        with mock.patch.object(CHECK, "_get", side_effect=fake_get):
            files = CHECK.changed_files(21, "t")
            self.assertEqual(len(files), 1005)
            self.assertIn("evil.py", [name for name, _ in files])
            self.assertFalse(CHECK.verdict(files)[0])

    def test_a_short_page_ends_the_fetch_without_reaching_the_ceiling(self):
        """A page smaller than the page size is the last page, so the list comes back whole."""
        with mock.patch.object(CHECK, "_get", return_value=[{"filename": "a.txt", "patch": ""}]):
            self.assertEqual(CHECK._get_all_pages("/repos/x/pulls/1/files", "t"),
                             [{"filename": "a.txt", "patch": ""}])


if __name__ == "__main__":
    unittest.main()
