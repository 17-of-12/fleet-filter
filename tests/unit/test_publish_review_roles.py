"""A pass verdict must name the three roles that produced it, or nothing is posted."""

import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "publish_review", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "publish-review.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)


def missing(text):
    """The role labels a verdict note fails to name."""
    return PUBLISH.missing_roles(text)


class Roles(unittest.TestCase):
    """The check that stands between a skipped verifier and a compliant-looking pass."""

    def test_a_bare_pass_is_refused(self):
        """A note naming no role lists all three as missing."""
        self.assertEqual(len(missing("looks fine to me")), 3)

    def test_a_partial_note_names_what_is_missing(self):
        """Reviewer-only notes are refused, and say which roles are absent."""
        self.assertEqual(missing("reviewer: checked the diff"),
                         ["verifier:", "verified by primary:"])

    def test_a_complete_note_passes(self):
        """All three labels present means nothing is missing."""
        text = ("reviewer (adversarial): found X | verifier: CONFIRMED X | "
                "verified by primary: opened the file")
        self.assertEqual(missing(text), [])

    def test_empty_notes_are_refused(self):
        """No notes at all is the same failure as notes without roles."""
        self.assertEqual(len(missing(None)), 3)


if __name__ == "__main__":
    unittest.main()
