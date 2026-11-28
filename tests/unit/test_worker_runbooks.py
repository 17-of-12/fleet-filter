"""The worker must be told to read a per-application runbook and to leave one behind."""

import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKER = (REPO / "bin" / "cve-worker.sh").read_text()
SKILL = (REPO / "skills" / "exploit-signature-pipeline.md").read_text()


class WorkerPrompt(unittest.TestCase):
    """A runbook nobody is told to read is a file, not a practice."""

    def test_the_prompt_names_the_runbook_directory(self):
        """The session has to know the path, not infer it from convention."""
        self.assertIn("lab/apps/", WORKER)

    def test_the_prompt_requires_updating_it_before_stopping(self):
        """Writing the runbook is part of the deliverable, not an optional courtesy."""
        self.assertIn("Before you stop", WORKER)
        self.assertIn("update that runbook", WORKER)

    def test_the_prompt_says_failure_counts(self):
        """The wall that stopped a session is the most valuable line in the file."""
        self.assertIn("success or failure", WORKER)
        self.assertIn("only records successes", WORKER)

    def test_the_skill_points_at_the_runbooks(self):
        """A session reads the skill first; if the skill never mentions them, they are invisible."""
        self.assertIn("lab/apps/", SKILL)


class Runbooks(unittest.TestCase):
    """The seeded runbooks have to contain what a next session can act on."""

    def read(self, name):
        """Contents of one runbook."""
        return (REPO / "lab" / "apps" / name).read_text()

    def test_every_runbook_has_the_sections_that_matter(self):
        """A runbook without build and verification cannot be followed."""
        for name in ("php.md", "apache.md", "wordpress.md"):
            text = self.read(name)
            for heading in ("## Build", "## Verification", "## Walls"):
                self.assertIn(heading, text, "%s is missing %s" % (name, heading))

    def test_the_php_runbook_carries_the_serializer_precondition(self):
        """Without the handler setting a serializer victim cannot reproduce its CVE at all."""
        self.assertIn("serialize_handler", self.read("php.md"))

    def test_the_wordpress_runbook_carries_the_permalink_wall(self):
        """A REST route 404s until permalinks are set, which reads as a missing endpoint."""
        self.assertIn("permalink", self.read("wordpress.md").lower())


if __name__ == "__main__":
    unittest.main()
