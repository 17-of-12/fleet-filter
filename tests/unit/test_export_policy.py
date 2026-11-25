#!/usr/bin/env python3
"""Tests that the public export publishes only what it is supposed to.

The rule this enforces: `docs/` is default-deny. A design record, a handoff or a working note is
internal unless someone deliberately lists it as public, because the failure mode of the other
direction - exclude what must not ship - is that the next document created in a hurry gets published.

Two things are checked, because either alone is insufficient:

1. the exporter keeps exactly the allowlisted documents and removes the directories that held the
   rest, so the public tree does not advertise that `handoffs/` ever existed;
2. no public document links to an internal one, because a link to something unpublished is a 404 a
   reader finds instead of an answer.
"""

import importlib.util
import os
import re
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_exporter():
    """Import bin/export-public.py, whose name is not a valid module identifier."""
    path = os.path.join(ROOT, "bin", "export-public.py")
    spec = importlib.util.spec_from_file_location("ff_export_public", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicDocsAllowlistTest(unittest.TestCase):
    """The allowlist is the contract; these tests describe what it means in practice."""

    @classmethod
    def setUpClass(cls):
        """Load the exporter once and read the public list."""
        cls.mod = load_exporter()
        cls.public = set(cls.mod.PUBLIC_DOCS)

    def test_every_allowlisted_document_exists(self):
        """An allowlist naming a missing file publishes nothing and hides the mistake."""
        missing = [p for p in self.public if not os.path.isfile(os.path.join(ROOT, p))]
        self.assertEqual(missing, [], "allowlisted but absent: %s" % missing)

    def test_an_internal_document_is_dropped_and_its_directory_removed(self):
        """Default-deny: a new file under docs/ is internal until someone says otherwise."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "export")
            for rel in ("docs/README.md", "docs/design/ADR-0001.md",
                        "docs/handoffs/HANDOFF.md", "docs/new-internal-note.md"):
                path = os.path.join(dest, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "w").write("# %s\n" % rel)
            dropped = dict(self.mod.prune_docs(__import__("pathlib").Path(dest)))
            self.assertIn("docs/design/ADR-0001.md", dropped)
            self.assertIn("docs/handoffs/HANDOFF.md", dropped)
            self.assertIn("docs/new-internal-note.md", dropped)
            self.assertNotIn("docs/README.md", dropped)
            self.assertFalse(os.path.exists(os.path.join(dest, "docs/design")),
                             "an emptied internal directory must not survive: its name is a hint")

    def test_no_public_document_links_to_an_internal_one(self):
        """A link to an unpublished file is a 404 the reader finds instead of an answer."""
        link = re.compile(r"\[[^\]]*\]\(([^)\s#]+)")
        allowed = {os.path.normpath(p) for p in self.public}
        offenders = []
        for doc in self.public:
            try:
                text = open(os.path.join(ROOT, doc)).read()
            except OSError:
                continue
            for target in link.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                resolved = os.path.normpath(os.path.join(os.path.dirname(doc), target))
                if not resolved.startswith("docs/"):
                    continue
                if resolved not in allowed:
                    # An anchor on an allowed document resolves to that document.
                    if resolved.split("#")[0] in allowed:
                        continue
                    offenders.append((doc, target, resolved))
        self.assertEqual(offenders, [],
                         "public docs link to unpublished files: %s" % offenders)

    def test_the_public_root_readme_does_not_link_to_internal_documents(self):
        """The front door is the most likely place to leak a link to a design record."""
        public = {os.path.normpath(p) for p in self.public}
        text = open(os.path.join(ROOT, "README.md")).read()
        offenders = []
        for target in re.findall(r"\[[^\]]*\]\(([^)\s#]+)", text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            resolved = os.path.normpath(target)
            if resolved.startswith("docs/") and resolved not in public:
                offenders.append(target)
        self.assertEqual(offenders, [], "README links to unpublished docs: %s" % offenders)


if __name__ == "__main__":
    unittest.main()
