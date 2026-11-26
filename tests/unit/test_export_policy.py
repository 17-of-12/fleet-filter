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


def exporter_present():
    """Whether the exporter exists in this tree.

    It is deliberately not published, so this test cannot run in the public tree - but a test that
    errors there makes the public CI red for a reason that is not a defect. Skip, and say why.
    """
    return os.path.isfile(os.path.join(ROOT, "bin", "export-public.py"))


def load_exporter():
    """Import bin/export-public.py, whose name is not a valid module identifier."""
    path = os.path.join(ROOT, "bin", "export-public.py")
    spec = importlib.util.spec_from_file_location("ff_export_public", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(exporter_present(), "the exporter is not published; this test covers it only")
class InternalBookkeepingTest(unittest.TestCase):
    """Build bookkeeping in a published document is a leak of the process, not of a secret.

    Bundle numbers, work-item ids and paths under `data/` are how this project tracks its own build.
    A reader of a public document cannot follow any of them: the bundle list is internal, and the
    cited measurement is not in the public tree. Both rot silently, so both are checked.
    """

    @classmethod
    def setUpClass(cls):
        """Load the exporter for the public list."""
        cls.mod = load_exporter()

    def published_files(self):
        """Every published document, including the three outside docs/."""
        return [p for p in self.mod.PUBLIC_DOCS if p.endswith(".md")]

    def test_published_documents_do_not_discuss_unpublished_material(self):
        """Telling a reader about documents they cannot open reads as a gap in the project.

        A public page that says "design records are not published" addresses an internal decision to
        an external audience: the reader never knew those documents existed and cannot act on the
        note. Either describe the thing, or leave it out.
        """
        banned = (r"\bnot published\b", r"\bunpublished\b", r"\binternal (?:document|doc)s?\b",
                  r"\bdesign records?\b", r"\bhandoffs?\b",
                  # Notes addressed to the maintainer: a decision we have not taken, or a host only
                  # our deployment has.
                  r"\bowner (?:decision|directive)\b", r"\blab-web01\b", r"\butility\.is\b", r"\blab-web01\b",
                  r"\bff-(?:apache|control|wp|fpm)\b")
        offenders = []
        for doc in self.published_files():
            for lineno, line in enumerate(open(os.path.join(ROOT, doc)).read().splitlines(), 1):
                for pattern in banned:
                    if re.search(pattern, line, re.IGNORECASE):
                        offenders.append((doc, lineno, re.search(pattern, line, re.I).group(0)))
        self.assertEqual(offenders, [], "published docs discuss unpublished material: %s" % offenders)

    def test_no_bundle_ids_in_published_documents(self):
        """A bundle id is a pointer to a plan only the maintainers can see."""
        offenders = []
        for doc in self.published_files():
            for lineno, line in enumerate(open(os.path.join(ROOT, doc)).read().splitlines(), 1):
                if re.search(r"Bundle\s+[A-Z][0-9]?\b", line):
                    offenders.append((doc, lineno, line.strip()[:60]))
        self.assertEqual(offenders, [], "build bookkeeping published: %s" % offenders)

    def test_no_published_document_cites_an_unpublished_path(self):
        """`data/...` is pruned from the export, so a citation of it is a dead end for the reader."""
        offenders = []
        for doc in self.published_files():
            for lineno, line in enumerate(open(os.path.join(ROOT, doc)).read().splitlines(), 1):
                # `var/` and `data/` are pruned from the export; docs/design and docs/handoffs are
                # unpublished by the allowlist. `lab/exploits` is published, so it is not listed -
                # the prefix must include the slash so a word like `variants` does not match `var`.
                for path in re.findall(r"`((?:data/|var/|docs/design/|docs/handoffs/)[^`]*)`", line):
                    offenders.append((doc, lineno, path))
        self.assertEqual(offenders, [], "published documents cite unpublished paths: %s" % offenders)


@unittest.skipUnless(exporter_present(), "the exporter is not published; this test covers it only")
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
