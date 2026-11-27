"""The repository audit must read the fields GitHub actually returns."""

import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "audit", pathlib.Path(__file__).resolve().parent.parent.parent / "bin" / "github-audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)

REPO = {"security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"},
    "dependabot_security_updates": {"status": "enabled"}}}
ACTIONS = {"default_workflow_permissions": "read", "sha_pinning_required": True}
RULESETS = [{"id": 1, "name": "main protection", "rules": [{"type": "pull_request"}]}]


def status(**kwargs):
    """The audit results as a name -> ok mapping, with overrides applied."""
    repo = {**REPO, **kwargs.pop("repo", {})}
    results = AUDIT.audit(repo, kwargs.pop("actions", ACTIONS), kwargs.pop("rulesets", RULESETS),
                          kwargs.pop("pvr", {"enabled": True}))
    return {name: ok for name, ok, _ in results}


class Audit(unittest.TestCase):
    """Each check is one fact about the repository, read from the endpoint that carries it."""

    def test_a_hardened_repository_passes_every_check(self):
        """The baseline: everything on means nothing is reported missing."""
        self.assertTrue(all(status().values()), status())

    def test_push_protection_off_is_reported(self):
        """Finding a secret after the push is the failure push protection exists to prevent."""
        self.assertFalse(status(repo={"security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
            "dependabot_security_updates": {"status": "enabled"}}})["secret_scanning_push_protection"])

    def test_a_write_default_token_is_reported(self):
        """A workflow that can write by default is a compromised workflow that can write."""
        self.assertFalse(status(actions={"default_workflow_permissions": "write",
                                         "sha_pinning_required": True})["actions_default_read_token"])

    def test_mutable_actions_are_reported(self):
        """A tag that moves can change what CI runs without a commit."""
        self.assertFalse(status(actions={"default_workflow_permissions": "read",
                                         "sha_pinning_required": False})["actions_sha_pinning"])

    def test_private_reporting_is_read_from_its_own_endpoint(self):
        """The repository payload does not carry it; assuming so reported a working channel as missing."""
        self.assertFalse(status(pvr={"enabled": False})["private_vulnerability_reporting"])

    def test_a_ruleset_without_a_pull_request_rule_is_reported(self):
        """Linear history and checks do not stop a direct push; the pull_request rule does."""
        self.assertFalse(status(rulesets=[{"id": 1, "name": "x", "rules": [{"type": "deletion"}]}])
                         ["ruleset_pr_required"])

    def test_a_ruleset_whose_rules_only_the_detail_endpoint_carries_is_still_found(self):
        """The list endpoint omits `rules`, so the code reads the `_detail` copy - the shape the API gives.

        This is the second bug the commit message admits to: the summary alone reported "no pull request
        rule" for a repository that has one. The other fixtures pass rules inline, so without this one
        the per-ruleset detail fetch in main() could be deleted and every audit test would stay green.
        """
        self.assertTrue(status(rulesets=[{"id": 1, "name": "main protection",
                                          "_detail": {"rules": [{"type": "pull_request"}]}}])
                        ["ruleset_pr_required"])
        self.assertFalse(status(rulesets=[{"id": 1, "name": "main protection"}])
                         ["ruleset_pr_required"])

    def test_a_reply_that_is_not_an_object_from_the_reporting_endpoint_reads_as_off(self):
        """The endpoint answers 404 with an error body when reporting is off; `.get()` on that raised.

        The audit had to distinguish "off" from "unreadable", and the unreadable cases now exit 2 in
        main(); for this one endpoint off is what a 404 means, so it must not crash the report.
        """
        self.assertFalse(status(pvr="404: Not Found")["private_vulnerability_reporting"])
        reported = [detail for name, _, detail in AUDIT.audit(REPO, ACTIONS, [], "404: Not Found")
                    if name == "private_vulnerability_reporting"]
        self.assertEqual(reported, ["not enabled"])


if __name__ == "__main__":
    unittest.main()
