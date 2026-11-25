"""The PoC index assembler, tested where a source could quietly lie.

The failure mode this guards against is not a missing source - a missing source shows up as a zero
count. It is a source being credited when it said nothing: a repository URL counted as a working
exploit, an Exploit-DB row whose `codes` column names a different CVE, or an NVD reference tagged
`Patch` being treated as exploit evidence. Each test below pins one of those.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
POC_INDEX = REPO / "bin" / "poc-index.py"

EXPLOITDB_ROWS = "\n".join([
    "id,file,description,date_published,author,type,platform,port,date_added,"
    "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url",
    '50383,exploits/multiple/webapps/50383.py,Apache HTTP Server 2.4.49 - Path Traversal (RCE),'
    '2021-10-05,0xGabe,webapps,multiple,,2021-10-05,2021-11-01,1,CVE-2021-41773;OSVDB-1,,,'
    'https://a,https://b,https://c',
    '99999,exploits/linux/local/99999.c,Something local,2021-10-06,someone,local,linux,,'
    '2021-10-06,2021-11-01,0,CVE-2021-99999,,,,,,',
])

METASPLOIT_ROWS = {
    "exploit_multi/http/apache_normalize_path_rce": {
        "references": ["CVE-2021-41773", "CVE-2021-42013", "URL-https://example.invalid"],
    },
    "auxiliary_scanner/http/apache_normalize_path": {
        "references": ["CVE-2021-41773"],
    },
    "exploit_linux/local/other": {"references": ["CVE-2021-99999"]},
}


def load_module():
    """Import bin/poc-index.py, whose name is not a valid module identifier."""
    spec = importlib.util.spec_from_file_location("poc_index", POC_INDEX)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PocIndexTest(unittest.TestCase):
    def setUp(self):
        """Load the module and the fixture tables it needs."""
        self.module = load_module()
        self.exploitdb = self.module.load_exploitdb(EXPLOITDB_ROWS.encode())
        self.metasploit = self.module.load_metasploit(json.dumps(METASPLOIT_ROWS).encode())

    def test_one_exploitdb_row_can_name_several_cves(self):
        """The `codes` column is semicolon-separated; splitting only on commas loses aliases."""
        self.assertIn("CVE-2021-41773", self.exploitdb)
        row = self.exploitdb["CVE-2021-41773"][0]
        self.assertEqual(row["id"], "50383")
        self.assertTrue(row["verified"])
        self.assertEqual(len(self.exploitdb.get("CVE-2021-42013", [])), 0)

    def test_an_unverified_exploitdb_row_is_still_evidence_but_says_so(self):
        """An unverified entry is a published exploit, not a checked one; the flag must survive."""
        row = self.exploitdb["CVE-2021-99999"][0]
        self.assertFalse(row["verified"])

    def test_metasploit_modules_map_to_every_cve_they_reference(self):
        """A module's reference list is the mapping; URL references must not be mistaken for CVEs."""
        self.assertIn(
            "exploit_multi/http/apache_normalize_path_rce",
            self.metasploit["CVE-2021-41773"],
        )
        self.assertIn(
            "exploit_multi/http/apache_normalize_path_rce",
            self.metasploit["CVE-2021-42013"],
        )
        self.assertTrue(all(name.startswith(("exploit_", "auxiliary_"))
                            for name in self.metasploit["CVE-2021-41773"]))

    def test_only_exploit_tagged_nvd_references_count(self):
        """A Patch or Vendor Advisory reference is not evidence of public exploit code."""
        record = {
            "references": [
                {"url": "https://packetstormsecurity.com/files/1/x", "tags": ["Exploit"]},
                {"url": "https://packetstormsecurity.com/files/1/x", "tags": ["Exploit"]},
                {"url": "https://vendor.example/advice", "tags": ["Patch"]},
            ]
        }
        found = self.module.from_nvd(record)
        self.assertEqual(found["urls"], ["https://packetstormsecurity.com/files/1/x"])

    def test_the_best_source_follows_the_declared_trust_order(self):
        """With NVD and Exploit-DB both present, NVD wins; with only Metasploit, that is the answer."""
        record = {"references": [{"url": "https://e", "tags": ["Exploit"]}]}
        both = self.module.evidence_for(
            "CVE-2021-41773", record,
            {"exploitdb": self.exploitdb, "metasploit": self.metasploit}, "/nonexistent", False,
        )["cves"]["CVE-2021-41773"]
        self.assertEqual(both["best"], "nvd")

        only_metasploit = self.module.evidence_for(
            "CVE-2021-42013", None,
            {"exploitdb": {}, "metasploit": self.metasploit}, "/nonexistent", False,
        )["cves"]["CVE-2021-42013"]
        self.assertEqual(only_metasploit["best"], "metasploit")

    def test_a_cve_with_no_evidence_reports_no_best_source(self):
        """An empty answer is a fact: the queue item then means "find reference code"."""
        entry = self.module.evidence_for(
            "CVE-2099-0001", None, {"exploitdb": {}, "metasploit": {}}, "/nonexistent", False,
        )["cves"]["CVE-2099-0001"]
        self.assertIsNone(entry["best"])
        self.assertEqual(entry["count"], 0)

    def test_a_source_can_be_dropped_without_touching_code(self):
        """Licensing is a downstream choice: excluding a source must remove it from the answer."""
        record = {"references": [{"url": "https://nvd-tagged", "tags": ["Exploit"]}]}
        tables = {"exploitdb": self.exploitdb, "metasploit": self.metasploit}
        without_exploitdb = self.module.evidence_for(
            "CVE-2021-41773", record, tables, "/nonexistent", False,
            allowed={"nvd", "metasploit"},
        )["cves"]["CVE-2021-41773"]
        self.assertNotIn("exploitdb", without_exploitdb["sources"])
        self.assertIn("metasploit", without_exploitdb["sources"])

        nvd_only = self.module.evidence_for(
            "CVE-2021-41773", record, tables, "/nonexistent", False, allowed={"nvd"},
        )["cves"]["CVE-2021-41773"]
        self.assertEqual(sorted(nvd_only["sources"]), ["nvd"])

    def test_an_offline_run_reads_the_cache_and_writes_the_map(self):
        """The CLI must work with no network, because a replay must not depend on a site being up."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "exploitdb.csv").write_text(EXPLOITDB_ROWS)
            out = tmp / "poc.json"
            cache = tmp / "cache"
            cache.mkdir()
            (cache / "files_exploits.csv").write_text(EXPLOITDB_ROWS)
            (cache / "modules_metadata_base.json").write_text(json.dumps(METASPLOIT_ROWS))
            result = subprocess.run(
                [sys.executable, str(POC_INDEX), "--cves", "CVE-2021-41773",
                 "--offline", "--cache", str(cache), "--out", str(out)],
                capture_output=True, text=True,
            )
            # --offline deliberately skips the CSV load, so an empty map is the correct answer here.
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("with reference code: 0 of 1", result.stdout)
            self.assertIn("CVE-2021-41773", json.loads(out.read_text())["cves"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
