"""Checks for compliance/control-map.csv.

Run from the repository root:  python compliance/test_control_map.py

The tests are deliberately about the seam between the map and the scripts. A malformed row is easy to
spot by eye. The failure that matters is a technique the scripts start emitting and the map never
learns about, which is what test_every_script_technique_is_mapped catches.
"""

import csv
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MAP = os.path.join(HERE, "control-map.csv")
TOOL_ROOT = os.path.dirname(HERE)
SCRIPTS = [
    os.path.join(TOOL_ROOT, "windows", "Invoke-LogGapAnalysis.ps1"),
    os.path.join(TOOL_ROOT, "linux", "linux-log-gap-analysis.sh"),
]

FRAMEWORKS = {"soc2", "iso27001"}
KEY_RE = re.compile(r"^(T\d{4}(\.\d{3})?|category:[a-z][a-z ]*)$")
CONTROL_RE = re.compile(r"^(CC\d\.\d|A\.\d+\.\d+)$")


def load_rows():
    with open(MAP, encoding="utf-8-sig", newline="") as fh:
        rows = [r for r in csv.reader(fh) if r and not r[0].startswith("#")]
    header, body = rows[0], rows[1:]
    return header, [r for r in body if r[0] != "key"]


def script_text():
    text = ""
    for path in SCRIPTS:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text += fh.read()
    return text


class ControlMapTest(unittest.TestCase):
    def setUp(self):
        self.header, self.rows = load_rows()

    def test_header(self):
        self.assertEqual(self.header, ["key", "framework", "control"])

    def test_rows_are_well_formed(self):
        for row in self.rows:
            self.assertEqual(len(row), 3, "row does not have 3 fields: %r" % (row,))
            key, framework, control = (c.strip() for c in row)
            self.assertRegex(key, KEY_RE, "bad key: %r" % (row,))
            self.assertIn(framework, FRAMEWORKS, "unknown framework: %r" % (row,))
            self.assertRegex(control, CONTROL_RE, "bad control: %r" % (row,))

    def test_no_duplicate_pairs(self):
        seen = set()
        for row in self.rows:
            pair = (row[0].strip(), row[1].strip(), row[2].strip())
            self.assertNotIn(pair, seen, "duplicate row: %r" % (pair,))
            seen.add(pair)

    def test_both_frameworks_cover_every_key(self):
        by_key = {}
        for key, framework, _ in self.rows:
            by_key.setdefault(key.strip(), set()).add(framework.strip())
        for key, frameworks in by_key.items():
            self.assertEqual(frameworks, FRAMEWORKS, "key %s is not mapped in both frameworks" % key)

    def test_every_script_technique_is_mapped(self):
        text = script_text()
        used = set(re.findall(r"'(T\d{4}(?:\.\d{3})?)'", text))
        mapped = {row[0].strip() for row in self.rows}
        missing = sorted(t for t in used if t not in mapped)
        self.assertEqual(missing, [], "techniques emitted by the scripts but missing from the map: %s" % missing)

    def test_parent_techniques_exist_for_subtechniques(self):
        mapped = {row[0].strip() for row in self.rows}
        for key in list(mapped):
            if "." in key and key.startswith("T"):
                parent = key.split(".")[0]
                self.assertIn(parent, mapped, "subtechnique %s has no parent row %s" % (key, parent))

    def test_every_finding_category_has_a_default(self):
        text = script_text()
        ps = set(re.findall(r"Add-Finding\s+'?(?:\$?\w+'?|\"[^\"]*\")\s+'([A-Za-z][A-Za-z ]*)'", text))
        sh = set(re.findall(r"add_finding\s+(?:\"?\$\w+\"?|\"\$sev\")\s+([A-Z][A-Za-z]+)", text))
        categories = {c.strip().lower() for c in ps | sh if c.strip()}
        self.assertTrue(categories, "no finding categories found, the extraction is broken")
        mapped = {row[0].strip() for row in self.rows}
        missing = sorted(c for c in categories if "category:" + c not in mapped)
        self.assertEqual(missing, [], "categories without a default mapping: %s" % missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
