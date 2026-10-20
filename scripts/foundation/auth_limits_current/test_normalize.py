"""Offline controls for the exact SEC07 metadata-only binding correction."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest

import normalize as N

ROOT = Path(__file__).resolve().parents[3]
DONOR = ROOT / ('test/reports/foundation/continuation-20261011-full-goal/environment/'
                'm1-sec07-complete1/source5/fixture1/contract.py')


class BindingControls(unittest.TestCase):
    def test_exact_forward_and_inverse(self):
        source = DONOR.read_bytes()
        patched = N.patch_contract(source)
        expected = source.replace(N.OLD_MANIFEST.encode(), f"MANIFEST_SHA='{N.CANDIDATE_SHA}'".encode())
        expected = expected.replace(N.OLD_SOURCE.encode(), f"SOURCE_SHA='{N.SOURCE_SHA}'".encode())
        self.assertEqual(patched, expected)
        self.assertEqual(patched.replace(N.CANDIDATE_SHA.encode(), N.OLD_MANIFEST.split("'")[1].encode())
                         .replace(N.SOURCE_SHA.encode(), N.OLD_SOURCE.split("'")[1].encode()), source)

    def test_all_other_ast_nodes_and_assertions_unchanged(self):
        source = ast.parse(DONOR.read_bytes())
        patched = ast.parse(N.patch_contract(DONOR.read_bytes()))
        changes = []
        for before, after in zip(source.body, patched.body):
            if ast.dump(before) != ast.dump(after):
                self.assertIsInstance(before, ast.Assign)
                self.assertIsInstance(after, ast.Assign)
                self.assertEqual(ast.dump(before.targets[0]), ast.dump(after.targets[0]))
                changes.append(before.targets[0].id)
        self.assertEqual(len(source.body), len(patched.body))
        self.assertEqual(changes, ['MANIFEST_SHA', 'SOURCE_SHA'])
        self.assertEqual([ast.dump(node) for node in ast.walk(source) if isinstance(node, ast.Assert)],
                         [ast.dump(node) for node in ast.walk(patched) if isinstance(node, ast.Assert)])

    def test_drift_and_repeat_are_rejected(self):
        source = DONOR.read_bytes()
        for invalid in (source + b'\n', N.patch_contract(source),
                        source.replace(b'healthy_probe_ms=1000', b'healthy_probe_ms=1001')):
            with self.assertRaises(AssertionError):
                N.patch_contract(invalid)
        self.assertEqual(hashlib.sha256(source).hexdigest(), N.CONTRACT_SHA)


if __name__ == '__main__':
    assert sys.dont_write_bytecode and sys.flags.optimize == 0
    unittest.main()
