"""Offline regression controls for the exact SEC17 candidate pin substitutions."""
import ast
import hashlib
from pathlib import Path
import sys
import unittest

import normalize as N

ROOT = Path(__file__).resolve().parents[3]
DONOR = ROOT / ('test/reports/foundation/continuation-20261011-full-goal/environment/'
                'm1-sec17-pending-cleanup1/source1/fixture1/run.py')


class BindingControls(unittest.TestCase):
    def test_exact_forward_and_inverse(self):
        source = DONOR.read_bytes()
        patched = N.patch_runner(source)
        self.assertEqual(patched, source.replace(N.OLD_MANIFEST.encode(), N.CANDIDATE_SHA.encode())
                         .replace(N.OLD_SOURCE.encode(), N.SOURCE_SHA.encode()))
        self.assertEqual(patched.replace(N.CANDIDATE_SHA.encode(), N.OLD_MANIFEST.encode())
                         .replace(N.SOURCE_SHA.encode(), N.OLD_SOURCE.encode()), source)

    def test_only_two_candidate_assertion_constants_change(self):
        before = ast.parse(DONOR.read_bytes())
        after = ast.parse(N.patch_runner(DONOR.read_bytes()))
        constants = [node for node in ast.walk(after) if isinstance(node, ast.Constant)]
        changed = []
        for node in constants:
            if node.value in (N.CANDIDATE_SHA, N.SOURCE_SHA):
                changed.append(node.value)
                node.value = {N.CANDIDATE_SHA: N.OLD_MANIFEST, N.SOURCE_SHA: N.OLD_SOURCE}[node.value]
        self.assertEqual(sorted(changed), sorted([N.CANDIDATE_SHA, N.SOURCE_SHA]))
        self.assertEqual(ast.dump(before), ast.dump(after))

    def test_source_drift_and_repeated_patch_are_rejected(self):
        source = DONOR.read_bytes()
        for invalid in (source + b'\n', N.patch_runner(source),
                        source.replace(b'started + 60', b'started + 61')):
            with self.assertRaises(AssertionError):
                N.patch_runner(invalid)
        self.assertEqual(hashlib.sha256(source).hexdigest(), N.RUNNER_SHA)


if __name__ == '__main__':
    assert sys.dont_write_bytecode and sys.flags.optimize == 0
    unittest.main()
