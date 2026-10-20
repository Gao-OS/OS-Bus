"""Offline binding controls; no guest runner, VM, actor or socket execution."""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class AdapterControls(unittest.TestCase):
    def adapter(self):
        path = Path(__file__).with_name('normalize.py')
        self.assertTrue(path.is_file(), 'current-candidate metadata adapter missing')
        spec = importlib.util.spec_from_file_location('current_adapter', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def inputs(self):
        root = Path(__file__).absolute().parents[3]
        return root / 'test/reports/foundation/resume-20261019/sec13-sec14-xml-preparation1/inputs/sec13'

    def test_contract_and_nix_have_only_two_reversible_digest_replacements_each(self):
        adapter = self.adapter()
        for name in ('contract.py', 'test.nix'):
            with self.subTest(name=name):
                original = (self.inputs() / 'fixtures' / name).read_bytes()
                corrected = adapter.patch_bindings(name, original)
                expected = original.replace(adapter.OLD_MANIFEST.encode(), adapter.CANDIDATE_SHA.encode())
                expected = expected.replace(adapter.OLD_SOURCE.encode(), adapter.SOURCE_SHA.encode())
                self.assertEqual(corrected, expected)
                self.assertEqual(corrected.replace(adapter.CANDIDATE_SHA.encode(), adapter.OLD_MANIFEST.encode()).replace(
                    adapter.SOURCE_SHA.encode(), adapter.OLD_SOURCE.encode()), original)
                if name == 'contract.py':
                    before, after = ast.parse(original), ast.parse(corrected)
                    for statement in before.body:
                        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Constant):
                            if statement.value.value == adapter.OLD_MANIFEST:
                                statement.value.value = adapter.CANDIDATE_SHA
                            elif statement.value.value == adapter.OLD_SOURCE:
                                statement.value.value = adapter.SOURCE_SHA
                    self.assertEqual(ast.dump(before), ast.dump(after))

    def test_drift_and_already_patched_sources_are_rejected(self):
        adapter = self.adapter()
        for name in ('contract.py', 'test.nix'):
            source = (self.inputs() / 'fixtures' / name).read_bytes()
            for invalid in (source + b'\n', source.replace(adapter.OLD_SOURCE.encode(), b'changed'),
                            adapter.patch_bindings(name, source)):
                with self.subTest(name=name):
                    with self.assertRaises(AssertionError):
                        adapter.patch_bindings(name, invalid)

    def test_complete_offline_normalization_preserves_runner_actors_and_oracles(self):
        adapter = self.adapter()
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / 'normalized'
            try:
                adapter.normalize(Path('/nix/store/9v44l2apb02b7c478dfia5ml7ak8crvn-osbus-authorization-current-inputs/candidate'),
                    Path('/nix/store/1x1d03jmlk0crx84v21iy3xwd4b8hgda-osbus-authorization-artifact'),
                    Path('/nix/store/3i9qh231qir81ib0l92dhi3y0943bp9a-osbus-authorization-runtime.json'),
                    self.inputs() / 'fixtures', self.inputs() / 'corpus.json', output)
                bindings = json.loads((output / 'bindings.json').read_text())
                self.assertEqual(bindings['fixture_files_unchanged'], adapter.FIXTURE_COUNT - 2)
                self.assertEqual(bindings['runnable_files_unchanged'], 80)
                self.assertEqual(set(bindings['patch_provenance']), {'contract.py', 'test.nix'})
                self.assertFalse(bindings['product_qualified'])
                for path in (self.inputs() / 'fixtures').rglob('*'):
                    if path.is_file() and path.name not in ('contract.py', 'test.nix'):
                        self.assertEqual(path.read_bytes(), (output / 'fixtures' / path.relative_to(self.inputs() / 'fixtures')).read_bytes())
            finally:
                if output.exists():
                    for path in output.rglob('*'):
                        if path.is_dir():
                            path.chmod(path.stat().st_mode | 0o700)

    def test_wrong_candidate_is_rejected_before_output_creation(self):
        adapter = self.adapter()
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            candidate = folder / 'candidate'
            candidate.mkdir()
            (candidate / 'candidate.json').write_text('{}')
            with self.assertRaises(AssertionError):
                adapter.normalize(candidate,
                    Path('/nix/store/1x1d03jmlk0crx84v21iy3xwd4b8hgda-osbus-authorization-artifact'),
                    Path('/nix/store/3i9qh231qir81ib0l92dhi3y0943bp9a-osbus-authorization-runtime.json'),
                    self.inputs() / 'fixtures', self.inputs() / 'corpus.json', folder / 'output')
            self.assertFalse((folder / 'output').exists())


if __name__ == '__main__':
    unittest.main()
