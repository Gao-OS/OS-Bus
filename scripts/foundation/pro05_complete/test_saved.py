"""Saved-file binding controls using temporary synthetic trees only.

Only contract.validate_complete is mocked for file-binding tests. These controls
do not create runtime evidence or establish runtime authenticity/qualification.
"""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import contract
import validate_saved as saved


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    data = path.read_bytes()
    return dict(bytes=len(data), mode=stat.S_IMODE(path.stat().st_mode), sha256=sha(data))


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o644)


def write_json(path, value):
    write(path, (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode())


class SavedReportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / 'repository'
        self.candidate = self.root / 'candidate'
        self.fixture = self.repository / 'scripts/foundation/pro05_complete'
        self.report_path, self.vmoff_path = self.root / 'report.json', self.root / 'vmoff.json'
        sources, files = {}, {}
        for index in range(70):
            name = f'apps/gao_bus/lib/synthetic_{index}.ex'
            write(self.repository / name, f'synthetic source {index}\n'.encode())
            sources[name] = pin(self.repository / name)
        write(self.repository / 'devenv.lock', b'{"synthetic":true}\n')
        sources['devenv.lock'] = pin(self.repository / 'devenv.lock')
        for index in range(80):
            name = f'lib/gao_bus/ebin/synthetic_{index}.beam'
            write(self.candidate / name, f'synthetic runnable {index}\n'.encode())
            files[name] = pin(self.candidate / name)
        helpers = {}
        for name in sorted(saved.HELPERS):
            write(self.repository / name, ('synthetic helper ' + name).encode())
            helpers[name] = pin(self.repository / name)
        for name, data in (
                ('cleanup.py', b'# synthetic cleanup\n'),
                ('policy.exs', b'# synthetic policy\n[]\n'),
                ('reference.conf', b'<busconfig>synthetic</busconfig>\n'),
                ('validate_saved.py', b'# synthetic prepared fixture source\n'),
                ('test_saved.py', b'# synthetic prepared source control\n')):
            write(self.fixture / name, data)
        self.artifact = dict(not_a_release=True, sources=sources, files=files,
                             origin_pin=dict(sha256='a' * 64))
        self.bindings = dict(production_sources=71, artifact_files=80, profiles_prepared=['core'],
            network_profile_prepared=False, runtime_qualification=False, not_a_release=True,
            runtime_manifest_sha256='a' * 64, helpers=helpers,
            nixpkgs_lock_sha256=sources['devenv.lock']['sha256'],
            cleanup_sha256=pin(self.fixture / 'cleanup.py')['sha256'])
        self.report = dict(profile='core', selected=copy.deepcopy(contract.SELECTED),
            result=saved.RESULT, readiness='L0', runtime_qualification=False,
            requirement_qualification=False, accepted_index_mutation=False,
            product_qualified=False, backends=[])
        for backend, name in (('reference', 'reference.conf'), ('gao_bus', 'policy.exs')):
            data = (self.fixture / name).read_bytes()
            configuration = dict(path=f'{saved.ROOT}/{backend}/{name}', bytes=data.decode(),
                sha256=sha(data), system_mode=True, external_only=True, isolated=True,
                profile='core', backend=backend, endpoint=f'{saved.ROOT}/{backend}/bus')
            self.report['backends'].append(dict(backend=backend, configuration=configuration))
        self.refresh_artifact()
        write_json(self.vmoff_path, dict(VMoff=True, socket_removed=True))

    def refresh_artifact(self):
        write_json(self.candidate / 'artifact.json', self.artifact)
        self.bindings['artifact_sha256'] = pin(self.candidate / 'artifact.json')['sha256']
        write_json(self.fixture / 'bindings.json', self.bindings)
        self.report.update(artifact=copy.deepcopy(self.artifact), bindings=copy.deepcopy(self.bindings),
            candidate_artifact_sha256=self.bindings['artifact_sha256'],
            candidate_source_sha256=contract.source_sha(self.artifact))
        self.report['fixture_pins'] = {
            path.name: dict(pin(path), mode=pin(path)['mode'] & ~0o222)
            for path in self.fixture.iterdir() if path.is_file()}

    def arguments(self):
        write_json(self.report_path, self.report)
        return dict(report_path=self.report_path, report_sha256=sha(self.report_path.read_bytes()),
                    vmoff_path=self.vmoff_path, vmoff_sha256=sha(self.vmoff_path.read_bytes()),
                    repository=self.repository, candidate=self.candidate, fixture=self.fixture)

    def validate(self, contract_called=True, **overrides):
        arguments = dict(self.arguments(), **overrides)
        with patch.object(contract, 'validate_complete', return_value=None) as checked:
            try:
                return saved.validate_saved(**arguments)
            finally:
                if contract_called:
                    checked.assert_called_once_with(self.report)
                else:
                    checked.assert_not_called()

    def tree(self):
        return {path.relative_to(self.root).as_posix(): (path.read_bytes(), pin(path)['mode'])
                for path in self.root.rglob('*') if path.is_file()}

    def test_exact_saved_bindings_are_read_only_and_leave_all_qualification_pending(self):
        arguments = self.arguments()
        before = self.tree()
        with patch.object(contract, 'validate_complete', return_value=None) as checked:
            result = saved.validate_saved(**arguments)
        checked.assert_called_once_with(self.report)
        self.assertEqual(self.tree(), before)
        self.assertTrue(result['validated_saved_report'])
        self.assertEqual(result['acceptance'], 'pending_independent_runtime_review')
        self.assertEqual(result['readiness'], 'L0')
        for key in ('runtime_qualification', 'requirement_qualification',
                    'accepted_index_mutation', 'product_qualified'):
            self.assertIs(result[key], False)
        self.assertEqual(result['observed_counts'], dict(backends=2, production_sources=71,
            runnable_files=80, fixture_files=6, inherited_helpers=3))
        self.assertEqual(result['inputs']['report']['sha256'], arguments['report_sha256'])
        self.assertEqual(result['inputs']['vmoff']['sha256'], arguments['vmoff_sha256'])

    def test_report_and_vmoff_require_the_exact_supplied_hashes(self):
        for field in ('report_sha256', 'vmoff_sha256'):
            for replacement in (None, '', '0' * 64):
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                    self.validate(contract_called=False, **{field: replacement})

    def test_vmoff_requires_both_actual_true_values_and_the_exact_shape(self):
        for value in (dict(VMoff=False, socket_removed=True), dict(VMoff=True, socket_removed=False),
                      dict(VMoff=1, socket_removed=True), dict(VMoff=True),
                      dict(VMoff=True, socket_removed=True, claimed=True)):
            write_json(self.vmoff_path, value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(contract_called=False)

    def test_contract_rejection_is_propagated_without_writes(self):
        arguments = self.arguments()
        before = self.tree()
        with patch.object(contract, 'validate_complete', side_effect=ValueError('raw observations absent')) as checked:
            with self.assertRaisesRegex(ValueError, 'raw observations absent'):
                saved.validate_saved(**arguments)
        checked.assert_called_once_with(self.report)
        self.assertEqual(self.tree(), before)

    def test_optimized_python_is_rejected_before_contract_call_without_writes(self):
        arguments = self.arguments()
        before = self.tree()
        with patch.object(saved.sys, 'flags', SimpleNamespace(optimize=1)), \
                patch.object(contract, 'validate_complete', return_value=None) as checked:
            with self.assertRaisesRegex(ValueError, 'enabled assertions required'):
                saved.validate_saved(**arguments)
            checked.assert_not_called()
        self.assertEqual(self.tree(), before)

    def test_altered_source_and_local_original_modes_are_rejected(self):
        name = next(name for name in self.artifact['sources'] if name != 'devenv.lock')
        path = self.repository / name
        original = path.read_bytes()
        write(path, original + b'changed')
        with self.assertRaisesRegex(ValueError, 'file pin mismatch'):
            self.validate()
        write(path, original)
        path.chmod(0o444)
        with self.assertRaisesRegex(ValueError, 'file pin mismatch'):
            self.validate()

    def test_altered_artifact_manifest_and_runnable_contents_are_rejected(self):
        manifest = self.candidate / 'artifact.json'
        original = manifest.read_bytes()
        manifest.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.validate()
        manifest.write_bytes(original)
        name = next(iter(self.artifact['files']))
        write(self.candidate / name, b'changed runnable')
        with self.assertRaisesRegex(ValueError, 'file pin mismatch'):
            self.validate()

    def test_extra_runnable_and_missing_pinned_runnable_are_rejected(self):
        extra = self.candidate / 'lib/gao_bus/ebin/extra.beam'
        write(extra, b'extra')
        with self.assertRaisesRegex(ValueError, 'runnable file set mismatch'):
            self.validate()
        extra.unlink()
        (self.candidate / next(iter(self.artifact['files']))).unlink()
        with self.assertRaises(FileNotFoundError):
            self.validate()

    def test_fixture_file_set_bytes_and_guest_readonly_modes_are_exact(self):
        write(self.fixture / 'extra.py', b'extra')
        with self.assertRaisesRegex(ValueError, 'fixture file set/bytes/hash/mode mismatch'):
            self.validate()
        (self.fixture / 'extra.py').unlink()
        self.report['fixture_pins']['cleanup.py']['mode'] = 0o644
        with self.assertRaisesRegex(ValueError, 'fixture file set/bytes/hash/mode mismatch'):
            self.validate()
        self.report['fixture_pins']['cleanup.py']['mode'] = 0o444
        write(self.fixture / 'cleanup.py', b'changed cleanup')
        with self.assertRaisesRegex(ValueError, 'fixture file set/bytes/hash/mode mismatch'):
            self.validate()

    def test_inherited_helper_bytes_and_current_binding_identity_are_checked(self):
        write(self.repository / sorted(saved.HELPERS)[0], b'changed helper')
        with self.assertRaisesRegex(ValueError, 'file pin mismatch'):
            self.validate()
        self.report['bindings']['artifact_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'current fixture bindings mismatch'):
            self.validate()

    def test_self_consistent_wrong_source_or_artifact_counts_are_rejected(self):
        self.artifact['sources'].pop(next(iter(self.artifact['sources'])))
        self.refresh_artifact()
        with self.assertRaisesRegex(ValueError, 'incomplete source or runnable file pins'):
            self.validate()

    def test_changed_policy_text_hash_backend_or_guest_path_is_rejected(self):
        for index in range(2):
            original = copy.deepcopy(self.report['backends'][index]['configuration'])
            for field, value in (('bytes', 'changed policy'), ('sha256', '0' * 64),
                                 ('backend', 'other'), ('path', '/tmp/policy'),
                                 ('endpoint', '/tmp/bus'), ('isolated', 1)):
                self.report['backends'][index]['configuration'] = dict(original, **{field: value})
                with self.subTest(index=index, field=field), self.assertRaisesRegex(ValueError, 'prepared configuration mismatch'):
                    self.validate()
            self.report['backends'][index]['configuration'] = original

    def test_core_network_or_selected_backend_drift_is_rejected(self):
        self.report['profile'] = 'network'
        with self.assertRaisesRegex(ValueError, 'exact selected core profile'):
            self.validate()
        self.report['profile'] = 'core'
        self.report['selected'] = []
        with self.assertRaisesRegex(ValueError, 'exact selected core profile'):
            self.validate()
        self.report['selected'] = copy.deepcopy(contract.SELECTED)
        self.report['backends'].reverse()
        with self.assertRaisesRegex(ValueError, 'backend selection mismatch'):
            self.validate()

    def test_promoted_qualification_flags_are_rejected_even_with_valid_file_hashes(self):
        for field in ('runtime_qualification', 'requirement_qualification',
                      'accepted_index_mutation', 'product_qualified'):
            self.report[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'must remain false'):
                self.validate()
            self.report[field] = False

    def test_noncanonical_pinned_paths_and_symlinks_are_rejected(self):
        expected = next(iter(self.artifact['sources'].values()))
        for name in ('../escape', '/absolute', 'apps/../escape', './devenv.lock'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                saved.check_pin(self.repository, name, expected)
        name = next(iter(self.artifact['files']))
        path = self.candidate / name
        path.unlink()
        path.symlink_to(self.repository / 'devenv.lock')
        with self.assertRaisesRegex(ValueError, 'symlink in pinned path'):
            self.validate()

    def test_cli_emits_only_the_pending_validation_json_and_writes_no_receipts(self):
        arguments = self.arguments()
        before = self.tree()
        argv = []
        for key, value in arguments.items():
            option = key.removesuffix('_path').replace('_', '-')
            argv.extend(['--' + option, str(value)])
        output = io.StringIO()
        with patch.object(contract, 'validate_complete', return_value=None) as checked, redirect_stdout(output):
            saved.main(argv)
        checked.assert_called_once_with(self.report)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())['acceptance'], 'pending_independent_runtime_review')
        self.assertEqual(self.tree(), before)


if __name__ == '__main__':
    unittest.main()
