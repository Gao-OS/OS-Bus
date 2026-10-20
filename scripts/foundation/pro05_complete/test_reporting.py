"""Offline provenance and finalization controls; no guest/target execution."""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run as adapter


def completed():
    return dict(status='observed_pending_teardown', shutdown_errors=[],
                endpoint_removed=True, shutdown_ms=10)


class ReportingTest(unittest.TestCase):
    def test_support_imports_restore_adapter_search_path(self):
        before = list(adapter.sys.path)
        try:
            adapter.load_support(Path(__file__).resolve().parents[3])
            self.assertEqual(adapter.sys.path, before)
        finally:
            adapter.sys.path[:] = before

    def test_optimized_entrypoint_rejects_before_guest_or_input_operations(self):
        with patch.object(adapter.sys, 'flags', SimpleNamespace(optimize=1)), \
                patch.object(adapter, 'check_guest') as guest, \
                patch.object(adapter, 'check_inputs') as inputs:
            with self.assertRaisesRegex(RuntimeError, 'enabled assertions'):
                adapter.main(None, None, None, None, None)
        guest.assert_not_called()
        inputs.assert_not_called()

    def test_configuration_retains_exact_bytes_hash_profile_and_endpoint(self):
        raw = b'<busconfig>\n  <type>system</type>\n</busconfig>\n'
        path = adapter.ROOT / 'reference/reference.conf'
        result = adapter.configuration_record('reference', path, raw)
        self.assertEqual(result['bytes'], raw.decode())
        self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['path'], str(path))
        self.assertEqual(result['endpoint'], str(adapter.ROOT / 'reference/bus'))
        self.assertEqual(result['backend'], 'reference')
        self.assertEqual(result['profile'], 'core')
        for field in ('system_mode', 'external_only', 'isolated'):
            self.assertIs(result[field], True)

    def test_configuration_rejects_wrong_backend_path_or_non_utf8(self):
        for backend, path, raw in (
                ('network', adapter.ROOT / 'reference/reference.conf', b'config\n'),
                ('gao_bus', adapter.ROOT / 'reference/reference.conf', b'config\n'),
                ('reference', Path('/unused/reference.conf'), b'config\n'),
                ('gao_bus', adapter.ROOT / 'gao_bus/policy.exs', b'')):
            with self.subTest(backend=backend, path=path, raw=raw):
                with self.assertRaises(AssertionError):
                    adapter.configuration_record(backend, path, raw)
        with self.assertRaises(UnicodeDecodeError):
            adapter.configuration_record('gao_bus', adapter.ROOT / 'gao_bus/policy.exs', b'\xff')

    def test_measurement_follows_teardown_before_pass_and_preserves_observations(self):
        record = completed()
        record['observation'] = dict(raw='unchanged')
        before = copy.deepcopy(record['observation'])
        expected = dict(source_groups=37, targets=41)

        def measure(value):
            self.assertIs(value, record)
            self.assertEqual(value['status'], 'observed_pending_teardown')
            self.assertTrue(value['endpoint_removed'])
            self.assertNotIn('invariant_measurement', value)
            return copy.deepcopy(expected)

        def validate(value):
            self.assertEqual(value['status'], 'passed_pending_independent_review')
            self.assertEqual(value['invariant_measurement'], expected)

        with patch('contract.measure_backend', side_effect=measure) as measured, \
                patch('contract.expected_invariant', return_value=expected), \
                patch('contract.validate_backend', side_effect=validate) as checked:
            adapter.finalize_backend(record)
        measured.assert_called_once_with(record)
        checked.assert_called_once_with(record)
        self.assertEqual(record['observation'], before)

    def test_failed_teardown_cannot_build_a_passing_measurement(self):
        for changes in (dict(shutdown_errors=['cleanup failed']), dict(endpoint_removed=False),
                        dict(shutdown_ms=5001), dict(shutdown_ms=float('nan')),
                        dict(status='running')):
            with self.subTest(changes=changes):
                record = dict(completed(), **changes)
                with patch('contract.measure_backend') as measured, \
                        patch('contract.validate_backend') as checked:
                    with self.assertRaises(AssertionError):
                        adapter.finalize_backend(record)
                self.assertEqual(record['status'], 'failed')
                self.assertIn('failure', record)
                self.assertNotIn('invariant_measurement', record)
                measured.assert_not_called()
                checked.assert_not_called()

    def test_incomplete_observations_propagate_failure(self):
        record = completed()
        with patch('contract.measure_backend', side_effect=AssertionError('missing raw receipt')), \
                patch('contract.validate_backend') as checked:
            with self.assertRaisesRegex(AssertionError, 'missing raw receipt'):
                adapter.finalize_backend(record)
        checked.assert_not_called()
        self.assertEqual(record['status'], 'failed')
        self.assertNotIn('invariant_measurement', record)

    def test_measurement_mismatch_is_failed_and_never_validated(self):
        record = completed()
        with patch('contract.measure_backend', return_value=dict(targets=40)), \
                patch('contract.expected_invariant', return_value=dict(targets=41)), \
                patch('contract.validate_backend') as checked:
            with self.assertRaises(AssertionError):
                adapter.finalize_backend(record)
        checked.assert_not_called()
        self.assertEqual(record['status'], 'failed')

    def test_final_contract_failure_removes_the_tentative_pass(self):
        record = completed()
        with patch('contract.measure_backend', return_value=dict(targets=41)), \
                patch('contract.expected_invariant', return_value=dict(targets=41)), \
                patch('contract.validate_backend', side_effect=AssertionError('drift')):
            with self.assertRaisesRegex(AssertionError, 'drift'):
                adapter.finalize_backend(record)
        self.assertEqual(record['status'], 'failed')
        self.assertIn('drift', record['failure'])


if __name__ == '__main__':
    unittest.main()
