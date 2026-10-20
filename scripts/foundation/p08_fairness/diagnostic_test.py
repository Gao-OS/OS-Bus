"""No-traffic checks: diagnostic adapter preserves the original workload operations."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from actor import Worker
from diagnostic_actor import command


class DiagnosticTest(unittest.TestCase):
    def test_observed_reports_only_actual_frames(self):
        worker = SimpleNamespace(client=SimpleNamespace(sock=object()), messages={'a': {'serial': 1}}, calls={})
        with patch('diagnostic_actor.select.select', return_value=([], [], [])):
            result = command(worker, {'op': 'diagnostic_observed', 'calls': 0})
        self.assertEqual(result['complete_delivery_proof'], 'NOT_MEASURED')
        self.assertEqual(result['delivered'], [{'serial': 1}])

    def test_missing_actual_calls_fails(self):
        worker = SimpleNamespace(client=SimpleNamespace(sock=object()), messages={}, calls={})
        with patch('diagnostic_actor.select.select', return_value=([], [], [])):
            with self.assertRaisesRegex(AssertionError, 'held calls'):
                command(worker, {'op': 'diagnostic_observed', 'calls': 16})

    def test_original_start_remains_identical(self):
        worker = SimpleNamespace(pumping=False)
        self.assertEqual(command(worker, {'op': 'start'}), {'pumping': True})
        self.assertTrue(worker.pumping)


if __name__ == '__main__':
    unittest.main()
