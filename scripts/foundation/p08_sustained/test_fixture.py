"""No-traffic tests for qualification's leak/authority acceptance oracle."""
import copy
import unittest
import actor

from qualify import verify_settled


class SettledOracleTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {'authorities': {'router': 'original'}, 'names': ['observer'],
                         'matches': 0, 'pending': 0, 'usage': {'reservations': 0},
                         'capabilities': 0, 'processes': 48, 'ports': 5,
                         'external': {'fds': 32}, 'atoms': 100}

    def test_exact_quiescent_sample_passes(self):
        verify_settled(copy.deepcopy(self.baseline), self.baseline)

    def test_leaks_and_authority_changes_fail(self):
        changes = {'authorities': {'router': 'restarted'}, 'names': ['observer', 'leak'],
                   'matches': 1, 'pending': 1, 'usage': {'reservations': 1},
                   'external': {'fds': 33}, 'atoms': 117,
                   'capabilities': 1, 'processes': 49, 'ports': 6}
        for key, value in changes.items():
            with self.subTest(metric=key):
                sample = copy.deepcopy(self.baseline)
                sample[key] = value
                with self.assertRaises(AssertionError):
                    verify_settled(sample, self.baseline)

    def test_declared_atom_warmup_allowance_passes(self):
        sample = copy.deepcopy(self.baseline)
        sample['atoms'] += 16
        verify_settled(sample, self.baseline)


class RequestNameWireTests(unittest.TestCase):
    def test_independent_aligned_churn_vector(self):
        expected = b'\x1c\0\0\0org.foundation.Service.Churn\0\0\0\0\x04\0\0\0'
        self.assertEqual(actor.request_name_body('org.foundation.Service.Churn', 4), expected)

    def test_already_aligned_observer_vector(self):
        expected = b'\x17\0\0\0org.foundation.Observer\0\0\0\0\0'
        self.assertEqual(actor.request_name_body('org.foundation.Observer', 0), expected)


if __name__ == '__main__':
    unittest.main()
