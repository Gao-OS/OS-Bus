"""Mandatory policy backend and private-reference containment regressions."""
import copy
import importlib
from pathlib import Path
import unittest

import packaged_policy_probe
import packaged_capture


def receipts():
    return {backend: dict(backend=backend, status='passed',
                         rows=[dict(id=row, status='passed') for row in packaged_policy_probe.ROWS],
                         counts=dict(selected=14, executed=14, passed=14, failed=0, blocked=0, skipped=0),
                         shutdown=[dict(method='eof', returncode=0), dict(method='eof', returncode=0)])
            for backend in ('reference', 'start', 'start_iex')}


class PolicyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module('packaged_qualify')

    def function(self, name):
        function = getattr(self.module, name, None)
        self.assertTrue(callable(function), 'missing required policy integration: ' + name)
        return function

    def test_all_three_backends_and_every_negative_row_are_required(self):
        validate = self.function('verify_policy_probes')
        validate(receipts())
        for backend in ('reference', 'start', 'start_iex'):
            with self.subTest(backend=backend):
                data = receipts()
                del data[backend]
                with self.assertRaises(AssertionError):
                    validate(data)
        for row in packaged_policy_probe.ROWS:
            for status in ('failed', 'blocked', 'skipped'):
                with self.subTest(row=row, status=status):
                    data = receipts()
                    data['reference']['rows'][packaged_policy_probe.ROWS.index(row)]['status'] = status
                    with self.assertRaises(AssertionError):
                        validate(data)

    def test_fabricated_counts_backend_or_abnormal_shutdown_cannot_pass(self):
        validate = self.function('verify_policy_probes')
        for change in (lambda d: d['start']['counts'].update(executed=13),
                       lambda d: d['start']['counts'].update(passed=True),
                       lambda d: d['start'].update(backend='reference'),
                       lambda d: d['start']['shutdown'][0].update(method='kill'),
                       lambda d: d['start']['shutdown'][0].update(returncode=1),
                       lambda d: d['start'].update(shutdown=[]),
                       lambda d: d['start'].update(status='failed'),
                       lambda d: d['start']['rows'].pop()):
            data = receipts()
            change(data)
            with self.assertRaises(AssertionError):
                validate(data)

    def test_private_reference_changes_only_the_listener(self):
        transform = self.function('reference_policy_xml')
        original = Path(__file__).with_name('packaged_wire_policy.xml').read_bytes()
        expected = original.replace(b'unix:path=/run/osbus-p08/socket/bus',
                                    b'unix:path=/run/osbus-p08/reference/bus')
        self.assertEqual(transform(original), expected)
        for invalid in (original.replace(b'/socket/bus', b'/another/bus'),
                        original + b'<listen>unix:path=/run/osbus-p08/socket/bus</listen>',
                        original.replace(b'/run/osbus-p08/socket/bus', b'/run/dbus/system_bus_socket')):
            with self.assertRaises(AssertionError):
                transform(invalid)

    def test_reference_cleanup_requires_the_exact_owned_group_and_endpoint(self):
        validate = self.function('verify_reference_cleanup')
        valid = dict(main_gone=True, socket_removed=True, cgroup_pids=[],
                     properties=dict(MainPID='0', ControlGroup='/system.slice/osbus-p08-policy-reference.service'))
        validate(valid)
        for change in (lambda d: d.update(main_gone=False),
                       lambda d: d.update(socket_removed=False),
                       lambda d: d.update(cgroup_pids=['1']),
                       lambda d: d['properties'].update(MainPID='1'),
                       lambda d: d['properties'].update(ControlGroup='/system.slice/dbus.service')):
            data = copy.deepcopy(valid)
            change(data)
            with self.assertRaises(AssertionError):
                validate(data)

    def test_runtime_requires_the_exact_adopted_policy_contract(self):
        validate = self.function('verify_policy_contract')
        contract = packaged_capture.policy_contract()
        validate(contract)
        for change in (lambda d: d.update(fixture='packaged_policy.xml'),
                       lambda d: d.update(universal_native_equivalence='passed'),
                       lambda d: d['design'].update(sha256='0' * 64),
                       lambda d: d.update(backends=['start_iex']),
                       lambda d: d.update(rows_per_backend=13),
                       lambda d: d.pop('valid_wire_delta')):
            data = copy.deepcopy(contract)
            change(data)
            with self.assertRaises(AssertionError):
                validate(data)
        with self.assertRaises(AssertionError):
            validate(None)


if __name__ == '__main__':
    unittest.main()
