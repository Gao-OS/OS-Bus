"""Pure wire/oracle tests; no bus traffic or guest service startup."""
import copy
import importlib
import socket
import time
import unittest
from unittest.mock import patch

from transport import Client


def modules():
    return importlib.import_module('packaged_policy_actor'), importlib.import_module('packaged_policy_probe')


class PolicyProbeTests(unittest.TestCase):
    def test_reply_before_sender_barrier_still_completes_two_observation_barriers(self):
        actor, probe = modules()
        for kind in [2, 3]:
            with self.subTest(kind=kind):
                left, right = socket.socketpair()
                worker = actor.PolicyClient.__new__(actor.PolicyClient)
                worker.sock, worker.serial = left, 100
                worker.reply_kind, worker.responses, worker.queued_messages = None, [], []
                fields = [(5, 'u', 101), (6, 's', ':1.2'), (7, 's', ':1.1'), (8, 'g', '')]
                if kind == 3:
                    fields.append((4, 's', 'org.foundation.Expected'))
                def barrier(serial):
                    return actor.frame(2, 500+serial, [(5, 'u', serial), (7, 's', 'org.freedesktop.DBus')])
                try:
                    # The reply is on the same stream before the sender's fence.
                    right.sendall(actor.frame(kind, 130, fields)+barrier(102))
                    sent = worker.command(dict(op='send', kind=1, destination=':1.1', interface=actor.ALLOWED))
                    self.assertEqual(sent['serial'], 101)
                    self.assertEqual([item['serial'] for item in sent['messages']], [130])
                    right.sendall(barrier(103)+barrier(104))
                    right.shutdown(socket.SHUT_WR)
                    observation = probe.observe_reply(lambda target, **command: worker.command(command),
                        worker, sent['messages'], dict(serial=130, kind=kind, reply_serial=101),
                        ':1.1', ':1.2', True)
                    received = observation['received']
                    self.assertEqual(received['barriers'], 2)
                    self.assertEqual(worker.serial, 104)
                    self.assertEqual(received['messages'], [])
                    self.assertIs(observation['prior_received'], sent['messages'])
                finally:
                    left.close()
                    right.close()

    def test_reply_receipts_preserve_missing_duplicate_and_denied_failures(self):
        _, probe = modules()
        reply = dict(serial=130, kind=3, reply_serial=101)
        message = dict(type=3, serial=130, fields={'7': ':1.1', '6': ':1.2',
            '5': 101, '4': 'org.foundation.Expected', '8': ''}, body_hex='')
        for prior, later, expected, passes in [
            ([message], [], True, True), ([], [message], True, True),
            ([], [], True, False), ([message], [message], True, False),
            ([message, message], [], True, False), ([], [message, message], True, False),
            ([], [], False, True), ([message], [], False, False), ([], [message], False, False),
        ]:
            with self.subTest(prior=len(prior), later=len(later), expected=expected):
                def request(target, **command):
                    self.assertEqual(command['negative'], not expected)
                    if expected:
                        self.assertEqual(command['expect_serial'], 130)
                        self.assertEqual(command.get('prior_serial'), 130 if prior else None)
                    else:
                        self.assertNotIn('expect_serial', command)
                        self.assertNotIn('prior_serial', command)
                    return dict(messages=later, barriers=2)
                if passes:
                    observed = probe.observe_reply(request, None, prior, reply, ':1.1', ':1.2', expected)
                    self.assertEqual(observed['received']['messages'], later)
                    self.assertEqual(observed['prior_received'], prior)
                else:
                    with self.assertRaisesRegex(AssertionError, 'policy delivery count'):
                        probe.observe_reply(request, None, prior, reply, ':1.1', ':1.2', expected)

    def test_earlier_reply_must_have_exact_envelope_and_cannot_hide_timeout(self):
        _, probe = modules()
        reply = dict(serial=130, kind=3, reply_serial=101)
        message = dict(type=3, serial=130, fields={'7': ':1.1', '6': ':1.2',
            '5': 101, '4': 'org.foundation.Expected', '8': ''}, body_hex='')
        for field, value in [('7', ':1.9'), ('6', ':1.9'), ('5', 100),
                             ('4', 'org.foundation.Wrong'), ('8', 'u')]:
            wrong = copy.deepcopy(message)
            wrong['fields'][field] = value
            for expected in [True, False]:
                with self.subTest(field=field, expected=expected), self.assertRaises(AssertionError):
                    probe.observe_reply(lambda target, **command: dict(messages=[], barriers=2),
                                        None, [wrong], reply, ':1.1', ':1.2', expected)
        timeout = dict(type=3, serial=99, fields={'7': 'org.freedesktop.DBus', '5': 101,
            '4': 'org.freedesktop.DBus.Error.NoReply'}, body_hex='')
        with self.assertRaisesRegex(AssertionError, 'timed out'):
            probe.observe_reply(lambda target, **command: dict(messages=[], barriers=2),
                                None, [timeout], reply, ':1.1', ':1.2', False)

    def test_prior_receipt_does_not_substitute_for_both_new_barriers(self):
        actor, probe = modules()
        worker = actor.PolicyClient.__new__(actor.PolicyClient)
        for prior in [True, 129]:
            with self.assertRaisesRegex(AssertionError, 'unbound prior observation'):
                worker.command(dict(op='observe', expect_serial=130, prior_serial=prior))
        for barriers in [0, 1]:
            with self.assertRaisesRegex(AssertionError, 'both reply observation barriers'):
                probe.observe_reply(lambda target, **command: dict(messages=[], barriers=barriers),
                                    None, [], dict(serial=130, kind=3, reply_serial=101), ':1.1', ':1.2', False)

    def test_armed_actor_answers_bound_call_without_another_parent_command(self):
        actor, _ = modules()
        for kind in [2, 3]:
            left, right = socket.socketpair()
            worker = actor.PolicyClient.__new__(actor.PolicyClient)
            reader = Client.__new__(Client)
            worker.sock, reader.sock = left, right
            worker.deadline, worker.serial = time.monotonic()+1, 100
            worker.reply_kind, worker.responses = kind, []
            worker.queued_messages = []
            try:
                right.sendall(actor.frame(1, 19, [(1,'o','/foundation'), (2,'s',actor.ALLOWED),
                    (3,'s','Probe'), (7,'s',':1.2'), (6,'s',':1.1'), (8,'g','')]))
                worker.wait_armed()
                result = reader.receive()
                self.assertEqual((result['type'],result['fields'][5],result['fields'][6]), (kind,19,':1.2'))
                self.assertEqual([item['serial'] for item in worker.queued_messages], [19])
                self.assertIsNone(worker.reply_kind)
                self.assertEqual(len(worker.responses), 1)
                self.assertEqual({key:value for key,value in worker.responses[0].items() if key != 'sent_at'},
                                 dict(serial=101,kind=kind,reply_serial=19,destination=':1.2'))
                self.assertLessEqual(worker.responses[0]['sent_at'], time.monotonic())
            finally:
                left.close()
                right.close()

    def test_integration_api_rejects_wrong_source_directory_or_backend(self):
        actor, probe = modules()
        with self.assertRaisesRegex(AssertionError, 'fixture directory mismatch'):
            probe.run_probe('/run/osbus-p08/reference/bus', '/run/osbus-p08/evidence/probe', '/tmp', 'reference')
        with self.assertRaises(AssertionError):
            probe.run_probe('/run/osbus-p08/reference/bus', '/run/osbus-p08/evidence/probe',
                            __import__('pathlib').Path(actor.__file__).parent, '../unbound')

    def test_probe_reads_share_original_absolute_budget(self):
        _, probe = modules()
        with patch('packaged_policy_probe.time.monotonic', return_value=59):
            self.assertEqual(probe.remaining(60), 1)
        with patch('packaged_policy_probe.time.monotonic', return_value=60):
            with self.assertRaisesRegex(AssertionError, 'probe deadline'):
                probe.remaining(60)

    def test_packet_types_are_valid_and_nil_call_keeps_interface_absent(self):
        actor, _ = modules()
        for kind, interface in [(1, None), (1, actor.ALLOWED), (1, actor.DENIED),
                                (4, actor.ALLOWED), (4, actor.DENIED), (2, None), (3, None)]:
            data = actor.packet(kind, 17, ':1.2', interface, 9 if kind in (2, 3) else None)
            left, right = socket.socketpair()
            client = Client.__new__(Client)
            client.sock = right
            try:
                left.sendall(data)
                decoded = client.receive()
                self.assertEqual(decoded['type'], kind)
                self.assertEqual(decoded['fields'].get(2), interface)
                self.assertEqual(decoded['fields'][6], ':1.2')
                self.assertEqual(decoded['fds'], [])
                if kind in (2, 3):
                    self.assertEqual(decoded['fields'][5], 9)
                if kind == 3:
                    self.assertEqual(decoded['fields'][4], 'org.foundation.Expected')
            finally:
                left.close()
                right.close()
        with self.assertRaises(AssertionError):
            actor.packet(4, 18, ':1.2', None)

    def test_positive_and_negative_receipts_require_exact_bound_message(self):
        _, probe = modules()
        message = dict(type=1, serial=17, fields={'7': ':1.1', '6': ':1.2',
            '1': '/foundation', '3': 'Probe', '2': 'org.foundation.Allowed', '8': ''}, body_hex='')
        probe.check_delivery([message], True, 1, 17, ':1.1', ':1.2', 'org.foundation.Allowed')
        probe.check_delivery([], False, 1, 17, ':1.1', ':1.2', 'org.foundation.Allowed')
        for messages, expected in [([], True), ([message], False), ([message, message], True)]:
            with self.assertRaises(AssertionError):
                probe.check_delivery(messages, expected, 1, 17, ':1.1', ':1.2', 'org.foundation.Allowed')
        for field, value in [('7', ':1.9'), ('6', ':1.9'), ('2', 'org.foundation.ReceiveDenied')]:
            malformed = copy.deepcopy(message)
            malformed['fields'][field] = value
            with self.assertRaises(AssertionError):
                probe.check_delivery([malformed], True, 1, 17, ':1.1', ':1.2', 'org.foundation.Allowed')
            with self.assertRaises(AssertionError):
                probe.check_delivery([malformed], False, 1, 17, ':1.1', ':1.2', 'org.foundation.Allowed')

    def test_reply_receipt_requires_reply_serial_and_exact_error(self):
        _, probe = modules()
        message = dict(type=3, serial=21, fields={'7': ':1.1', '6': ':1.2', '5': 19,
            '4': 'org.foundation.Expected', '8': ''}, body_hex='')
        probe.check_delivery([message], True, 3, 21, ':1.1', ':1.2', None, 19)
        for field, value in [('5', 18), ('4', 'org.foundation.Unexpected')]:
            wrong = copy.deepcopy(message)
            wrong['fields'][field] = value
            with self.assertRaises(AssertionError):
                probe.check_delivery([wrong], True, 3, 21, ':1.1', ':1.2', None, 19)

    def test_requested_denial_cannot_pass_from_bound_broker_timeout(self):
        _, probe = modules()
        timeout = dict(type=3,serial=99,fields={'7':'org.freedesktop.DBus','5':19,
            '4':'org.freedesktop.DBus.Error.NoReply'},body_hex='')
        with self.assertRaisesRegex(AssertionError, 'timed out'):
            probe.check_delivery([timeout],False,2,17,':1.1',':1.2',None,19)

    def test_denied_call_requires_matching_broker_access_denied(self):
        _, probe = modules()
        denied = dict(type=3,serial=99,fields={'7':'org.freedesktop.DBus','5':17,
            '4':'org.freedesktop.DBus.Error.AccessDenied','6':':1.1'},body_hex='')
        probe.check_access_denied([denied],17,':1.1')
        for messages in [[],[dict(denied,fields=dict(denied['fields'],**{'5':18}))],
                         [dict(denied,fields=dict(denied['fields'],**{'4':'org.freedesktop.DBus.Error.NoReply'}))],
                         [dict(denied,fields=dict(denied['fields'],**{'7':':1.9'}))]]:
            with self.assertRaises(AssertionError):
                probe.check_access_denied(messages,17,':1.1')

    def test_all_required_rows_must_execute_without_skips(self):
        _, probe = modules()
        self.assertEqual(len(probe.ROWS), 14)
        self.assertEqual(len(set(probe.ROWS)), 14)
        rows = [{'id': row, 'status': 'passed'} for row in probe.ROWS]
        report = probe.accounting(rows)
        self.assertEqual(report, dict(selected=14, executed=14, passed=14, failed=0, blocked=0, skipped=0))
        probe.validate_complete(rows, report)
        for status in ['failed', 'blocked', 'skipped']:
            bad = copy.deepcopy(rows)
            bad[0]['status'] = status
            with self.assertRaises(AssertionError):
                probe.validate_complete(bad, probe.accounting(bad))
        with self.assertRaises(AssertionError):
            probe.validate_complete(rows[:-1], probe.accounting(rows[:-1]))
        with self.assertRaises(AssertionError):
            probe.validate_complete(rows, dict(report, executed=0))

    def test_probe_guard_rejects_live_and_escaped_paths_before_io(self):
        _, probe = modules()
        for path in ['/run/dbus/system_bus_socket', '/run/user/1000/bus',
                     '/run/osbus-p08/../dbus/system_bus_socket', 'relative/socket']:
            with self.assertRaises(AssertionError):
                probe.private_path(path)
        self.assertEqual(str(probe.private_path('/run/osbus-p08/reference/bus')), '/run/osbus-p08/reference/bus')

    def test_evidence_accepts_only_root_owned_exact_disk_backed_alias(self):
        _, probe = modules()
        alias = '/run/osbus-p08/evidence/policy-reference'
        disk = '/var/lib/osbus-p08-evidence'
        resolved = disk+'/policy-reference'
        self.assertEqual(str(probe.validate_evidence_destination(alias,disk,resolved,0)), alias)
        for path, target, actual, owner in [
            ('/run/dbus/evidence',disk,resolved,0),
            (resolved,disk,resolved,0),
            ('/run/osbus-p08/evidence/../socket',disk,resolved,0),
            (alias,'/var/lib/other-evidence',resolved,0),
            (alias,disk,'/var/lib/other-evidence/policy-reference',0),
            (alias,disk,resolved,1100),
        ]:
            with self.assertRaises(AssertionError):
                probe.validate_evidence_destination(path,target,actual,owner)

    def test_credential_bindings_require_broker_and_actor_pid_uid_agreement(self):
        _, probe = modules()
        receipt = dict(pid=123, uid=1100, gid=100, groups=[100], name=':1.2',
                       broker_pid=123, broker_uid=1100)
        probe.validate_identity(receipt, 1100)
        for field, value in [('broker_pid',124), ('broker_uid',1101), ('uid',0),
                              ('groups',[]), ('pid',True), ('name','org.foundation.Observer')]:
            with self.assertRaises(AssertionError):
                probe.validate_identity(dict(receipt, **{field:value}), 1100)


if __name__ == '__main__':
    unittest.main()
