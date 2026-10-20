"""Pure actor controls: fixed pins and mocked I/O; never opens a socket."""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import actor_overlay as actor


class ActorTest(unittest.TestCase):
    def test_targets_equal_independent_accepted_vector_pins(self):
        vectors = json.loads(Path(__file__).with_name('vectors.json').read_text())
        self.assertEqual(set(vectors['cases']), set(actor.CASES))
        for case, expected in vectors['cases'].items():
            with self.subTest(case=case):
                frame = actor.target_frame(case)
                self.assertEqual(len(frame), expected['bytes'])
                self.assertEqual(hashlib.sha256(frame).hexdigest(), expected['sha256'])
                self.assertEqual(int.from_bytes(frame[8:12], 'little'), expected['serial'])
                if 'hex' in expected:
                    self.assertEqual(frame.hex(), expected['hex'])
        collection = actor.target_frame('collection')
        self.assertEqual(collection[136:140], bytes.fromhex('74ff0f00'))
        self.assertEqual(collection[140:], b'\x2a' * 1_048_436)

    def test_unknown_target_rejects(self):
        with self.assertRaises(AssertionError):
            actor.target_frame('unselected')

    def test_registration_preserves_all_legal_signal_interleavings(self):
        for position in range(3):
            client = fake_client()
            rows = [reply(1, [client.unique]), reply(2, [client.bus_id])]
            rows.insert(position, acquired(client.unique))
            client.messages = list(rows)
            with self.subTest(position=position), patch.object(client, 'authenticate'), \
                    patch.object(actor.select, 'select', return_value=([], [], [])):
                result = client.command(dict(op='register'))
            self.assertEqual(result['registration'], rows)
            self.assertEqual(result['unique'], client.unique)
            self.assertEqual(result['bus_id'], client.bus_id)
            self.assertEqual(client.messages, [])

    def test_registration_rejects_reversed_replies_or_extra_signal(self):
        client = fake_client()
        hello, get_id = reply(1, [client.unique]), reply(2, [client.bus_id])
        signal = acquired(client.unique)
        for rows in ([get_id, signal, hello], [hello, signal, signal]):
            client.messages = list(rows)
            with self.subTest(rows=rows), patch.object(client, 'authenticate'), \
                    self.assertRaises(AssertionError):
                client.command(dict(op='register'))

    def test_guest_endpoint_namespace_is_mandatory(self):
        actor.check_endpoint('/run/osbus-security/pro05-complete/gao_bus/bus')
        for path in ['/run/dbus/system_bus_socket', '/tmp/bus',
                     '/run/osbus-security/pro05-complete/../other/bus',
                     '/run/osbus-security/pro05-complete-extra/bus']:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                actor.check_endpoint(path)

    def test_large_send_trace_is_compact_and_records_actual_bytes(self):
        raw = Mock()
        trace = []
        clock = dict(origin=10.0, deadline=13.0)
        stream = actor.RecordedSocket(raw, trace, clock)
        frame = actor.target_frame('collection')
        with patch.object(actor.time, 'monotonic', return_value=10.1):
            stream.sendall(frame)
        raw.sendall.assert_called_once_with(frame)
        self.assertEqual(trace, [dict(direction='send', **actor.receipt(frame),
                                     sent=True, elapsed_ms=trace[0]['elapsed_ms'])])
        self.assertNotIn('hex', trace[0])
        self.assertLess(len(actor.control_line(dict(wire=trace))), 1024)

    def test_failed_send_is_not_a_successful_write_receipt(self):
        raw = Mock()
        raw.sendall.side_effect = BrokenPipeError(32, 'closed')
        trace = []
        stream = actor.RecordedSocket(raw, trace, dict(origin=10, deadline=13))
        with patch.object(actor.time, 'monotonic', return_value=11):
            with self.assertRaises(BrokenPipeError):
                stream.sendall(actor.target_frame('prefix'))
        self.assertFalse(trace[0]['sent'])
        self.assertEqual(trace[0]['errno'], 32)

    def test_successful_io_cannot_overrun_whole_command_deadline(self):
        raw = Mock()
        stream = actor.RecordedSocket(raw, [], dict(origin=10, deadline=13))
        with patch.object(actor.time, 'monotonic', side_effect=[12, 12, 14]):
            with self.assertRaises(AssertionError):
                stream.sendall(b'x')

    def test_caller_deadline_caps_fixed_budget(self):
        self.assertEqual(actor.command_deadline({'op': 'target', 'case': 'collection'}, 10),
                         (13, 3000))
        self.assertEqual(actor.command_deadline({'op': 'observe'}, 10), (11, 1000))
        self.assertEqual(actor.command_deadline({'op': 'target', 'deadline_monotonic': 10.5}, 10),
                         (10.5, 3000))
        for value in [10, float('inf'), float('nan'), True]:
            with self.subTest(value=value), self.assertRaises(AssertionError):
                actor.command_deadline({'op': 'target', 'deadline_monotonic': value}, 10)

    def test_terminal_target_only_sends_before_controller_authorizes_eof(self):
        client = fake_client()
        result = client.command(dict(op='target', case='prefix'))
        self.assertEqual(result['disposition'], 'sent-awaiting-controller')
        client.socket.recv.assert_not_called()
        self.assertTrue(result['source_socket_open'])
        client.socket.recv.return_value = b''
        result = client.command(dict(op='terminal', case='prefix', authorization='down/restored/1'))
        self.assertEqual(result['terminal_hex'], '')
        self.assertTrue(result['source_socket_open'])
        client.socket.close.assert_not_called()

    def test_terminal_cannot_run_without_authorization_or_matching_send(self):
        client = fake_client()
        for request in [dict(op='terminal', case='prefix', authorization='x'),
                        dict(op='terminal', case='prefix')]:
            with self.subTest(request=request), self.assertRaises(AssertionError):
                client.command(request)
        client.socket.recv.assert_not_called()
        client.command(dict(op='target', case='prefix'))
        with self.assertRaises(AssertionError):
            client.command(dict(op='terminal', case='prefix'))
        client.socket.recv.assert_not_called()

    def test_legal_target_reads_error_then_exact_source_health(self):
        client = fake_client()
        client.messages = [dict(type=3, reply_serial=3, sender=actor.BUS,
                                error=actor.INVALID_ARGS, body=['bad arguments']),
                           reply(4, [client.unique]), reply(5, [client.bus_id])]
        with patch.object(actor.select, 'select', return_value=([], [], [])):
            result = client.command(dict(op='target', case='array32'))
        self.assertEqual(result['disposition'], 'invalid-args')
        self.assertEqual([row['reply_serial'] for row in result['source_health']], [4, 5])
        self.assertEqual(client.serial, 5)
        self.assertEqual(client.messages, [])

    def test_typed_observation_does_not_skip_an_unexpected_signal(self):
        client = fake_client()
        client.role = 1100
        client.serial = 11
        client.messages = [dict(type=4, serial=6, reply_serial=None, error=None, sender=':1.2',
                                interface='org.foundation.Probe', member='Changed', body=[42]),
                           reply(12, [client.unique]), reply(13, [client.bus_id])]
        with self.assertRaises(AssertionError):
            client.command(dict(op='observe', owner='org.foundation.Pro05Observer', serial=12))

    def test_setup_allows_existing_kernel_identity_queries(self):
        client = fake_client()
        for operation in ('call', 'send'):
            for member in ('GetConnectionUnixUser', 'GetConnectionUnixProcessID'):
                request = dict(op=operation, member=member, signature='s', body=[client.unique])
                with self.subTest(operation=operation, member=member):
                    self.assertEqual(client.command(request), request)

    def test_control_line_bound_is_unchanged(self):
        self.assertEqual(actor.CONTROL_BYTES, 4_194_304)
        with self.assertRaises(AssertionError):
            actor.control_line(dict(raw='x' * actor.CONTROL_BYTES))


def reply(serial, body):
    return dict(type=2, reply_serial=serial, sender=actor.BUS, error=None, body=body)


def acquired(name):
    return dict(type=4, serial=1, reply_serial=None, error=None, sender=actor.BUS,
                interface=actor.BUS, member='NameAcquired', body=[name])


def fake_client():
    class Client:
        def __init__(self, path):
            self.socket = Mock()
            self.socket.fileno.return_value = 7
            self.buffer = b''
            self.pending = []
            self.serial = 2
            self.unique = ':1.2'
            self.bus_id = '0123456789abcdef0123456789abcdef'
            self.messages = []

        def message(self):
            return self.messages.pop(0)

        def command(self, request):
            return request

    return actor.client_type(Client, [], dict(origin=0, deadline=1))('unused-in-pure-test')


if __name__ == '__main__':
    unittest.main()
