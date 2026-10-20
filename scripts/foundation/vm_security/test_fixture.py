"""No bus traffic: fixed wire vectors and bounded controller I/O checks."""
from copy import deepcopy
import os
from pathlib import Path
import socket
import subprocess
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import run as fixture

from actor import Client, packet
from run import Channel, WORKLOAD, complete, run_check


class FixtureTests(unittest.TestCase):
    def test_real_cleanup_state_requires_settled_egress_and_exact_ingress(self):
        result = subprocess.run(
            ['elixir', str(Path(__file__).with_name('state_test.exs'))],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('3 tests, 0 failures', result.stdout)

    def test_authenticated_fd_negotiation_requires_exact_agreement(self):
        for response, accepted in [(b'AGREE_UNIX_FD', True), (b'ERROR unsupported', False)]:
            with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
                path = str(Path(directory) / 'unit-auth')
                listener.bind(path)
                listener.listen()
                listener.settimeout(2)
                seen = []
                def server():
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        stream = connection.makefile('rb')
                        seen.append(stream.readline())
                        connection.sendall(b'OK 0123456789abcdef0123456789abcdef\r\n')
                        seen.append(stream.readline())
                        connection.sendall(response + b'\r\n')
                        seen.append(stream.readline())
                worker = threading.Thread(target=server)
                worker.start()
                client = Client('/run/osbus-security/vector')
                # Unit-only private endpoint; qualification keeps the guest path guard.
                client.path = path
                try:
                    if accepted:
                        self.assertEqual(client.authenticate(), {'authenticated': True})
                    else:
                        with self.assertRaises(AssertionError):
                            client.authenticate()
                finally:
                    client.socket.close()
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(seen[1], b'NEGOTIATE_UNIX_FD\r\n')
                if accepted:
                    self.assertEqual(seen[2], b'BEGIN\r\n')

    def test_peer_death_must_retain_work_until_consumer_releases_it(self):
        charged = {'reservations': 1, 'global': {'ingress_messages': 1, 'ingress_bytes': 128, 'ingress_fds': 0}}
        released = {'reservations': 0, 'global': {'ingress_messages': 0, 'ingress_bytes': 0, 'ingress_fds': 0}}
        prepared = {'snapshot': {'usage': charged}}
        result = {'retained_ingress': {'usage': charged}, 'consumer_release': 'ok', 'after': {'usage': released}}
        fixture.verify_ingress_cleanup(prepared, result)
        result['retained_ingress'] = {'usage': released}
        with self.assertRaises(AssertionError):
            fixture.verify_ingress_cleanup(prepared, result)

    def test_missing_or_unsuccessful_consumer_release_cannot_qualify_cleanup(self):
        charged = {'reservations': 1, 'global': {'ingress_messages': 1, 'ingress_bytes': 128, 'ingress_fds': 0}}
        prepared = {'snapshot': {'usage': charged}}
        for release in [None, 'unknown_reservation']:
            result = {'retained_ingress': {'usage': charged}, 'consumer_release': release, 'after': {'usage': charged}}
            with self.assertRaises(AssertionError):
                fixture.verify_ingress_cleanup(prepared, result)

    def test_required_action_runs_and_checks_observer_before_passing(self):
        report = {'selected': ['SEC-test'], 'outcomes': {'SEC-test': {'status': 'blocked'}}}
        events = []
        def action():
            events.append('action')
            return 'wire result'
        run_check(report, 'SEC-test', action, lambda: events.append('observer'), lambda: events.append('persist'))
        self.assertEqual([event for event in events if event != 'persist'], ['action', 'observer'])
        self.assertEqual(report['outcomes']['SEC-test'], {'status': 'passed', 'evidence': 'wire result'})
        complete(report)

    def test_action_failure_is_not_a_passing_or_unfinished_result(self):
        report = {'selected': ['SEC-test'], 'outcomes': {'SEC-test': {'status': 'blocked'}}}
        def action():
            raise RuntimeError('intentional actor failure')
        with self.assertRaisesRegex(RuntimeError, 'intentional actor failure'):
            run_check(report, 'SEC-test', action, lambda: self.fail('observer must not mask failure'), lambda: None)
        self.assertEqual(report['outcomes']['SEC-test']['status'], 'failed')
        with self.assertRaises(AssertionError):
            complete(report)

    def test_zero_skipped_or_running_rows_cannot_complete(self):
        with self.assertRaises(AssertionError):
            complete({'selected': [], 'outcomes': {}})
        for status in ['running', 'blocked', 'skipped']:
            with self.assertRaises(AssertionError):
                complete({'selected': ['SEC-test'], 'outcomes': {'SEC-test': {'status': status}}})
    def test_required_workload_selection_and_bounds(self):
        expected = [f'SEC-{n:02d}' for n in range(1, 18)] + ['SYS-02', 'FAIL-01', 'FAIL-02', 'RES-03']
        self.assertEqual(WORKLOAD['selected'], expected)
        self.assertEqual(len(set(expected)), len(expected))
        self.assertLess(WORKLOAD['auth']['trickle_interval_ms'], WORKLOAD['auth']['idle_ms'])
        self.assertLess(WORKLOAD['auth']['idle_ms'], WORKLOAD['auth']['close_min_ms'])
        self.assertEqual(WORKLOAD['metrics']['fd_growth_max'], 0)
    def test_fixed_hello_vector(self):
        # D-Bus spec alignment: fixed header, a(yv) fields, padding, empty body.
        expected = bytes.fromhex(
            '6c01000100000000010000006d000000'
            '01016f00150000002f6f72672f667265656465736b746f702f4442757300'
            '000002017300140000006f72672e667265656465736b746f702e4442757300'
            '000000030173000500000048656c6c6f000000'
            '06017300140000006f72672e667265656465736b746f702e4442757300000000'
        )
        self.assertEqual(packet(1, 'Hello'), expected)

    def decode(self, data):
        first, second = socket.socketpair()
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.settimeout(1)
        second.sendall(data)
        second.shutdown(socket.SHUT_WR)
        client = Client('/run/osbus-security/vector')
        client.socket = first
        return client.message()

    def test_name_owner_changed_fixed_body(self):
        # One signature header and three independently encoded strings.
        header = b'\x08\x01g\x00\x03sss\x00'
        payload = bytes.fromhex('01000000780000000100000079000000010000007a00')
        prefix = struct.pack('<BBBBIII', ord('l'), 4, 0, 1, len(payload), 9, len(header))
        result = self.decode(prefix + header + b'\0' * 7 + payload)
        self.assertEqual(result['body'], ['x', 'y', 'z'])

    def test_invalid_string_terminator_rejected(self):
        header = b'\x08\x01g\x00\x01s\x00'
        payload = b'\x01\x00\x00\x00x!'
        prefix = struct.pack('<BBBBIII', ord('l'), 2, 0, 1, len(payload), 1, len(header))
        with self.assertRaises(AssertionError):
            self.decode(prefix + header + b'\0' + payload)

    def test_sender_field_can_represent_forged_input(self):
        frame = packet(2, 'Changed', 's', ['probe'], destination=':1.4', sender=':1.1',
                       message_type=4, interface='org.foundation.Allowed', path='/public')
        self.assertEqual(self.decode(frame)['sender'], ':1.1')

    def test_complete_malformed_body_vector(self):
        frame = bytearray(packet(2, 'RequestName', 'su', ['org.foundation.Service.Malformed', 0]))
        del frame[-4:]
        size = struct.unpack_from('<I', frame, 4)[0]
        struct.pack_into('<I', frame, 4, size - 4)
        with self.assertRaises(struct.error):
            self.decode(frame)

    def test_channel_reads_buffered_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            channel = Channel([sys.executable, '-u', '-c',
                               'import sys; print("noise\\nFIXTURE {\\"n\\":1}\\nFIXTURE {\\"n\\":2}"); sys.stdin.read()'],
                              Path(directory) / 'channel.log', 'FIXTURE ')
            try:
                self.assertEqual(channel.read(timeout=1), {'n': 1})
                self.assertEqual(channel.read(timeout=1), {'n': 2})
            finally:
                channel.stop()
            self.assertEqual(channel.process.returncode, 0)

    def test_channel_forced_stop_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            channel = Channel([sys.executable, '-u', '-c',
                               'import signal; print("{}"); signal.pause()'],
                              Path(directory) / 'channel.log')
            channel.read(timeout=1)
            try:
                result = channel.stop(grace=0.05)
            finally:
                if channel.process.poll() is None:
                    channel.stop()
            self.assertEqual(result['returncode'], -15)
            self.assertEqual(result['method'], 'terminate')
            with self.assertRaises(ProcessLookupError):
                os.kill(channel.process.pid, 0)


class ResourceBaselineTests(unittest.TestCase):
    def baseline(self):
        counts = dict(connections=1, authenticating=0, frame_bytes=0, frame_fds=0,
                      ingress_messages=0, ingress_bytes=0, ingress_fds=0,
                      egress_messages=0, egress_bytes=0, egress_fds=0)
        peers = [
            dict(peer='observer', name=':1.1', names=[':1.1', 'org.foundation.Observer'],
                 credentials=dict(pid=985, uid=1100, gid=100, unique_name=':1.1'),
                 match_rules=False, capabilities=0),
            dict(peer='service', name=':1.2', names=[':1.2', 'org.foundation.Service'],
                 credentials=dict(pid=990, uid=1101, gid=100, unique_name=':1.2'),
                 match_rules=False, capabilities=0),
        ]
        usage = dict(reservations=0,
            peers=[dict(peer=row['peer'], counts=deepcopy(counts)) for row in peers],
            uids=[dict(uid=uid, counts=deepcopy(counts)) for uid in [1100, 1101]])
        usage['global'] = dict(counts, connections=2)
        return dict(snapshot=dict(peers=peers, usage=usage))

    def extra_peer(self, before):
        measured = deepcopy(before)
        snapshot = measured['snapshot']
        snapshot['peers'].append(dict(
            peer='burst', name=':1.78', names=[':1.78'],
            credentials=dict(pid=1106, uid=1100, gid=100, unique_name=':1.78'),
            match_rules=False, capabilities=0))
        usage = snapshot['usage']
        usage['global']['connections'] += 1
        usage['peers'].append(dict(peer='burst', counts=deepcopy(usage['peers'][0]['counts'])))
        usage['uids'][0]['counts']['connections'] += 1
        return measured

    def measurement(self, observations, advance_seconds):
        clock = [100.0]
        calls = []

        def measure():
            if len(calls) == 128:
                raise RuntimeError('test guard: attempted a 129th measurement')
            measured = observations[min(len(calls), len(observations) - 1)]
            clock[0] += advance_seconds
            calls.append(measured)
            return measured

        return clock, calls, measure

    def assert_retention_refused(self, before, retained):
        clock, calls, measure = self.measurement([retained], 0.5)
        with patch.object(fixture.time, 'monotonic', lambda: clock[0]):
            with self.assertRaises(AssertionError):
                fixture.await_resource_baseline(before, measure, 750)
        self.assertEqual(len(calls), 2)

    def test_extra_peer_in_both_authorities_requires_another_measurement(self):
        before = self.baseline()
        original = deepcopy(before)
        extra = self.extra_peer(before)
        recovered = deepcopy(before)
        recovered['snapshot']['peers'].reverse()
        recovered['measurement'] = 'actual recovered result'
        clock, calls, measure = self.measurement([extra, recovered], 0.125)
        with patch.object(fixture.time, 'monotonic', lambda: clock[0]):
            result = fixture.await_resource_baseline(before, measure, 2000)
        self.assertIs(result['after'], recovered)
        self.assertEqual(result['attempts'], 2)
        self.assertAlmostEqual(result['elapsed_ms'], 250)
        self.assertEqual(len(result['samples']), 2)
        self.assertEqual(calls, [extra, recovered])
        self.assertEqual(before, original)

    def test_persistent_extra_registered_peer_times_out(self):
        before = self.baseline()
        self.assert_retention_refused(before, self.extra_peer(before))

    def test_same_counts_with_wrong_uid_credit_refuse(self):
        before = self.baseline()
        retained = deepcopy(before)
        retained['snapshot']['usage']['uids'][0]['uid'] = 1102
        self.assert_retention_refused(before, retained)

    def test_same_counts_with_changed_peer_identity_refuse(self):
        before = self.baseline()
        retained = deepcopy(before)
        retained['snapshot']['peers'][0]['peer'] = 'different peer'
        self.assert_retention_refused(before, retained)

    def test_same_counts_with_changed_peer_credentials_refuse(self):
        before = self.baseline()
        retained = deepcopy(before)
        retained['snapshot']['peers'][0]['credentials']['uid'] = 1102
        self.assert_retention_refused(before, retained)

    def test_same_counts_with_retained_router_name_refuse(self):
        before = self.baseline()
        retained = deepcopy(before)
        retained['snapshot']['peers'][0]['names'].append('org.foundation.Forbidden')
        self.assert_retention_refused(before, retained)

    def test_router_only_extra_peer_refuses(self):
        before = self.baseline()
        retained = self.extra_peer(before)
        retained['snapshot']['usage'] = deepcopy(before['snapshot']['usage'])
        self.assert_retention_refused(before, retained)

    def test_limits_only_extra_peer_refuses(self):
        before = self.baseline()
        retained = self.extra_peer(before)
        retained['snapshot']['peers'] = deepcopy(before['snapshot']['peers'])
        self.assert_retention_refused(before, retained)

    def test_retained_egress_credit_refuses(self):
        before = self.baseline()
        retained = deepcopy(before)
        usage = retained['snapshot']['usage']
        for counts in [usage['global'], usage['peers'][0]['counts'], usage['uids'][0]['counts']]:
            counts.update(egress_messages=1, egress_bytes=128)
        usage['reservations'] = 1
        self.assert_retention_refused(before, retained)

    def test_exact_callback_returning_after_deadline_is_rejected(self):
        before = self.baseline()
        clock, calls, measure = self.measurement([deepcopy(before)], 1.125)
        with patch.object(fixture.time, 'monotonic', lambda: clock[0]):
            with self.assertRaises(AssertionError):
                fixture.await_resource_baseline(before, measure, 1000)
        self.assertEqual(len(calls), 1)

    def test_deadline_is_not_reset_between_measurements(self):
        before = self.baseline()
        clock, calls, measure = self.measurement([self.extra_peer(before), deepcopy(before)], 0.625)
        with patch.object(fixture.time, 'monotonic', lambda: clock[0]):
            with self.assertRaises(AssertionError):
                fixture.await_resource_baseline(before, measure, 1000)
        self.assertEqual(len(calls), 2)

    def test_measurements_are_capped_at_128(self):
        before = self.baseline()
        clock, calls, measure = self.measurement([self.extra_peer(before)], 0)
        with patch.object(fixture.time, 'monotonic', lambda: clock[0]):
            with self.assertRaises(AssertionError):
                fixture.await_resource_baseline(before, measure, 2000)
        self.assertEqual(len(calls), 128)

    def test_measurement_callback_error_propagates_unchanged(self):
        before = self.baseline()
        clock = [100.0]
        calls = []
        failure = RuntimeError('measurement failed')

        def measure():
            clock[0] += 0.125
            calls.append('measure')
            raise failure

        with patch.object(fixture.time, 'monotonic', lambda: clock[0]):
            with self.assertRaises(RuntimeError) as raised:
                fixture.await_resource_baseline(before, measure, 2000)
        self.assertIs(raised.exception, failure)
        self.assertEqual(calls, ['measure'])


if __name__ == '__main__':
    unittest.main()
