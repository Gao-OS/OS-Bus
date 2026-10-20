"""Offline controls only: native socketpair/wire primitives, never a broker."""
import array
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class ActorControls(unittest.TestCase):
    def setUp(self):
        self.assertTrue((HERE / 'actor.py').is_file(), 'independent actor implementation missing')
        spec = importlib.util.spec_from_file_location('fd01_actor_controls', HERE / 'actor.py')
        self.actor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.actor)
        self.wire = self.actor.load_wire(ROOT / 'apps/gao_bus/test/fixtures')
        self.owned = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for item in reversed(self.owned):
            item.close()

    def pair(self):
        pair = socket.socketpair()
        self.owned.extend(pair)
        return pair

    def client(self, role='target', name=':1.2'):
        reader, writer = self.pair()
        client = self.actor.Client(reader, role, self.wire)
        client.name, client.phase = name, 'active'
        return client, writer

    def delivered(self, **changes):
        client, peer = self.client()
        original, partner = self.pair()
        fields = [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
                  (3, 's', 'Resource'), (6, 's', changes.pop('destination', ':1.2')),
                  (7, 's', changes.pop('sender', ':1.1')),
                  (8, 'g', changes.pop('signature', 'h')), (9, 'u', changes.pop('count', 1))]
        raw = self.wire.frame(changes.pop('kind', 4), changes.pop('serial', 100), fields,
                              changes.pop('body', self.wire.u32(0)), changes.pop('flags', 0))
        rights = changes.pop('rights', [original.fileno()])
        peer.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
        message = client.receive()
        self.addCleanup(lambda: self.wire.close_fds(message['fds']))
        return client, message, original, partner

    def test_real_singleton_resource_is_usable_and_identical(self):
        client, message, original, partner = self.delivered()
        partner.sendall(b'SOCKET')
        receipt = self.actor.validate_transfer(client, message, ':1.1', original.fileno(), partner.fileno())
        self.assertEqual(receipt['content'], 'SOCKET')
        self.assertEqual(receipt['source_fd']['ino'], receipt['received_fd']['ino'])
        self.assertNotEqual(receipt['partner_fd']['ino'], receipt['received_fd']['ino'])
        self.assertEqual(receipt['received']['wire_hex'], client.events[-1]['wire_hex'])
        self.assertEqual(len(message['fds']), 1)

    def test_wrong_order_identity_signature_index_and_count_are_rejected(self):
        for change in ({'serial': 99}, {'kind': 2}, {'sender': ':1.9'},
                       {'destination': ':1.9'}, {'signature': 'u'}, {'body': self.wire.u32(1)},
                       {'count': 0, 'rights': []}):
            with self.subTest(change=change):
                client, message, original, partner = self.delivered(**change)
                with self.assertRaises(AssertionError):
                    self.actor.validate_transfer(client, message, ':1.1', original.fileno(), partner.fileno())

    def test_nonzero_signal_flags_are_rejected(self):
        client, message, original, partner = self.delivered(flags=1)
        partner.sendall(b'SOCKET')
        with self.assertRaises(AssertionError):
            self.actor.validate_transfer(client, message, ':1.1', original.fileno(), partner.fileno())

    def test_partial_socket_payload_reads_all_six_bytes(self):
        reader, writer = self.pair()
        writer.sendall(b'SOCKET')
        class OneByte:
            def settimeout(self, timeout): reader.settimeout(timeout)
            def recv(self, length): return reader.recv(min(length, 1))
        self.assertEqual(self.actor.read_payload(OneByte()), b'SOCKET')

    def test_payload_eof_and_wrong_content_are_rejected(self):
        for data in (b'SOC', b'BROKEN'):
            reader, writer = self.pair()
            writer.sendall(data)
            writer.shutdown(socket.SHUT_WR)
            with self.assertRaises(AssertionError): self.actor.read_payload(reader)

    def test_partial_frame_eof_closes_received_right(self):
        client, peer = self.client()
        resource, partner = self.pair()
        before = self.actor.fd_state()
        raw = self.wire.signal(100, ':1.2')
        peer.sendmsg([raw[:17]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [resource.fileno()]))])
        peer.shutdown(socket.SHUT_WR)
        with self.assertRaises(AssertionError): client.receive()
        self.assertEqual(self.actor.fd_state(), before)
        self.assertIn('error', client.events[-1])

    def test_header_count_mismatch_closes_right(self):
        client, peer = self.client()
        resource, partner = self.pair()
        before = self.actor.fd_state()
        peer.sendmsg([self.wire.signal(100, ':1.2', 0)],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [resource.fileno()]))])
        with self.assertRaises(AssertionError): client.receive()
        self.assertEqual(self.actor.fd_state(), before)

    def test_health_first_receipt_is_strict_and_closes_extra_right(self):
        client, peer = self.client('source', ':1.1')
        resource, partner = self.pair()
        before = self.actor.fd_state()
        peer.sendmsg([self.wire.signal(99, ':1.1')],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [resource.fileno()]))])
        with self.assertRaises(AssertionError): self.actor.healthy(client, 110)
        self.assertEqual(self.actor.fd_state(), before)

    def test_real_health_reply_exact_name_owner(self):
        client, peer = self.client('source', ':1.1')
        peer.sendall(self.wire.frame(2, 30, [(5, 'u', 110), (6, 's', ':1.1'),
                    (7, 's', 'org.freedesktop.DBus'), (8, 'g', 's')], self.wire.string(':1.1')))
        result = self.actor.healthy(client, 110)
        self.assertEqual(result['reply_serial'], 110)
        self.assertEqual(result['owner'], ':1.1')
        self.assertEqual(result['rights'], 0)

    def test_close_retained_resources_and_connections(self):
        worker = self.actor.Workload('/unused/offline-control', self.wire)
        source, source_peer = self.client('source', ':1.1')
        target, target_peer = self.client()
        first, second = self.pair()
        received = os.dup(first.fileno())
        worker.clients = {'source': source, 'target': target}
        worker.pair = (first, second)
        worker.received_fd = received
        fds = [source.sock.fileno(), target.sock.fileno(), first.fileno(), second.fileno(), received]
        result = worker.close('close')
        self.assertEqual(result['connections'], [])
        self.assertTrue(all(row['closed'] for row in result['closure']))
        for fd in fds:
            with self.assertRaises(OSError) as error: os.fstat(fd)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_eof_cleanup_envelope_and_error_cleanup(self):
        source, peer = self.client('source', ':1.1')
        worker = self.actor.Workload('/unused/offline-control', self.wire)
        # The offline peer belongs to this test process, outside actor ownership.
        baseline = self.actor.fd_state()
        baseline['fds'] = [row for row in baseline['fds'] if row['fd'] != source.sock.fileno()]
        baseline['count'] = len(baseline['fds'])
        worker.baseline = baseline
        worker.clients = {'source': source}
        output = io.StringIO()
        self.actor.serve(worker, io.StringIO('{"op":"unknown"}\n'), output)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertFalse(rows[0]['ok'])
        self.assertEqual(rows[0]['cleanup']['connections'], [])
        self.assertEqual(rows[1]['result']['op'], 'eof')
        self.assertEqual(rows[1]['result']['connections'], [])
        self.assertEqual(rows[1]['result']['fd_growth'], 0)

    def test_operation_order_rejects_exercise_without_open(self):
        worker = self.actor.Workload('/unused/offline-control', self.wire)
        with self.assertRaises(AssertionError): worker.command({'op': 'exercise'})

    def offline_transfer_channels(self):
        """Explicit native wire relay for unit controls; no broker or auth claim."""
        source, source_peer = self.client('source', ':1.1')
        target, target_peer = self.client()
        source_peer.sendall(self.wire.frame(2, 30, [(5, 'u', 110), (6, 's', ':1.1'),
              (7, 's', 'org.freedesktop.DBus'), (8, 'g', 's')], self.wire.string(':1.1')))
        def relay(raw, rights):
            self.assertEqual(raw, self.wire.signal(100, ':1.2'))
            self.assertEqual(len(rights), 1)
            forwarded = self.wire.frame(4, 100, [(1, 'o', '/foundation'),
                (2, 's', 'org.foundation.Transport'), (3, 's', 'Resource'),
                (6, 's', ':1.2'), (7, 's', ':1.1'), (8, 'g', 'h'), (9, 'u', 1)], self.wire.u32(0))
            target_peer.sendmsg([forwarded], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
            target_peer.sendall(self.wire.frame(2, 31, [(5, 'u', 111), (6, 's', ':1.2'),
                (7, 's', 'org.freedesktop.DBus'), (8, 'g', 's')], self.wire.string(':1.2')))
        source.send_fds = relay
        worker = self.actor.Workload('/unused/offline-control', self.wire)
        worker.baseline['fds'] = [row for row in worker.baseline['fds']
                    if row['fd'] not in (source.sock.fileno(), target.sock.fileno())]
        worker.baseline['count'] = len(worker.baseline['fds'])
        return worker, source, target

    def test_exercise_keeps_three_actual_resources_until_close(self):
        worker, source, target = self.offline_transfer_channels()
        worker.clients, worker.state = {'source': source, 'target': target}, 'open'
        receipt = worker.command({'op': 'exercise'})
        self.assertTrue(receipt['held'])
        self.assertEqual([row['serial'] for row in receipt['health']], [110, 111])
        transfer = receipt['transfer']
        for role in ('source_fd', 'partner_fd', 'received_fd'):
            self.assertEqual(self.actor.fd_record(transfer[role]['fd']), transfer[role])
        self.assertEqual(transfer['sent']['wire_hex'], self.wire.signal(100, ':1.2').hex())
        with self.assertRaises(AssertionError): worker.command({'op': 'exercise'})
        closed = worker.command({'op': 'close'})
        self.assertEqual(len(closed['closure']), 5)
        self.assertEqual(closed['fd_growth'], 0)
        self.assertTrue(closed['baseline_equal'])

    def test_warmup_completes_transfer_and_closes_before_return(self):
        worker, source, target = self.offline_transfer_channels()
        with patch.object(self.actor.Client, 'connect', side_effect=[source, target]):
            result = worker.command({'op': 'warmup'})
        self.assertFalse(result['held'])
        self.assertEqual(result['connections'], [])
        self.assertTrue(result['close']['baseline_equal'])
        self.assertEqual(worker.state, 'warmed')
        for row in result['close']['closure']:
            with self.assertRaises(OSError): os.fstat(row['fd'])

    def test_error_during_exercise_closes_pair_right_and_both_connections(self):
        worker, source, target = self.offline_transfer_channels()
        worker.clients, worker.state = {'source': source, 'target': target}, 'open'
        output = io.StringIO()
        with patch.object(self.actor, 'read_payload', side_effect=AssertionError('offline payload error')):
            self.actor.serve(worker, io.StringIO('{"op":"exercise"}\n'), output)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertFalse(rows[0]['ok'])
        closed = rows[0]['cleanup']
        self.assertEqual(len(closed['closure']), 5)
        self.assertTrue(closed['baseline_equal'])
        self.assertEqual(closed['fd_growth'], 0)
        self.assertEqual(closed['events']['target'][-1]['serial'], 100)
        self.assertTrue(rows[-1]['ok'])

    def test_eof_at_checked_closes_every_held_descriptor(self):
        worker, source, target = self.offline_transfer_channels()
        worker.clients, worker.state = {'source': source, 'target': target}, 'open'
        worker.exercise()
        output = io.StringIO()
        self.actor.serve(worker, io.StringIO(''), output)
        row = json.loads(output.getvalue())
        self.assertTrue(row['ok'])
        self.assertEqual(row['result']['op'], 'eof')
        self.assertEqual(len(row['result']['closure']), 5)
        self.assertTrue(row['result']['baseline_equal'])
        self.assertEqual(row['result']['fd_growth'], 0)

    def test_active_reply_filtering_is_forbidden(self):
        client, peer = self.client()
        with self.assertRaisesRegex(AssertionError, 'permissive active reply read forbidden'):
            client.reply(110)

    def test_real_ancillary_truncation_closes_kernel_installed_rights(self):
        client, peer = self.client()
        resource, partner = self.pair()
        raw = client.sock.raw
        class SmallControls:
            def __getattr__(self, name): return getattr(raw, name)
            def recvmsg(self, length, capacity): return raw.recvmsg(length, socket.CMSG_SPACE(4))
        client.sock.raw = SmallControls()
        before = self.actor.fd_state()
        peer.sendmsg([self.wire.signal(100, ':1.2', 3)],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [resource.fileno()] * 3))])
        with self.assertRaises(AssertionError): client.receive()
        self.assertEqual(self.actor.fd_state(), before)

    def test_expired_deadline_rejects_before_socket_read(self):
        client, peer = self.client()
        client.deadline_at = self.actor.time.monotonic() - 1
        with self.assertRaisesRegex(AssertionError, 'absolute actor socket deadline'):
            client.read(1, [])

    def test_absolute_deadline_stays_fixed_across_reads(self):
        client, peer = self.client()
        with client.deadline(1000):
            end = client.deadline_at
            with client.deadline(3000): self.assertEqual(client.deadline_at, end)
            peer.sendall(b'ab')
            self.assertEqual(client.read(1, []), b'a')
            self.assertEqual(client.read(1, []), b'b')
            self.assertEqual(client.deadline_at, end)


if __name__ == '__main__':
    unittest.main(verbosity=2)
