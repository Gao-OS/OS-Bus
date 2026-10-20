"""Offline FD-05 controls: real Unix streams/rights, never a bus daemon."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
WIRE = HERE.parents[2] / 'apps/gao_bus/test/fixtures'
sys.path.insert(0, str(WIRE))
import transport_actor as wire


class ActorControls(unittest.TestCase):
    def setUp(self):
        path = HERE / 'actor.py'
        self.assertTrue(path.is_file(), 'FD-05 independent actor is not implemented')
        spec = importlib.util.spec_from_file_location('fd05_actor', path)
        self.actor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.actor)
        self.actor.load_wire(WIRE)
        self.left, self.right = socket.socketpair()
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)
        self.events = {'sent': [], 'received': [], 'resources': [], 'health': [], 'barriers': []}
        self.client = self.actor.ObservedClient.__new__(self.actor.ObservedClient)
        self.client.configure(self.left, 'ordinary', self.events)
        self.client.name = ':1.77'

    def reply(self, serial=4, kind=2, sender='org.freedesktop.DBus', destination=':1.77', body=None, signature='s', extra=()):
        return wire.frame(kind, 700, [(5, 'u', serial), (7, 's', sender),
             (6, 's', destination), (8, 'g', signature), *extra],
             wire.string(':1.77') if body is None else body)

    def error(self, serial=3, error='org.freedesktop.DBus.Error.NotSupported', kind=3, sender='org.freedesktop.DBus', destination=':1.77', extra=()):
        return wire.frame(kind, 701, [(4, 's', error), (5, 'u', serial),
             (7, 's', sender), (6, 's', destination), (8, 'g', 's'), *extra], wire.string('FDs unsupported'))

    def transfer(self, raw, contents=b'OS-BUS-BROADCAST-MEMFD'):
        fd = os.memfd_create('foundation-broadcast-%d' % os.getpid(), os.MFD_CLOEXEC)
        self.addCleanup(os.close, fd)
        os.write(fd, contents)
        import array
        self.right.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        return fd

    def test_exact_health_receipt_and_duration(self):
        self.right.sendall(self.reply())
        receipt = self.actor.healthy(self.client, 4)
        self.assertEqual(receipt['serial'], 4)
        self.assertLessEqual(receipt['latency_ms'], 1000)
        observed = self.events['received'][0]
        self.assertEqual(observed['wire_hex'], self.reply().hex())
        self.assertEqual(observed['body_hex'], wire.string(':1.77').hex())
        self.assertEqual(observed['rights'], 0)

    def test_stripped_resource_before_valid_health_is_rejected(self):
        raw = wire.signal(100, count=None, body=wire.u32(0))
        self.right.sendall(raw + self.reply())
        with self.assertRaises(AssertionError):
            self.actor.healthy(self.client, 4)
        self.assertEqual(len(self.events['received']), 1)
        self.assertEqual(self.events['received'][0]['serial'], 100)

    def test_resource_before_valid_health_is_rejected_and_closed(self):
        source = self.transfer(wire.signal(100))
        self.right.sendall(self.reply())
        before = self.actor.fd_inventory()['count']
        with self.assertRaises(AssertionError):
            self.actor.healthy(self.client, 4)
        self.assertEqual(self.actor.fd_inventory()['count'], before)
        self.assertEqual(os.pread(source, 99, 0), b'OS-BUS-BROADCAST-MEMFD')
        self.assertEqual(self.events['received'][0]['rights'], 1)

    def test_health_rejects_wrong_type_serial_sender_destination_body(self):
        for mutation in ({'kind': 3}, {'serial': 9}, {'sender': ':9.1'}, {'destination': ':1.8'}, {'body': wire.string('wrong')}):
            with self.subTest(mutation=mutation):
                self.right.sendall(self.reply(**mutation))
                with self.assertRaises(AssertionError):
                    self.actor.healthy(self.client, 4)

    def test_health_requires_string_signature(self):
        self.right.sendall(self.reply(signature='h'))
        with self.assertRaises(AssertionError):
            self.actor.healthy(self.client, 4)

    def test_header_right_count_mismatch_is_rejected_and_closed(self):
        self.transfer(self.reply(extra=[(9, 'u', 0)]))
        before = self.actor.fd_inventory()['count']
        with self.assertRaises(AssertionError):
            self.actor.healthy(self.client, 4)
        self.assertEqual(self.actor.fd_inventory()['count'], before)

    def test_error_requires_exact_type_serial_error_and_envelope(self):
        self.right.sendall(self.error())
        result = self.actor.denied(self.client)
        self.assertEqual(result['error_reply_serial'], 3)
        for mutation in ({'kind': 2}, {'serial': 9}, {'error': 'org.freedesktop.DBus.Error.AccessDenied'}, {'sender': ':9.1'}, {'destination': ':1.8'}):
            with self.subTest(mutation=mutation):
                self.right.sendall(self.error(**mutation))
                with self.assertRaises(AssertionError):
                    self.actor.denied(self.client)

    def test_resource_bearing_error_is_rejected_and_right_closed(self):
        self.transfer(self.error(extra=[(9, 'u', 1)]))
        before = self.actor.fd_inventory()['count']
        with self.assertRaises(AssertionError):
            self.actor.denied(self.client)
        self.assertEqual(self.actor.fd_inventory()['count'], before)

    def test_negotiated_usable_memfd_received_and_closed(self):
        import broadcast_delivery_actor as mixed
        raw = mixed.signal(100, 'Resource', 'h', wire.u32(0), 1)
        # The broker forwards the original signal and adds the actual source.
        raw = wire.frame(4, 100, [(1, 'o', '/broadcast'), (2, 's', mixed.INTERFACE),
             (3, 's', 'Resource'), (8, 'g', 'h'), (9, 'u', 1), (7, 's', ':1.1')], wire.u32(0))
        self.transfer(raw)
        before = self.actor.fd_inventory()['count']
        source = type('Source', (), {'name': ':1.1'})()
        receipt = self.actor.receive_resource(self.client, source)
        self.assertTrue(receipt['closed'])
        self.assertEqual(receipt['contents_hex'], mixed.CONTENTS.hex())
        self.assertEqual(self.actor.fd_inventory()['count'], before)
        with self.assertRaises(OSError):
            os.fstat(receipt['fd'])

    def test_resource_wrong_content_is_rejected_and_closed(self):
        import broadcast_delivery_actor as mixed
        raw = wire.frame(4, 100, [(1, 'o', '/broadcast'), (2, 's', mixed.INTERFACE),
             (3, 's', 'Resource'), (8, 'g', 'h'), (9, 'u', 1), (7, 's', ':1.1')], wire.u32(0))
        self.transfer(raw, b'WRONG')
        before = self.actor.fd_inventory()['count']
        with self.assertRaises(AssertionError):
            self.actor.receive_resource(self.client, type('Source', (), {'name': ':1.1'})())
        self.assertEqual(self.actor.fd_inventory()['count'], before)

    def test_barrier_rejects_intervening_frame(self):
        self.right.sendall(wire.signal(100, count=None) + self.reply(serial=101))
        with self.assertRaises(AssertionError):
            self.actor.barrier(self.client, 101)
        self.assertEqual(self.events['received'][-1]['serial'], 100)

    def test_inventory_numeric_identity_and_no_fd_growth(self):
        first = self.actor.identity()
        second = self.actor.identity()
        self.assertEqual(first['pid'], os.getpid())
        self.assertEqual(first['uid'], os.getuid())
        self.assertEqual(first['fds'], second['fds'])
        self.assertTrue(all(isinstance(row['fd'], int) for row in first['fds']['targets']))
        self.assertTrue(first['process']['starttime_ticks'] > 0)

    def peer(self, role, name, events):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        client = self.actor.ObservedClient.__new__(self.actor.ObservedClient)
        client.configure(left, role, events)
        client.name, client.phase = name, 'active'
        client.negotiation = {'requested': role != 'ordinary', 'auth_reply': 'OK socketpair',
             'fd_reply': None if role == 'ordinary' else 'AGREE_UNIX_FD'}
        return client, right

    def named_health(self, name, serial):
        return wire.frame(2, 800 + serial, [(5, 'u', serial), (7, 's', 'org.freedesktop.DBus'),
             (6, 's', name), (8, 'g', 's')], wire.string(name))

    def named_barrier(self, name, serial):
        return wire.frame(2, 900 + serial, [(5, 'u', serial), (7, 's', 'org.freedesktop.DBus'),
             (6, 's', name), (8, 'g', 'as')], wire.u32(0))

    def session(self, case):
        session = self.actor.Workload('/run/osbus-fd-quotas/bus')
        peers = [self.peer(role, ':1.%d' % (index + 1), session.events)
                 for index, role in enumerate(('source', 'target', 'ordinary'))]
        session.clients = [client for client, _ in peers]
        session.case = case
        self.addCleanup(session.close)
        return session, [peer for _, peer in peers]

    def test_complete_unicast_exercise_and_close(self):
        session, peers = self.session('unicast')
        peers[0].sendall(self.error(destination=':1.1') + self.named_health(':1.1', 5))
        peers[2].sendall(self.named_health(':1.3', 4))
        result = session.exercise()
        self.assertEqual([row['serial'] for row in result['health']], [4, 5])
        self.assertEqual(result['assertions']['resource_deliveries'], 0)
        self.assertEqual(result['resources'][0]['contents_hex'], b'DO-NOT-DELIVER'.hex())
        packet = result['sent'][0]
        self.assertEqual(packet['wire_hex'], wire.frame(1, 3, [(1, 'o', '/foundation'),
             (2, 's', 'org.foundation.Transport'), (3, 's', 'Resource'), (6, 's', ':1.3'),
             (8, 'g', 'h'), (9, 'u', 1)], wire.u32(0)).hex())
        self.assertEqual(packet['rights'], 1)
        self.assertEqual(session.close()['connections'], [])

    def test_complete_mixed_exercise_strict_serials_resources_and_close(self):
        import array
        import broadcast_delivery_actor as mixed
        session, peers = self.session('mixed')
        peers[0].sendall(self.named_barrier(':1.1', 101) + self.named_health(':1.1', 110)
             + self.named_barrier(':1.1', 201) + self.named_health(':1.1', 210))
        resource = wire.frame(4, 100, [(1, 'o', '/broadcast'), (2, 's', mixed.INTERFACE),
             (3, 's', 'Resource'), (8, 'g', 'h'), (9, 'u', 1), (7, 's', ':1.1')], wire.u32(0))
        plain = wire.frame(4, 200, [(1, 'o', '/broadcast'), (2, 's', mixed.INTERFACE),
             (3, 's', 'Plain'), (8, 'g', 's'), (7, 's', ':1.1')], wire.string(mixed.PLAIN))
        fd = os.memfd_create('foundation-broadcast-%d' % os.getpid(), os.MFD_CLOEXEC)
        self.addCleanup(os.close, fd)
        os.write(fd, mixed.CONTENTS)
        peers[1].sendmsg([resource], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        peers[1].sendall(self.named_health(':1.2', 111) + plain + self.named_health(':1.2', 211))
        peers[2].sendall(self.named_health(':1.3', 112) + plain + self.named_health(':1.3', 212))
        result = session.exercise()
        self.assertEqual(result['assertions'], {'resource_deliveries': 1, 'rights0_deliveries': 2,
             'healthy_replies': 6, 'actor_fd_growth': 0, 'strict_first_message': True})
        self.assertEqual([row['serial'] for row in result['health']], [110, 111, 112, 210, 211, 212])
        self.assertEqual([row['serial'] for row in result['barriers']], [101, 201])
        self.assertEqual([row['serial'] for row in result['received']],
             [1001, 100, 910, 911, 912, 1101, 200, 200, 1010, 1011, 1012])
        self.assertTrue(all(row['closed'] for row in result['resources']))
        self.assertEqual(session.close()['connections'], [])

    def test_warmup_forwards_same_usable_right_then_closes(self):
        import array
        import threading
        import broadcast_delivery_actor as mixed
        session = self.actor.Workload('/run/osbus-fd-quotas/bus')
        peers = []
        clients = []
        failures = []
        def connect(role, negotiate=True):
            client, peer = self.peer(role, ':1.%d' % (len(clients) + 1), session.events)
            clients.append(client); peers.append(peer); session.clients.append(client)
            original_close = client.close
            def close_pair():
                original_close()
                peer.close()
            client.close = close_pair
            if role == 'target':
                def forward():
                    fds = []
                    try:
                        source = wire.Client.__new__(wire.Client)
                        source.sock = peers[0]
                        source.sock.settimeout(2)
                        message = source.receive()
                        fds = message['fds']
                        self.assertEqual(message['serial'], 100)
                        self.assertEqual(len(fds), 1)
                        packet = wire.frame(4, 100, [(1, 'o', '/broadcast'), (2, 's', mixed.INTERFACE),
                             (3, 's', 'Resource'), (8, 'g', 'h'), (9, 'u', 1),
                             (6, 's', ':1.2'), (7, 's', ':1.1')], wire.u32(0))
                        peers[1].sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
                        wire.close_fds(fds); fds = []
                        peers[0].sendall(self.named_health(':1.1', 110))
                        peers[1].sendall(self.named_health(':1.2', 111))
                    except BaseException as error:
                        failures.append(error)
                    finally:
                        wire.close_fds(fds)
                thread = threading.Thread(target=forward)
                threads.append(thread); thread.start()
            return client
        threads = []
        session.connect = connect
        # Close fixture server ends alongside their paired actor sockets.
        before = self.actor.fd_inventory()['count']
        result = session.warmup()
        for thread in threads:
            thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(result['usable_transfer'])
        self.assertEqual(result['connections'], [])
        self.assertEqual(result['resources'][0]['ino'], result['resources'][1]['ino'])
        self.assertTrue(all(row['closed'] for row in result['resources']))
        self.assertEqual(self.actor.fd_inventory()['count'], before)

    def test_health_absolute_deadline_is_fixed_at_1000ms(self):
        started = self.actor.time.monotonic()
        with self.assertRaises(TimeoutError):
            self.actor.healthy(self.client, 4)
        elapsed = (self.actor.time.monotonic() - started) * 1000
        self.assertGreaterEqual(elapsed, 900)
        self.assertLess(elapsed, 1400)
        self.assertEqual(self.client.sock.gettimeout(), 3)

    def test_bootstrap_auth_negotiation_and_nameacquired_filtering(self):
        import threading
        from unittest.mock import patch
        for negotiate in (True, False):
            with self.subTest(negotiate=negotiate):
                left, right = socket.socketpair()
                class Endpoint(socket.socket):
                    def connect(endpoint, address):
                        self.assertEqual(address, '/run/osbus-fd-quotas/bus')
                endpoint = Endpoint(fileno=left.detach())
                self.addCleanup(endpoint.close); self.addCleanup(right.close)
                failures = []
                auth_lines = []
                def server():
                    try:
                        right.settimeout(2)
                        def line():
                            result = b''
                            while not result.endswith(b'\r\n'):
                                piece = right.recv(1)
                                assert piece
                                result += piece
                            auth_lines.append(result)
                            return result
                        self.assertEqual(line(), b'\0AUTH EXTERNAL ' + str(os.getuid()).encode().hex().encode() + b'\r\n')
                        right.sendall(b'OK fixture-guid\r\n')
                        if negotiate:
                            self.assertEqual(line(), b'NEGOTIATE_UNIX_FD\r\n')
                            right.sendall(b'AGREE_UNIX_FD\r\n')
                        self.assertEqual(line(), b'BEGIN\r\n')
                        peer = wire.Client.__new__(wire.Client); peer.sock = right
                        hello = peer.receive()
                        self.assertEqual(hello['fields'].get(3), 'Hello')
                        acquired = wire.frame(4, 99, [(1, 'o', '/org/freedesktop/DBus'),
                             (2, 's', 'org.freedesktop.DBus'), (3, 's', 'NameAcquired'),
                             (8, 'g', 's'), (7, 's', 'org.freedesktop.DBus')], wire.string(':1.9'))
                        right.sendall(self.named_health(':1.9', 1) + acquired)
                        request = peer.receive()
                        self.assertEqual(request['fields'].get(3), 'ListNames')
                        right.sendall(self.named_barrier(':1.9', 2))
                    except BaseException as error:
                        failures.append(error)
                thread = threading.Thread(target=server); thread.start()
                try:
                    with patch.object(self.actor.wire.socket, 'socket', return_value=endpoint):
                        client = self.actor.ObservedClient('/run/osbus-fd-quotas/bus', 'source' if negotiate else 'ordinary', self.events, negotiate)
                    self.assertEqual(client.name, ':1.9')
                    self.assertEqual(client.receipt()['negotiated'], negotiate)
                    self.assertEqual(client.phase, 'active')
                    with self.assertRaises(AssertionError):
                        client.reply(2)
                    client.close()
                finally:
                    endpoint.close(); thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])

    def test_bootstrap_unexpected_rights_are_closed(self):
        self.client.phase = 'setup'
        self.transfer(wire.signal(100))
        self.right.sendall(self.reply())
        before = self.actor.fd_inventory()['count']
        with self.assertRaises(AssertionError):
            self.client.reply(4)
        self.assertEqual(self.actor.fd_inventory()['count'], before)

    def test_line_protocol_initial_eof_exit0_without_bus(self):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'actor.py'),
             '/run/osbus-fd-quotas/bus', str(WIRE)], input='', text=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertTrue(receipt['ok'])
        self.assertEqual(receipt['result']['connections'], [])
        self.assertEqual(receipt['result']['uid'], os.getuid())
        self.assertFalse(any(row['target'].startswith('socket:') for row in receipt['result']['fds']['targets']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
