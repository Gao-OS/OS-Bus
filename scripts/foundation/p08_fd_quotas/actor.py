"""One independent kernel-credential client; readonly sustained framing helpers."""
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

from transport import Client, call, close_fds, frame, u32

WORKLOAD = json.loads(Path(__file__).with_name('workload.json').read_text())
BUS = 'org.freedesktop.DBus'


def payload(serial, size):
    seed = ('quota-%d|' % serial).encode()
    return (seed + bytes(range(256)) * ((size // 256) + 1))[:size]


def resource(serial):
    return ('quota-resource-%d' % serial).encode()


def packet(serial, target, size, sender=None, denied=False):
    fields = [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
              (3, 's', 'Hold'), (6, 's', target)]
    if sender is not None:
        fields.append((7, 's', sender))
    fields += [(8, 'g', 'hay'), (9, 'u', 1)]
    data = payload(serial, size)
    return frame(1 if denied else 4, serial, fields, u32(0) + u32(len(data)) + data)


def fd_state():
    targets = []
    for entry in (Path('/proc') / str(os.getpid()) / 'fd').iterdir():
        try:
            targets.append(os.readlink(entry))
        except FileNotFoundError:
            pass
    return {'fds': len(targets), 'memfds': sorted(x for x in targets if '/memfd:' in x)}


def validate_partial(raw, fds, serial, target, sender, expected_offset):
    expected = packet(serial, target, WORKLOAD['accepted_payload_bytes'], sender)
    header_size = struct.unpack_from('<I', expected, 12)[0]
    body_at = 16 + header_size + (-header_size % 8)
    assert body_at + 8 < len(raw) < len(expected), 'not an incomplete body-bearing frame'
    assert len(raw) == expected_offset and raw == expected[:len(raw)], 'partial wire bytes mismatch'
    assert len(fds) == 1, 'missing or leaked rejected resource'
    assert os.pread(fds[0], 4096, 0) == resource(serial), 'wrong or unusable resource'
    fd_target = os.readlink('/proc/self/fd/%d' % fds[0])
    assert fd_target == '/memfd:quota-%d (deleted)' % serial, 'unexpected resource identity'
    return {'serial': serial, 'sender': sender, 'target': target, 'wire_bytes': len(raw),
            'encoded_bytes': len(expected), 'prefix_sha256': hashlib.sha256(raw).hexdigest(),
            'encoded_sha256': hashlib.sha256(expected).hexdigest(), 'fds': 1,
            'resource': resource(serial).decode(), 'resource_target': fd_target,
            'partial': True, 'eof': True}


class Workload:
    def __init__(self, path, role):
        self.path, self.role, self.client = path, role, None
        self.serial = 10000

    def command(self, row):
        op = row['op']
        if op == 'connect':
            assert self.client is None
            self.client = Client(self.path)
            return {'name': self.client.name, 'negotiated': True, **fd_state()}
        if op == 'close':
            self.client.close()
            self.client = None
            return fd_state()
        if op == 'fds':
            return fd_state()
        assert self.client is not None
        if op == 'send':
            serial, denied = row['serial'], row.get('denied', False)
            size = WORKLOAD['denied_payload_bytes'] if denied else WORKLOAD['accepted_payload_bytes']
            fd = os.memfd_create('quota-%d' % serial, os.MFD_CLOEXEC)
            try:
                os.write(fd, resource(serial))
                self.client.send_fds(packet(serial, row['target'], size, denied=denied), [fd])
            finally:
                os.close(fd)
            result = {'serial': serial, 'payload_bytes': size}
            if denied:
                reply = self.client.reply(serial)
                try:
                    assert reply['type'] == 3 and reply['fields'][4] == BUS + '.Error.LimitsExceeded', reply
                    assert reply['fields'][5] == serial and not reply['fds'], reply
                    result.update(error=reply['fields'][4], reply_serial=reply['fields'][5])
                finally:
                    close_fds(reply['fds'])
            return result
        if op == 'barrier' or op == 'health':
            self.serial += 1
            started = time.monotonic()
            previous_timeout = self.client.sock.gettimeout()
            if op == 'health':
                self.client.sock.settimeout(WORKLOAD['healthy_ms'] / 1000)
            # A real on-wire source fence precedes every daemon trace snapshot.
            self.client.sock.sendall(call('ListNames', self.serial))
            reply = None
            try:
                while True:
                    if op == 'health':
                        remaining = WORKLOAD['healthy_ms'] / 1000 - (time.monotonic() - started)
                        assert remaining > 0, 'absolute diagnostic deadline'
                        self.client.sock.settimeout(remaining)
                    reply = self.client.receive()
                    if reply['fields'].get(5) == self.serial:
                        break
                    try:
                        assert not reply['fds'], 'unexpected diagnostic-path resource'
                    finally:
                        close_fds(reply['fds'])
                        reply = None
                assert reply['type'] == 2 and reply['fields'][5] == self.serial, reply
                assert reply['fields'][7] == BUS and not reply['fds'], 'untrusted or resource-bearing diagnostic reply'
                elapsed = (time.monotonic() - started) * 1000
                if op == 'health':
                    assert elapsed <= WORKLOAD['healthy_ms'], 'absolute diagnostic deadline'
                return {'serial': self.serial, 'reply_serial': reply['fields'][5],
                        'sender': reply['fields'][7], 'latency_ms': elapsed,
                        'name': self.client.name, 'fds': len(reply['fds'])}
            finally:
                if reply:
                    close_fds(reply['fds'])
                self.client.sock.settimeout(previous_timeout)
        if op == 'warm':
            message = self.client.receive()
            try:
                serial = row['serial']
                assert message['type'] == 4 and message['serial'] == serial
                assert message['fields'][7] == row['sender'] and message['fields'][3] == 'Hold'
                assert message['fields'][8] == 'hay' and len(message['fds']) == 1
                assert message['body'] == u32(0) + u32(WORKLOAD['accepted_payload_bytes']) + payload(serial, WORKLOAD['accepted_payload_bytes'])
                assert os.pread(message['fds'][0], 4096, 0) == resource(serial)
                assert os.readlink('/proc/self/fd/%d' % message['fds'][0]) == '/memfd:quota-%d (deleted)' % serial
                return {'serial': serial, 'fds': 1, 'used': True}
            finally:
                close_fds(message['fds'])
        if op == 'eof':
            assert self.client.sock.recv(1) == b'', 'killed source socket still open'
            return {'eof': True}
        if op == 'partial':
            raw, fds = b'', []
            deadline = time.monotonic() + WORKLOAD['cleanup_ms'] / 1000
            try:
                while True:
                    self.client.sock.settimeout(max(deadline - time.monotonic(), .001))
                    data, controls, flags, _ = self.client.sock.recvmsg(65536, socket.CMSG_SPACE(16 * 4))
                    assert not flags & socket.MSG_CTRUNC, 'truncated rights'
                    for level, kind, rights in controls:
                        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                        incoming = array.array('i')
                        incoming.frombytes(rights)
                        fds.extend(incoming)
                    if not data:
                        break
                    raw += data
                    assert len(raw) <= WORKLOAD['accepted_payload_bytes'] + 4096
                    assert time.monotonic() < deadline, 'recipient EOF deadline'
                result = validate_partial(raw, fds, row['serial'], self.client.name,
                                          row['sender'], row['offset'])
            finally:
                close_fds(fds)
            result['after_close'] = fd_state()
            return result
        raise AssertionError(row)


def main():
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    path, role = sys.argv[1:]
    assert path == '/run/osbus-fd-quotas/bus'
    assert os.getuid() == WORKLOAD['roles'][role]
    worker = Workload(path, role)
    print(json.dumps({'ok': True, 'result': {'pid': os.getpid(), 'uid': os.getuid(),
                     'gid': os.getgid(), 'role': role, **fd_state()}}), flush=True)
    try:
        for line in sys.stdin:
            try:
                result = worker.command(json.loads(line))
                response = {'ok': True, 'result': result}
            except Exception as error:
                response = {'ok': False, 'error': repr(error)}
            print(json.dumps(response), flush=True)
    finally:
        if worker.client:
            worker.client.close()


if __name__ == '__main__':
    main()
