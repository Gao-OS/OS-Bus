"""Independent FD09 actors; shared transport and quota helpers stay unchanged."""
import array
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

from transport import call, close_fds, frame, string, u32

WORKLOAD = json.loads(Path(__file__).with_name('workload.json').read_text())
BUS = 'org.freedesktop.DBus'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payload(serial, size):
    seed = ('fanout-%d|' % serial).encode()
    return (seed + bytes(range(256)) * ((size // 256) + 1))[:size]


def resource(serial):
    return ('fanout-resource-%d' % serial).encode()


def packet(serial, target=None, size=None, sender=None):
    size = WORKLOAD['accepted_payload_bytes'] if size is None else size
    fields = [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
              (3, 's', 'Hold')]
    if target is not None:
        fields.append((6, 's', target))
    if sender is not None:
        fields.append((7, 's', sender))
    fields += [(8, 'g', 'hay'), (9, 'u', 1)]
    data = payload(serial, size)
    return frame(4, serial, fields, u32(0) + u32(len(data)) + data)


def validate_resource(fd, serial):
    expected = resource(serial)
    info = os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_size == len(expected), 'wrong resource type/size'
    assert os.pread(fd, len(expected) + 1, 0) == expected, 'wrong or unusable resource'
    target = os.readlink('/proc/self/fd/%d' % fd)
    assert target == '/memfd:fanout-%d (deleted)' % serial, 'unexpected resource identity'
    return {'resource': expected.decode(), 'resource_sha256': digest(expected),
            'resource_target': target, 'fd_identity': '%d:%d' % (info.st_dev, info.st_ino)}


def validate_full(raw, fds, serial, sender, target=None, size=None):
    size = WORKLOAD['accepted_payload_bytes'] if size is None else size
    expected = packet(serial, target, size, sender)
    assert raw == expected, 'full wire frame mismatch'
    assert len(fds) == 1, 'missing or extra full-frame resource'
    body = u32(0) + u32(size) + payload(serial, size)
    return {'serial': serial, 'sender': sender, 'target': target,
            'wire_bytes': len(raw), 'encoded_bytes': len(expected),
            'wire_sha256': digest(raw), 'encoded_sha256': digest(expected),
            'body_sha256': digest(body), 'fds': 1, 'used': True,
            **validate_resource(fds[0], serial)}


def validate_partial(raw, fds, serial, sender, expected_offset):
    expected = packet(serial, sender=sender)
    header_size = struct.unpack_from('<I', expected, 12)[0]
    body_at = 16 + header_size + (-header_size % 8)
    assert body_at + 8 < len(raw) < len(expected), 'not an incomplete body-bearing frame'
    assert len(raw) == expected_offset and raw == expected[:len(raw)], 'partial wire bytes mismatch'
    assert len(fds) == 1, 'missing or extra partial-frame resource'
    return {'serial': serial, 'sender': sender, 'target': None,
            'wire_bytes': len(raw), 'encoded_bytes': len(expected),
            'prefix_sha256': digest(raw), 'encoded_sha256': digest(expected),
            'fds': 1, 'partial': True, 'eof': True,
            **validate_resource(fds[0], serial)}


class Workload:
    def __init__(self, path, role, quota_dir):
        spec = importlib.util.spec_from_file_location('fd09_quota_actor', Path(quota_dir) / 'actor.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.generic = module.Workload(path, role)
        self.fd_state = module.fd_state
        self.role = role
        self.held = None
        self.retained_reads = []
        self.serial = 20000

    @property
    def client(self):
        return self.generic.client

    def receive_raw(self):
        fds = []
        try:
            prefix = self.client.read(16, fds)
            assert prefix[:4] == b'l\x04\x00\x01', 'unexpected full-frame prefix'
            body_size, _, header_size = struct.unpack_from('<III', prefix, 4)
            assert body_size + header_size <= WORKLOAD['accepted_payload_bytes'] + 4096, 'oversized received frame'
            raw = prefix + self.client.read(header_size + (-header_size % 8) + body_size, fds)
            return raw, fds
        except BaseException:
            close_fds(fds)
            raise

    def read_deadline(self, length, fds, deadline):
        result = b''
        while len(result) < length:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'absolute diagnostic deadline'
            self.client.sock.settimeout(remaining)
            data, controls, flags, _ = self.client.sock.recvmsg(length - len(result), socket.CMSG_SPACE(253 * 4))
            for level, kind, rights in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                incoming = array.array('i')
                incoming.frombytes(rights)
                fds.extend(incoming)
            assert data and not flags & socket.MSG_CTRUNC, 'closed or truncated diagnostic frame'
            assert time.monotonic() <= deadline, 'absolute diagnostic deadline'
            result += data
        return result

    def diagnostic(self, op):
        self.serial += 1
        started = time.monotonic()
        deadline = started + WORKLOAD['healthy_ms'] / 1000
        previous_timeout = self.client.sock.gettimeout()
        previous_read = self.client.read
        reply = None
        try:
            # Send and receive both use the same original absolute deadline.
            self.client.sock.settimeout(max(deadline - time.monotonic(), .001))
            self.client.sock.sendall(call('ListNames', self.serial))
            self.client.read = lambda length, fds: self.read_deadline(length, fds, deadline)
            reply = self.client.receive()
            assert reply['type'] == 2 and reply['fields'].get(5) == self.serial, 'extra or unexpected fence frame'
            assert reply['fields'].get(7) == BUS and not reply['fds'], 'untrusted or resource-bearing fence reply'
            elapsed = (time.monotonic() - started) * 1000
            assert elapsed <= WORKLOAD['healthy_ms'], 'absolute diagnostic deadline'
            return {'serial': self.serial, 'reply_serial': reply['fields'][5],
                    'sender': reply['fields'][7], 'latency_ms': elapsed,
                    'name': self.client.name, 'fds': 0, 'strict_fence': True}
        finally:
            if reply is not None:
                close_fds(reply['fds'])
            self.client.read = previous_read
            self.client.sock.settimeout(previous_timeout)

    def command(self, row):
        op = row['op']
        if op in ('connect', 'close', 'fds'):
            if op in ('connect', 'close'):
                assert self.held is None, 'retained FD closed before both kill checks'
            return self.generic.command(row)
        assert self.client is not None
        if op in ('barrier', 'health'):
            return self.diagnostic(op)
        if op == 'send':
            assert self.role == 'source'
            serial, size = row['serial'], row.get('size', WORKLOAD['accepted_payload_bytes'])
            assert size == WORKLOAD['accepted_payload_bytes'], 'workload size changed'
            encoded = packet(serial, row.get('target'), size)
            fd = os.memfd_create('fanout-%d' % serial, os.MFD_CLOEXEC)
            try:
                assert os.write(fd, resource(serial)) == len(resource(serial))
                identity = validate_resource(fd, serial)['fd_identity']
                self.client.send_fds(encoded, [fd])
            finally:
                os.close(fd)
            return {'serial': serial, 'target': row.get('target'), 'payload_bytes': size,
                    'fd_identity': identity, 'source_closed': True,
                    'after_send': self.fd_state()}
        if op == 'subscribe':
            assert self.role in ('fast', 'slow')
            self.serial += 1
            self.client.sock.sendall(call('AddMatch', self.serial, 's', string(WORKLOAD['match_rule'])))
            reply = self.client.receive()
            try:
                assert reply['type'] == 2 and reply['fields'].get(5) == self.serial
                assert reply['fields'].get(7) == BUS and not reply['fds']
            finally:
                close_fds(reply['fds'])
            return {'subscribed': True, 'rule': WORKLOAD['match_rule'], 'name': self.client.name}
        if op in ('warm', 'receive_hold'):
            assert self.held is None
            if op == 'receive_hold':
                assert self.role == 'fast' and row['serial'] == WORKLOAD['broadcast_serial']
            raw, fds = self.receive_raw()
            try:
                target = self.client.name if op == 'warm' else None
                result = validate_full(raw, fds, row['serial'], row['sender'], target)
                if op == 'receive_hold':
                    self.held = {'fd': fds[0], **result}
                    fds = []
                    result.update(held_fd=True, after_receive=self.fd_state())
                    return result
            finally:
                close_fds(fds)
            return {**result, 'held_fd': False, 'after_close': self.fd_state()}
        if op == 'verify_held':
            assert self.held is not None, 'retained FD missing'
            assert len(self.retained_reads) < 2 and row['stage'] == ('after_source', 'after_slow')[len(self.retained_reads)], 'retained reads out of order'
            result = validate_resource(self.held['fd'], self.held['serial'])
            assert result['fd_identity'] == self.held['fd_identity'], 'retained resource identity changed'
            self.retained_reads.append(row['stage'])
            return {'stage': row['stage'], 'serial': self.held['serial'], 'fds': 1,
                    'held_fd': True, **result, 'fd_state': self.fd_state()}
        if op == 'release_held':
            assert self.held is not None and self.retained_reads == ['after_source', 'after_slow'], 'retained FD released prematurely'
            identity = self.held['fd_identity']
            os.close(self.held['fd'])
            self.held = None
            return {'held_fd': False, 'fd_identity': identity, 'fd_state': self.fd_state()}
        if op == 'partial':
            assert self.role == 'slow' and row['serial'] == WORKLOAD['broadcast_serial']
            raw, fds = b'', []
            deadline = time.monotonic() + WORKLOAD['cleanup_ms'] / 1000
            previous_timeout = self.client.sock.gettimeout()
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0, 'recipient EOF deadline'
                    self.client.sock.settimeout(remaining)
                    data, controls, flags, _ = self.client.sock.recvmsg(65536, socket.CMSG_SPACE(16 * 4))
                    for level, kind, rights in controls:
                        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                        incoming = array.array('i')
                        incoming.frombytes(rights)
                        fds.extend(incoming)
                    assert not flags & socket.MSG_CTRUNC, 'truncated rights'
                    assert len(fds) <= 1, 'duplicate or extra rights'
                    assert time.monotonic() <= deadline, 'recipient EOF deadline'
                    if not data:
                        break
                    raw += data
                    assert len(raw) <= WORKLOAD['accepted_payload_bytes'] + 4096, 'extra partial bytes/messages'
                result = validate_partial(raw, fds, row['serial'], row['sender'], row['offset'])
            finally:
                close_fds(fds)
                self.client.sock.settimeout(previous_timeout)
            return {**result, 'after_close': self.fd_state()}
        if op == 'eof':
            assert self.client.sock.recv(1) == b'', 'killed source socket still open'
            return {'eof': True}
        raise AssertionError(row)

    def shutdown(self):
        if self.held is not None:
            os.close(self.held['fd'])
            self.held = None
        if self.client is not None:
            self.client.close()
            self.generic.client = None


def main():
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    path, role, quota_dir = sys.argv[1:]
    assert path == '/run/osbus-fd-quotas/bus'
    assert os.getuid() == WORKLOAD['roles'][role]
    worker = Workload(path, role, quota_dir)
    print(json.dumps({'ok': True, 'result': {'pid': os.getpid(), 'uid': os.getuid(),
                     'gid': os.getgid(), 'role': role, **worker.fd_state()}}), flush=True)
    try:
        for line in sys.stdin:
            try:
                response = {'ok': True, 'result': worker.command(json.loads(line))}
            except Exception as error:
                response = {'ok': False, 'result': None, 'error': repr(error)}
            print(json.dumps(response), flush=True)
    finally:
        worker.shutdown()


if __name__ == '__main__':
    main()
