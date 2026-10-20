"""Independent FD01 singleton actor; Python Linux socket/SCM_RIGHTS fixture."""
import array
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import time

BUS = 'org.freedesktop.DBus'
SOCKET_MS, WRITER_MS, HEALTH_MS, CLEANUP_MS = 3000, 5000, 1000, 1000


def load_wire(directory):
    path = Path(directory) / 'transport_actor.py'
    spec = importlib.util.spec_from_file_location('fd01_unchanged_wire', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fd_record(fd):
    target = os.readlink('/proc/self/fd/%d' % fd)
    info = os.fstat(fd)
    return {'fd': fd, 'target': target,
            'dev': info.st_dev, 'ino': info.st_ino, 'mode': info.st_mode,
            'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid()}


def fd_state():
    records = []
    for name in sorted(os.listdir('/proc/self/fd'), key=int):
        try:
            records.append(fd_record(int(name)))
        except FileNotFoundError:
            pass  # The directory iterator itself has already closed.
    return {'fds': records, 'count': len(records)}


def identity():
    return {'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
            'native_fixture': 'Python Linux socket/SCM_RIGHTS'}


class DeadlineSocket:
    def __init__(self, client, raw):
        self.client, self.raw = client, raw

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def bounded(self):
        if self.client.deadline_at is not None:
            remaining = self.client.deadline_at - time.monotonic()
            assert remaining > 0, 'absolute actor socket deadline'
            self.raw.settimeout(remaining)

    def recv(self, length):
        self.bounded()
        return self.raw.recv(length)

    def recvmsg(self, *args):
        self.bounded()
        data, controls, flags, address = self.raw.recvmsg(*args)
        self.client.capture.extend(data)
        installed = []
        try:
            for level, kind, rights in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS), 'unexpected ancillary control'
                incoming = array.array('i')
                incoming.frombytes(rights)
                installed.extend(incoming)
            self.client.received_targets.extend(fd_record(fd) for fd in installed)
            assert data and not flags & socket.MSG_CTRUNC, 'closed or truncated actor frame'
        except BaseException:
            self.client.wire.close_fds(installed)
            raise
        return data, controls, flags, address

    def sendall(self, data):
        self.bounded()
        raw = data[7:] if data.startswith(b'BEGIN\r\n') else data
        if self.client.phase == 'setup' and raw.startswith(b'l'):
            member, serial = ('Hello', 1) if data.startswith(b'BEGIN\r\n') else ('ListNames', 2)
            assert raw == self.client.wire.call(member, serial), 'unexpected setup writer frame'
            self.client.events.append({'role': self.client.role, 'phase': 'setup', 'direction': 'sent',
                'type': 1, 'serial': serial, 'fields': {1: '/org/freedesktop/DBus',
                    2: BUS, 3: member, 6: BUS, 8: ''}, 'body_hex': '',
                'wire_hex': raw.hex(), 'wire_sha256': digest(raw), 'wire_bytes': len(raw), 'rights': 0})
        return self.raw.sendall(data)

    def sendmsg(self, *args):
        self.bounded()
        return self.raw.sendmsg(*args)


class Client:
    def __init__(self, raw, role, wire):
        self.role, self.wire = role, wire
        self.phase, self.name = 'setup', None
        self.events, self.capture, self.received_targets = [], bytearray(), []
        self.deadline_at = None
        self.negotiation = {'requested': True, 'auth_reply': None, 'fd_reply': None}
        if raw is not None:
            raw.settimeout(SOCKET_MS / 1000)
            self.sock = raw

    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, raw):
        self._sock = DeadlineSocket(self, raw)

    @classmethod
    def connect(cls, path, role, wire):
        client = cls(None, role, wire)
        try:
            with client.deadline(SOCKET_MS):
                wire.Client.__init__(client, path, True)
            assert client.name.startswith(':'), 'not a unique bus identity'
            client.phase = 'active'
            return client
        except BaseException:
            if hasattr(client, '_sock'):
                client.close()
            raise

    @contextmanager
    def deadline(self, milliseconds):
        previous = self.deadline_at
        end = time.monotonic() + milliseconds / 1000
        self.deadline_at = end if previous is None else min(previous, end)
        try:
            yield
            assert time.monotonic() <= self.deadline_at, 'absolute actor socket deadline'
        finally:
            self.deadline_at = previous
            if hasattr(self, '_sock'):
                self.sock.settimeout(SOCKET_MS / 1000)

    def line(self):
        raw = self.wire.Client.line(self)
        if raw.startswith(b'OK '):
            self.negotiation['auth_reply'] = raw.decode().rstrip('\r\n')
        elif raw == b'AGREE_UNIX_FD\r\n':
            self.negotiation['fd_reply'] = raw.decode().rstrip('\r\n')
        return raw

    def read(self, length, fds):
        return self.wire.Client.read(self, length, fds)

    def receive(self):
        self.capture, self.received_targets = bytearray(), []
        event = {'role': self.role, 'phase': self.phase, 'direction': 'received'}
        try:
            with self.deadline(SOCKET_MS):
                message = self.wire.Client.receive(self)
            event.update(type=message['type'], serial=message['serial'], fields=message['fields'],
                         body_hex=message['body'].hex(), rights=len(message['fds']))
            return message
        except BaseException as error:
            event.update(error=repr(error), rights=len(self.received_targets))
            raise
        finally:
            event.update(wire_hex=self.capture.hex(), wire_sha256=digest(self.capture),
                         wire_bytes=len(self.capture), fd_targets=self.received_targets.copy())
            self.events.append(event)

    def reply(self, serial):
        assert self.phase == 'setup', 'permissive active reply read forbidden'
        while True:
            message = self.receive()
            try:
                assert not message['fds'], 'resource-bearing setup message'
                if message['fields'].get(5) == serial:
                    return message
            finally:
                self.wire.close_fds(message['fds'])

    def barrier(self, serial):
        assert self.phase == 'setup', 'setup barrier used after activation'
        return self.wire.Client.barrier(self, serial)

    def send_fds(self, data, fds):
        with self.deadline(WRITER_MS):
            return self.wire.Client.send_fds(self, data, fds)

    def close(self):
        self.sock.close()

    def receipt(self):
        return {**identity(), 'role': self.role, 'name': self.name,
                'socket_fd': self.sock.fileno(), 'socket': fd_record(self.sock.fileno()),
                'negotiated': self.negotiation['fd_reply'] == 'AGREE_UNIX_FD',
                'negotiation': self.negotiation.copy(),
                'setup': [row for row in self.events if row['phase'] == 'setup']}


def read_payload(fd):
    deadline, content = time.monotonic() + SOCKET_MS / 1000, b''
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, 'absolute resource pipe deadline'
        readable, _, _ = select.select([fd], [], [], remaining)
        assert readable, 'absolute resource pipe deadline'
        piece = os.read(fd, 5 - len(content))
        if not piece:
            break
        content += piece
        assert len(content) <= 4, 'resource content mismatch'
    assert time.monotonic() <= deadline, 'absolute resource pipe deadline'
    assert content == b'PIPE', 'resource content mismatch'
    return content


def validate_transfer(client, message, sender, source_fd):
    fields = message['fields']
    assert bytes.fromhex(client.events[-1]['wire_hex'])[:4] == b'l\x04\x00\x01', 'invalid Resource fixed header'
    assert message['type'] == 4 and message['serial'] == 100, 'unexpected first active resource frame'
    assert fields.get(1) == '/foundation' and fields.get(2) == 'org.foundation.Transport'
    assert fields.get(3) == 'Resource' and fields.get(6) == client.name and fields.get(7) == sender
    assert fields.get(8) == 'h' and fields.get(9) == 1 and message['body'] == client.wire.u32(0)
    assert len(message['fds']) == 1, 'resource right count mismatch'
    source, received = map(fd_record, (source_fd, message['fds'][0]))
    assert all(stat.S_ISFIFO(row['mode']) for row in (source, received)), 'wrong resource kind'
    assert (source['dev'], source['ino'], source['mode'], source['target']) == (
        received['dev'], received['ino'], received['mode'], received['target']), 'transferred endpoint identity mismatch'
    # Duplicated pipe readers share the stream: only the received right reads.
    content = read_payload(message['fds'][0])
    return {'serial': 100, 'sender': sender, 'target': client.name, 'signature': 'h',
            'index': 0, 'header9': 1, 'rights': 1, 'content': content.decode(),
            'content_hex': content.hex(), 'content_sha256': digest(content),
            'source_fd': source, 'received_fd': received,
            'received': client.events[-1].copy()}


def close_descriptor(role, fd, close):
    row = {'role': role, **fd_record(fd)}
    close()
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == 9, 'unexpected descriptor close outcome'
        row['closed'] = True
    else:
        raise AssertionError('owned descriptor remained open')
    return row


def healthy(client, serial):
    started = time.monotonic()
    message = None
    with client.deadline(HEALTH_MS):
        try:
            sent = client.wire.call('GetNameOwner', serial, 's', client.wire.string(client.name))
            client.sock.sendall(sent)
            message = client.receive()
            fields = message['fields']
            assert message['type'] == 2 and fields.get(5) == serial, 'unexpected first healthy frame'
            assert fields.get(7) == BUS and fields.get(6) == client.name, 'untrusted healthy identity'
            assert fields.get(8) == 's' and fields.get(9, 0) == 0 and not message['fds']
            assert message['body'] == client.wire.string(client.name), 'GetNameOwner content mismatch'
        finally:
            if message is not None:
                client.wire.close_fds(message['fds'])
    return {'role': client.role, 'serial': serial, 'reply_serial': fields[5], 'owner': client.name,
            'rights': 0, 'latency_ms': (time.monotonic() - started) * 1000,
            'sent': {'role': client.role, 'phase': 'active', 'direction': 'sent',
                     'type': 1, 'serial': serial, 'fields': {1: '/org/freedesktop/DBus',
                         2: BUS, 3: 'GetNameOwner', 6: BUS, 8: 's'},
                     'body_hex': client.wire.string(client.name).hex(),
                     'wire_hex': sent.hex(), 'wire_sha256': digest(sent), 'wire_bytes': len(sent), 'rights': 0},
            'received': client.events[-1].copy()}


class Workload:
    def __init__(self, path, wire):
        self.path, self.wire = path, wire
        self.clients, self.original_fd, self.received_fd = {}, None, None
        self.baseline = fd_state()
        self.state = 'initial'

    def open(self):
        assert not self.clients and self.original_fd is None and self.received_fd is None
        try:
            for role in ('source', 'target'):
                self.clients[role] = Client.connect(self.path, role, self.wire)
        except BaseException:
            self.close('open-error')
            raise
        self.state = 'open'
        return {'op': 'open', **identity(), **{r: c.receipt() for r, c in self.clients.items()},
                'connections': [c.receipt() for c in self.clients.values()], 'fd_state': fd_state()}

    def exercise(self):
        assert self.state == 'open' and set(self.clients) == {'source', 'target'}, 'exercise requires open'
        assert self.original_fd is None and self.received_fd is None, 'only one live resource permitted'
        source, target = self.clients['source'], self.clients['target']
        self.original_fd, writer = os.pipe()
        try:
            os.set_blocking(writer, False)
            written = os.write(writer, b'PIPE')
            assert written == 4, 'short pipe write'
        finally:
            writer_close = close_descriptor('writer', writer, lambda: os.close(writer))
        packet = self.wire.signal(100, target.name, 1, self.wire.u32(0), 'h')
        try:
            source.send_fds(packet, [self.original_fd])
            message = target.receive()  # No filtering, skipping or reply helper.
            assert len(message['fds']) == 1, 'resource right count mismatch'
            self.received_fd = message['fds'][0]
            transfer = validate_transfer(target, message, source.name, self.original_fd)
            transfer.update(written_bytes=written, writer_close=writer_close)
            transfer['sent'] = {'role': 'source', 'phase': 'active', 'direction': 'sent', 'type': 4, 'serial': 100,
                'fields': {'1': '/foundation', '2': 'org.foundation.Transport', '3': 'Resource',
                           '6': target.name, '8': 'h', '9': 1},
                'body_hex': self.wire.u32(0).hex(), 'wire_hex': packet.hex(),
                'wire_sha256': digest(packet), 'wire_bytes': len(packet), 'rights': 1}
            health = [healthy(source, 110), healthy(target, 111)]
        except BaseException:
            if 'message' in locals() and self.received_fd is None:
                self.wire.close_fds(message['fds'])
            raise
        self.state = 'checked'
        return {'op': 'exercise', **identity(), 'transfer': transfer, 'health': health,
                'held': True, 'connections': [c.receipt() for c in self.clients.values()], 'fd_state': fd_state()}

    def close(self, op):
        started, closure = time.monotonic(), []
        events = {role: client.events.copy() for role, client in self.clients.items()}
        owners = []
        if self.received_fd is not None:
            owners.append(('received', self.received_fd, lambda: os.close(self.received_fd)))
        if self.original_fd is not None:
            owners.append(('original', self.original_fd, lambda: os.close(self.original_fd)))
        owners.extend((role, client.sock.fileno(), client.close) for role, client in self.clients.items())
        for role, fd, close in owners:
            closure.append(close_descriptor(role, fd, close))
        self.received_fd, self.original_fd, self.clients = None, None, {}
        self.state = 'closed'
        after = fd_state()
        elapsed = (time.monotonic() - started) * 1000
        assert elapsed <= CLEANUP_MS, 'absolute actor cleanup deadline'
        return {'op': op, **identity(), 'closure': closure, 'connections': [], 'held': False,
                'events': events,
                'fd_state': after, 'fd_growth': after['count'] - self.baseline['count'],
                'baseline_equal': after == self.baseline, 'latency_ms': elapsed}

    def command(self, row):
        assert set(row) == {'op'}, 'unexpected actor command fields'
        op = row['op']
        if op == 'warmup':
            assert self.state == 'initial', 'warmup is first and cannot repeat'
            self.open()
            transfer = self.exercise()
            closed = self.close('warmup-close')
            assert closed['baseline_equal'] and closed['fd_growth'] == 0, 'warmup leaked actor descriptors'
            self.baseline = fd_state()
            self.state = 'warmed'
            return {'op': op, **identity(), 'exercise': transfer, 'close': closed,
                    'connections': [], 'held': False, 'fd_state': self.baseline, 'fd_growth': 0}
        if op == 'open':
            assert self.state == 'warmed', 'open requires completed warmup'
            return self.open()
        if op == 'exercise':
            return self.exercise()
        if op == 'close':
            assert self.state in ('open', 'checked'), 'close requires open connections'
            result = self.close(op)
            assert result['baseline_equal'] and result['fd_growth'] == 0, 'actor descriptors not reclaimed'
            return result
        raise AssertionError('unknown actor operation: %r' % op)


def serve(worker, input_stream, output_stream):
    try:
        for line in input_stream:
            try:
                result = worker.command(json.loads(line))
                response = {'ok': True, 'result': result}
            except Exception as error:
                response = {'ok': False, 'error': repr(error), 'cleanup': worker.close('error')}
            print(json.dumps(response), file=output_stream, flush=True)
    finally:
        result = worker.close('eof')
        response = {'ok': result['baseline_equal'] and result['fd_growth'] == 0, 'result': result}
        if not response['ok']:
            response['error'] = 'EOF actor descriptors not reclaimed'
        print(json.dumps(response), file=output_stream, flush=True)


def main():
    assert len(sys.argv) == 3
    path, directory = sys.argv[1:]
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert path == '/run/osbus-fd-quotas/bus' and os.getuid() == 1100
    worker = Workload(path, load_wire(directory))
    print(json.dumps({'ok': True, 'result': {**identity(), 'op': 'ready',
          'fd_state': worker.baseline, 'connections': []}}), flush=True)
    serve(worker, sys.stdin, sys.stdout)


if __name__ == '__main__':
    main()
