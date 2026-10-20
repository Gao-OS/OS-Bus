"""VM-only raw actor: independently constructs the small tested D-Bus corpus."""
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import time

BUS = 'org.freedesktop.DBus'


def signatures(signature):
    return {'': [], 's': ['s'], 'u': ['u'], 'b': ['b'], 'ss': ['s', 's'],
            'sss': ['s', 's', 's'], 'su': ['s', 'u'], 'as': ['as'], 'asu': ['as', 'u'],
            'a{ss}': ['a{ss}']}[signature]


def pad(data, alignment):
    data.extend(b'\0' * (-len(data) % alignment))


def encode_value(data, kind, value):
    if kind in ('s', 'o'):
        pad(data, 4)
        raw = value.encode()
        data.extend(struct.pack('<I', len(raw)) + raw + b'\0')
    elif kind == 'g':
        raw = value.encode()
        data.extend(bytes([len(raw)]) + raw + b'\0')
    elif kind in ('u', 'b'):
        pad(data, 4)
        data.extend(struct.pack('<I', int(value)))
    elif kind in ('as', 'a{ss}'):
        pad(data, 4)
        length_at = len(data)
        data.extend(b'\0' * 4)
        if kind == 'a{ss}':
            pad(data, 8)
        start = len(data)
        for item in value:
            if kind == 'as':
                encode_value(data, 's', item)
            else:
                pad(data, 8)
                encode_value(data, 's', item[0])
                encode_value(data, 's', item[1])
        struct.pack_into('<I', data, length_at, len(data) - start)
    else:
        raise AssertionError(('unsupported fixture type', kind))


def packet(serial, member=None, signature='', body=(), destination=BUS,
           path='/org/freedesktop/DBus', interface=BUS, message_type=1, reply_serial=None, sender=None):
    fields = [(1, 'o', path), (2, 's', interface), (3, 's', member),
              (5, 'u', reply_serial), (6, 's', destination), (7, 's', sender), (8, 'g', signature or None)]
    headers = bytearray()
    for code, kind, value in fields:
        if value is not None:
            pad(headers, 8)
            headers.append(code)
            encode_value(headers, 'g', kind)
            encode_value(headers, kind, value)
    payload = bytearray()
    types = signatures(signature)
    assert len(types) == len(body)
    for kind, value in zip(types, body):
        encode_value(payload, kind, value)
    prefix = struct.pack('<BBBBIII', ord('l'), message_type, 0, 1, len(payload), serial, len(headers))
    pad(headers, 8)
    return prefix + headers + payload


def decode_value(data, offset, kind, endian):
    if kind == 'g':
        size = data[offset]
        start = offset + 1
        assert data[start + size] == 0
        return data[start:start + size].decode(), start + size + 1
    offset += -offset % 4
    size = struct.unpack_from(endian + 'I', data, offset)[0]
    offset += 4
    if kind in ('u', 'b'):
        return (bool(size) if kind == 'b' else size), offset
    if kind in ('s', 'o'):
        assert data[offset + size] == 0
        return data[offset:offset + size].decode(), offset + size + 1
    assert kind == 'as', ('unsupported response fixture type', kind)
    end = offset + size
    items = []
    while offset < end:
        value, offset = decode_value(data, offset, 's', endian)
        items.append(value)
    assert offset == end
    return items, offset


class Client:
    def __init__(self, path):
        assert path.startswith('/run/osbus-security/') and '/..' not in path
        self.path = path
        self.socket = None
        self.buffer = b''
        self.serial = 0
        self.pending = []

    def exact(self, size):
        while len(self.buffer) < size:
            piece = self.socket.recv(size - len(self.buffer))
            assert piece, 'peer closed'
            self.buffer += piece
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    def line(self):
        while b'\r\n' not in self.buffer:
            piece = self.socket.recv(4096)
            assert piece, 'authentication closed'
            self.buffer += piece
        line, self.buffer = self.buffer.split(b'\r\n', 1)
        return line

    def message(self):
        prefix = self.exact(16)
        endian = '<' if prefix[0] == ord('l') else '>'
        assert prefix[0] in (ord('l'), ord('B')) and prefix[3] == 1
        body_size, serial, header_size = struct.unpack_from(endian + 'III', prefix, 4)
        assert body_size + header_size <= 1_048_576
        headers = self.exact(header_size + -header_size % 8)[:header_size]
        fields = {}
        offset = 0
        while offset < len(headers):
            offset += -offset % 8
            if offset == len(headers):
                break
            code = headers[offset]
            kind, offset = decode_value(headers, offset + 1, 'g', endian)
            fields[code], offset = decode_value(headers, offset, kind, endian)
        payload = self.exact(body_size)
        values, offset = [], 0
        for kind in signatures(fields.get(8, '')):
            value, offset = decode_value(payload, offset, kind, endian)
            values.append(value)
        assert offset == body_size
        return dict(type=prefix[1], serial=serial, reply_serial=fields.get(5),
                    error=fields.get(4), sender=fields.get(7), interface=fields.get(2),
                    member=fields.get(3), body=values)

    def reply(self, serial):
        deadline = time.monotonic() + 3
        while True:
            assert time.monotonic() < deadline, 'reply deadline'
            self.socket.settimeout(max(deadline - time.monotonic(), 0.001))
            message = self.message()
            if message['reply_serial'] == serial:
                return message
            self.pending.append(message)

    def authenticate(self, flow='plain'):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(3)
        self.socket.connect(self.path)
        auth = b'\0AUTH EXTERNAL ' + str(os.getuid()).encode().hex().encode() + b'\r\n'
        self.serial = 1
        if flow == 'pipeline':
            self.socket.sendall(auth + b'BEGIN\r\n' + packet(1, 'Hello'))
            assert self.line().startswith(b'OK ')
        else:
            if flow == 'data':
                self.socket.sendall(b'\0AUTH\r\n')
                assert self.line() == b'REJECTED EXTERNAL'
                self.socket.sendall(b'AUTH EXTERNAL\r\n')
                assert self.line() == b'DATA'
                self.socket.sendall(b'DATA ' + str(os.getuid()).encode().hex().encode() + b'\r\n')
            elif flow == 'fragmented':
                for byte in auth:
                    self.socket.sendall(bytes([byte]))
            else:
                self.socket.sendall(auth)
            assert self.line().startswith(b'OK ')
            self.socket.sendall(b'NEGOTIATE_UNIX_FD\r\n')
            assert self.line() == b'AGREE_UNIX_FD'
            self.socket.sendall(b'BEGIN\r\n')
        return {'authenticated': True}

    def register(self, flow='plain'):
        self.authenticate(flow)
        if flow != 'pipeline':
            self.socket.sendall(packet(1, 'Hello'))
        reply = self.reply(1)
        assert reply['type'] == 2 and reply['body'][0].startswith(':')
        return reply

    def command(self, request):
        operation = request['op']
        if operation == 'trickle':
            interval = request['interval_ms'] / 1000
            with socket.socket(socket.AF_UNIX) as attack:
                attack.settimeout(3)
                attack.connect(self.path)
                started = time.monotonic()
                attack.sendall(b'\0AUTH EXT')
                sent = [0.0]
                next_send = started + interval
                deadline = started + request['close_max_ms'] / 1000
                while True:
                    now = time.monotonic()
                    assert now < deadline, 'paced authentication close deadline'
                    if select.select([attack], [], [], max(min(next_send, deadline) - now, 0))[0]:
                        assert attack.recv(4096) == b'', 'unexpected trickle response'
                        return dict(elapsed_ms=(time.monotonic() - started) * 1000, sent_ms=[t * 1000 for t in sent])
                    attack.sendall(b'x')
                    sent.append(time.monotonic() - started)
                    next_send += interval
        if operation == 'burst':
            started = time.monotonic()
            counts = dict(rejected_auth=0, malformed_frame=0, denied_ownership=0)
            for kind in counts:
                for index in range(request['per_kind']):
                    assert time.monotonic() - started < request['duration_max_seconds'], 'burst duration bound'
                    worker = Client(self.path)
                    try:
                        if kind == 'rejected_auth':
                            result = worker.command(dict(op='raw', hex=b'\0AUTH EXTERNAL 30\r\n'.hex()))
                            assert b'REJECTED' in bytes.fromhex(result['response_hex'])
                        else:
                            worker.register()
                            if kind == 'malformed_frame':
                                frame = bytearray(packet(2, 'RequestName', 'su', ['org.foundation.Forbidden', 0]))
                                frame[3] = 9
                                assert worker.command(dict(op='terminal', hex=frame.hex()))['closed']
                            else:
                                result = worker.command(dict(op='call', member='RequestName', signature='su', body=['org.foundation.Forbidden', 0]))
                                assert result['error'] == BUS + '.Error.AccessDenied'
                        counts[kind] += 1
                    finally:
                        if worker.socket is not None:
                            worker.socket.close()
            return dict(counts=counts, elapsed_ms=(time.monotonic() - started) * 1000,
                        malformed_version=9, denied_name='org.foundation.Forbidden')
        if operation == 'authenticate':
            return self.authenticate()
        if operation == 'registration_sequence':
            self.authenticate()
            self.serial = 3
            self.socket.sendall(packet(1, 'Hello') + packet(2, 'RequestName', 'su', [request['name'], 0]) + packet(3, 'Hello'))
            return [self.reply(serial) for serial in [1, 2, 3]]
        if operation in ('terminal', 'wait_closed'):
            if operation == 'terminal':
                self.socket.sendall(bytes.fromhex(request['hex']))
            deadline = time.monotonic() + 3
            response, self.buffer = self.buffer, b''
            while True:
                assert time.monotonic() < deadline, 'terminal close deadline'
                self.socket.settimeout(max(deadline - time.monotonic(), 0.001))
                try:
                    piece = self.socket.recv(4096)
                except ConnectionResetError:
                    piece = b''
                if not piece:
                    return dict(closed=True, response_hex=response.hex())
                response += piece
                assert len(response) <= 65_536
        if operation == 'register':
            return self.register(request.get('flow', 'plain'))
        if operation == 'raw':
            with socket.socket(socket.AF_UNIX) as attack:
                attack.settimeout(3)
                attack.connect(self.path)
                attack.sendall(bytes.fromhex(request['hex']))
                response = b''
                closed = False
                deadline = time.monotonic() + 3
                while True:
                    assert time.monotonic() < deadline, 'raw response deadline'
                    attack.settimeout(max(deadline - time.monotonic(), 0.001))
                    try:
                        part = attack.recv(4096)
                    except ConnectionResetError:
                        closed = True
                        break
                    if not part:
                        closed = True
                        break
                    response += part
                    assert len(response) <= 65_536
                    if request.get('until', 'line') == 'line' and b'\r\n' in response:
                        break
                return dict(response_hex=response.hex(), closed=closed)
        if operation in ('call', 'send'):
            self.serial += 1
            options = {key: value for key, value in request.items() if key != 'op'}
            self.socket.sendall(packet(self.serial, **options))
            return self.reply(self.serial) if operation == 'call' else {'sent': self.serial}
        assert operation == 'poll'
        messages, self.pending = self.pending, []
        deadline = time.monotonic() + request.get('timeout', 0.15)
        while self.buffer or select.select([self.socket], [], [], max(deadline - time.monotonic(), 0))[0]:
            assert time.monotonic() < deadline, 'poll deadline'
            self.socket.settimeout(max(deadline - time.monotonic(), 0.001))
            messages.append(self.message())
        return messages


if __name__ == '__main__':
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    client = Client(sys.argv[1])
    print(json.dumps(dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid())), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            try:
                result = client.command(request)
                print(json.dumps(dict(ok=True, result=result)), flush=True)
            except Exception as error:
                print(json.dumps(dict(ok=False, error=repr(error))), flush=True)
    finally:
        if client.socket is not None:
            client.socket.close()
