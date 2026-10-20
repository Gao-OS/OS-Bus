"""Guest-only PRO05 controls on the existing independent security Client.

Commands: register, call/send/poll for setup, target(case), terminal(case,
authorization), observe(owner, serial, source_name=None), and close. A terminal
target only sends: the controller must prove normal DOWN and restoration before
authorizing the separate EOF command. An authorization token is a receipt join,
not evidence that the controller performed those checks.
"""
import array
import hashlib
import json
import math
import os
from pathlib import Path
import select
import socket
import stat
import sys
import time


BUS = 'org.freedesktop.DBus'
INVALID_ARGS = BUS + '.Error.InvalidArgs'
CONTROL_BYTES = 4_194_304
RECEIVE_BYTES = 65_536
CASES = ('variant64', 'variant65', 'array32', 'array33', 'struct32', 'struct33',
         'match_string', 'match_uint32', 'collection', 'prefix')
TERMINAL = ('variant65', 'array33', 'struct33', 'prefix')


def receipt(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def _text(value):
    raw = value.encode()
    return len(raw).to_bytes(4, 'little') + raw + b'\0'


def _frame(kind, serial, fields, body):
    # Independent construction; neither production nor vectors.py is imported.
    header = bytearray()
    for code, signature, value in fields:
        header.extend(bytes(-len(header) % 8))
        header.extend(bytes([code, 1]) + signature.encode() + b'\0')
        if signature == 'g':
            raw = value.encode()
            header.extend(bytes([len(raw)]) + raw + b'\0')
        else:
            assert signature in ('s', 'o')
            header.extend(_text(value))
    fixed = bytes([ord('l'), kind, 0, 1])
    fixed += len(body).to_bytes(4, 'little') + serial.to_bytes(4, 'little')
    fixed += len(header).to_bytes(4, 'little')
    return fixed + header + bytes(-len(header) % 8) + body


def _call(member, serial, signature=None, body=b''):
    fields = [(1, 'o', '/org/freedesktop/DBus'), (2, 's', BUS),
              (3, 's', member), (6, 's', BUS)]
    if signature is not None:
        fields.append((8, 'g', signature))
    return _frame(1, serial, fields, body)


def target_frame(case):
    """Exactly the accepted native packet, including its original serial."""
    assert case in CASES, 'unselected PRO05 case'
    if case == 'prefix':
        return bytes([255, 1, 0, 1]) + bytes(4) + (3).to_bytes(4, 'little') + bytes(4)
    if case.startswith('variant'):
        depth = 64 if case == 'variant64' else 65
        body = b'\x01v\0' * (depth - 1) + b'\x01y\0\x2a'
        return _call('RequestName', 3 if depth == 64 else 6, 'v', body)
    if case.startswith('array'):
        depth = 32 if case == 'array32' else 33
        body = b''.join(size.to_bytes(4, 'little') for size in range(depth * 4 - 3, 0, -4))
        return _call('GetId', 3 if depth == 32 else 6, 'a' * depth + 'y', body + b'\x2a')
    if case.startswith('struct'):
        depth = 32 if case == 'struct32' else 33
        return _call('GetId', 3 if depth == 32 else 6,
                     '(' * depth + 'y' + ')' * depth, b'\x2a')
    if case == 'collection':
        count = 1_048_576 - 16 - 120 - 4
        return _call('GetId', 3, 'ay', count.to_bytes(4, 'little') + b'\x2a' * count)
    signature, serial, body = ('s', 3, _text('/probe')) if case == 'match_string' else (
        'u', 6, (42).to_bytes(4, 'little'))
    return _frame(4, serial, [(1, 'o', '/probe'), (2, 's', 'org.foundation.Probe'),
                             (3, 's', 'Changed'), (8, 'g', signature)], body)


def check_endpoint(endpoint):
    path = Path(endpoint)
    assert path.is_absolute() and '..' not in path.parts
    assert str(path).startswith('/run/osbus-security/pro05-complete/')
    assert len(os.fsencode(path)) < 108


def control_line(value):
    line = json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n'
    assert len(line.encode('ascii')) <= CONTROL_BYTES, 'fixture output line too large'
    return line


def command_deadline(command, started):
    budget_ms = 1000 if command['op'] == 'observe' else 3000
    deadline = started + budget_ms / 1000
    if 'deadline_monotonic' in command:
        caller = command['deadline_monotonic']
        assert type(caller) in (int, float) and math.isfinite(caller) and caller > started
        deadline = min(deadline, caller)
    return deadline, budget_ms


class RecordedSocket:
    """Transport-only instrumentation; Client retains all wire decoding."""
    def __init__(self, raw, trace, clock):
        self.raw, self.trace, self.clock = raw, trace, clock

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def remaining(self):
        value = self.clock['deadline'] - time.monotonic()
        assert value > 0, 'PRO05 actor whole-command deadline'
        return value

    def settimeout(self, value):
        remaining = self.remaining()
        self.raw.settimeout(remaining if value is None else min(value, remaining))

    def connect(self, path):
        check_endpoint(path)
        self.settimeout(None)
        self.raw.connect(path)
        self.remaining()

    def sendall(self, data):
        event = dict(direction='send', **receipt(data), sent=False,
                     elapsed_ms=(time.monotonic() - self.clock['origin']) * 1000)
        self.trace.append(event)
        try:
            self.settimeout(None)
            self.raw.sendall(data)
            event['sent'] = True
            self.remaining()
        except (BrokenPipeError, ConnectionResetError) as error:
            event['errno'] = error.errno
            raise

    def recv(self, size):
        self.settimeout(None)
        size = min(size, RECEIVE_BYTES - self.clock.get('received_bytes', 0) + 1)
        data, controls, flags, _ = self.raw.recvmsg(size, socket.CMSG_SPACE(253 * 4))
        # FD-free tests never retain accidentally received rights.
        for level, kind, value in controls:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                descriptors = array.array('i')
                descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
                for descriptor in descriptors:
                    os.close(descriptor)
        self.trace.append(dict(direction='receive', hex=data.hex(), flags=flags,
                               ancillary_count=len(controls),
                               elapsed_ms=(time.monotonic() - self.clock['origin']) * 1000))
        self.clock['received_bytes'] = self.clock.get('received_bytes', 0) + len(data)
        assert self.clock['received_bytes'] <= RECEIVE_BYTES, 'actor receive artifact exceeds bound'
        assert controls == [] and flags == 0, 'unexpected ancillary data or flags'
        self.remaining()
        return data


def _reply(row, serial, body=None, error=None):
    assert row['reply_serial'] == serial and row['sender'] == BUS
    assert row['type'] == (3 if error else 2) and row['error'] == error
    if error is not None:
        assert len(row['body']) == 1 and isinstance(row['body'][0], str)
    if body is not None:
        assert row['body'] == body
    return row


def client_type(Client, trace, clock):
    """Overlay the existing Client; importing this module opens no transport."""
    class RecordedClient(Client):
        def __init__(self, path, role=1101):
            super().__init__(path)
            self.role = role
            self.terminal_case = None

        def authenticate(self, flow='plain'):
            assert self.socket is None and flow in ('plain', 'discovery')
            self.socket = RecordedSocket(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM), trace, clock)
            self.socket.connect(self.path)
            assertion = str(os.getuid()).encode().hex().encode()
            if flow == 'discovery':
                self.socket.sendall(b'\0AUTH\r\n')
                assert self.line() == b'REJECTED EXTERNAL'
                self.socket.sendall(b'AUTH EXTERNAL ' + assertion + b'\r\n')
            else:
                self.socket.sendall(b'\0AUTH EXTERNAL ' + assertion + b'\r\n')
            ok = self.line()
            assert len(ok) == 35 and ok.startswith(b'OK ')
            assert len(bytes.fromhex(ok[3:].decode())) == 16
            self.serial = 2
            self.socket.sendall(b'BEGIN\r\n' + _call('Hello', 1) + _call('GetId', 2))

        def empty(self):
            assert self.buffer == b'' and self.pending == []
            assert not select.select([self.socket], [], [], 0)[0], 'unconsumed socket bytes or EOF'

        def health(self, owner, serial):
            assert serial > self.serial and self.pending == [] and self.buffer == b''
            self.socket.sendall(_call('GetNameOwner', serial, 's', _text(owner)))
            self.socket.sendall(_call('GetId', serial + 1, ''))
            self.serial = serial + 1

        def health_rows(self, serial):
            rows = [self.message(), self.message()]
            _reply(rows[0], serial, [self.unique])
            _reply(rows[1], serial + 1, [self.bus_id])
            self.empty()
            return rows

        def command(self, request):
            operation = request['op']
            if self.terminal_case is not None:
                assert operation in ('terminal', 'close'), 'terminal source awaiting retirement'
            if operation == 'register':
                self.authenticate(request.get('flow', 'plain'))
                rows = [self.message(), self.message(), self.message()]
                replies = [row for row in rows if row['type'] == 2]
                signals = [row for row in rows if row['type'] == 4]
                assert len(replies) == 2 and len(signals) == 1
                hello = _reply(replies[0], 1)
                acquired, get_id = signals[0], replies[1]
                assert len(hello['body']) == 1 and hello['body'][0].startswith(':')
                self.unique = hello['body'][0]
                assert acquired['type'] == 4 and acquired['sender'] == BUS
                assert acquired['interface'] == BUS and acquired['member'] == 'NameAcquired'
                assert acquired['body'] == [self.unique]
                _reply(get_id, 2)
                assert len(get_id['body']) == 1 and len(get_id['body'][0]) == 32
                self.bus_id = get_id['body'][0]
                self.empty()
                return dict(hello, unique=self.unique, bus_id=self.bus_id, registration=rows,
                            buffered_hex='', pending_messages=0)
            if operation == 'target':
                assert self.role == 1101 and self.pending == [] and self.buffer == b''
                case = request['case']
                frame = target_frame(case)
                serial = int.from_bytes(frame[8:12], 'little')
                assert self.serial == serial - 1
                self.socket.sendall(frame)
                self.serial = serial
                result = dict(case=case, frame=receipt(frame), serial=serial,
                              source_socket_open=self.socket.fileno() >= 0,
                              buffered_hex='', pending_messages=0)
                assert result['source_socket_open']
                if case in TERMINAL:
                    self.terminal_case = case
                    return dict(result, disposition='sent-awaiting-controller')
                if case.startswith('match_'):
                    error = None
                else:
                    error = _reply(self.message(), serial, error=INVALID_ARGS)
                self.health(self.unique, serial + 1)
                rows = self.health_rows(serial + 1)
                return dict(result, disposition='signal-sent' if error is None else 'invalid-args',
                            error=error, source_health=rows)
            if operation == 'terminal':
                assert self.terminal_case == request['case'] and self.terminal_case is not None
                token = request.get('authorization')
                assert isinstance(token, str) and 0 < len(token) <= 256
                assert self.buffer == b'' and self.pending == []
                opened = self.socket.fileno() >= 0
                assert opened
                began = time.monotonic()
                terminal = self.socket.recv(1)
                elapsed = (time.monotonic() - began) * 1000
                assert terminal == b'' and elapsed <= 3000, 'expected automatic empty EOF'
                return dict(case=self.terminal_case, disposition='automatic-eof',
                            source_socket_open=opened, terminal_hex='', eof_ms=elapsed,
                            authorization=token, buffered_hex='', pending_messages=0)
            if operation == 'observe':
                assert self.role == 1100
                serial = request['serial']
                began = time.monotonic()
                self.health(request['owner'], serial)
                signal_row = None
                if request.get('source_name') is not None:
                    signal_row = self.message()
                    assert signal_row['type'] == 4 and signal_row['serial'] == 3
                    assert signal_row['sender'] == request['source_name']
                    assert signal_row['interface'] == 'org.foundation.Probe'
                    assert signal_row['member'] == 'Changed' and signal_row['body'] == ['/probe']
                rows = self.health_rows(serial)
                elapsed = (time.monotonic() - began) * 1000
                assert elapsed <= 1000
                return dict(signal=signal_row, health=rows, observer_health_ms=elapsed,
                            bus_id=self.bus_id, buffered_hex='', pending_messages=0)
            if operation == 'close':
                assert self.socket is not None
                self.socket.close()
                self.socket = None
                return dict(disposition='controller-close', socket_closed=True)
            assert operation in ('call', 'send', 'poll'), 'unselected actor operation'
            if operation != 'poll':
                assert request['member'] in ('RequestName', 'AddMatch', 'GetNameOwner',
                                             'GetId', 'ListNames', 'NameHasOwner',
                                             'GetConnectionUnixUser', 'GetConnectionUnixProcessID')
            else:
                assert 0 <= request.get('timeout', 0.15) <= 1
            inherited = {key: value for key, value in request.items() if key != 'deadline_monotonic'}
            return super().command(inherited)

    return RecordedClient


def main(original, endpoint):
    assert not sys.flags.optimize
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    check_endpoint(endpoint)
    assert stat.S_ISSOCK(os.lstat(endpoint).st_mode)
    uid, gid = os.getuid(), os.getgid()
    assert uid == os.geteuid() and gid == os.getegid() and uid == gid and uid in (1100, 1101)
    sys.path.insert(0, str(original))
    from actor import Client
    trace = []
    clock = {}
    client = client_type(Client, trace, clock)(endpoint, role=uid)
    sys.stdout.write(control_line(dict(pid=os.getpid(), uid=uid, gid=gid)))
    sys.stdout.flush()
    try:
        while True:
            line = sys.stdin.buffer.readline(CONTROL_BYTES + 1)
            if not line:
                return 0
            assert len(line) <= CONTROL_BYTES and line.endswith(b'\n'), 'actor input line exceeds bound'
            trace.clear()
            began = time.monotonic()
            request = {}
            try:
                request = json.loads(line)
                assert isinstance(request, dict), 'actor command must be an object'
                deadline, budget_ms = command_deadline(request, began)
                clock.update(origin=began, deadline=deadline, received_bytes=0)
                result = client.command(request)
                ended = time.monotonic()
                assert ended < deadline, 'PRO05 actor whole-command deadline'
                response = dict(ok=True, result=result, wire=trace,
                                elapsed_ms=(ended - began) * 1000, budget_ms=budget_ms)
            except Exception as error:
                response = dict(ok=False, error=repr(error), wire=trace,
                                elapsed_ms=(time.monotonic() - began) * 1000,
                                budget_ms=1000 if isinstance(request, dict) and request.get('op') == 'observe' else 3000)
            sys.stdout.write(control_line(response))
            sys.stdout.flush()
            if not response['ok']:
                return 1
    finally:
        if client.socket is not None:
            client.socket.close()


if __name__ == '__main__':
    assert len(sys.argv) == 3
    sys.exit(main(Path(sys.argv[1]), sys.argv[2]))
