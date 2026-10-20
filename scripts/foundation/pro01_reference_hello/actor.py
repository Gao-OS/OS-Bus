"""127 normal reference Hello splits; wire/kernel evidence, no parser claims."""
import array
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import termios
import time


def emit(event, **values):
    print(json.dumps(dict(event=event, **values), sort_keys=True), flush=True)


def starttime():
    raw = Path('/proc/self/stat').read_text()
    return int(raw[raw.rfind(')') + 2:].split()[19])


def send_signature(trace):
    sends = [row for row in trace if row['direction'] == 'send']
    return dict(events=len(sends), bytes=sum(len(bytes.fromhex(v['hex'])) for v in sends),
                sha256=hashlib.sha256(json.dumps(sends, sort_keys=True,
                                               separators=(',', ':')).encode()).hexdigest())


def connection(raw):
    return dict(pid=os.getpid(), starttime_ticks=starttime(), fd=raw.fileno(),
                inode=os.fstat(raw.fileno()).st_ino)


def queue(raw, identity, trace):
    """Port of SEC07 observe_queue; TIOCOUTQ is allocation, never payload bytes."""
    row = dict(started=time.monotonic(), connection=connection(raw), kernel=os.uname().release,
               ioctl=int(termios.TIOCOUTQ), units='transmit allocation accounting',
               sole_writer=True, duplicated_connection=False, send_trace=send_signature(trace))
    assert row['connection'] == identity
    assert not select.select([raw], [], [], 0)[0], 'source reply or EOF before completion'
    value = array.array('i', [0])
    assert value.itemsize == 4
    fcntl.ioctl(raw.fileno(), termios.TIOCOUTQ, value, True)
    assert value[0] >= 0
    row.update(allocation=value[0], live=True, success=True, error=None)
    assert connection(raw) == identity
    assert not select.select([raw], [], [], 0)[0], 'source reply or EOF during observation'
    row['finished'] = time.monotonic()
    return row


def validate_queue(row, identity, trace, ioctl, kernel):
    assert row['connection'] == identity
    assert row['live'] is row['success'] is row['sole_writer'] is True
    assert row['duplicated_connection'] is False and row['error'] is None
    assert row['units'] == 'transmit allocation accounting'
    assert type(row['allocation']) is int and row['allocation'] == 0
    assert row['ioctl'] == ioctl and row['kernel'] == kernel
    assert identity['pid'] > 0 and identity['starttime_ticks'] > 0
    assert identity['fd'] >= 0 and identity['inode'] > 0
    sends = [v for v in trace if v['direction'] == 'send']
    assert sends and all(v['outcome'] == 'sent' and v['monotonic'] <= v['completed'] for v in sends)
    assert row['send_trace'] == send_signature(trace)
    assert sends[-1]['completed'] <= row['started'] <= row['finished']


def validate_barrier(barrier, identity, trace, ioctl, kernel):
    first, second, health = (barrier[k] for k in ('first', 'second', 'health'))
    for row in (first, second):
        validate_queue(row, identity, trace, ioctl, kernel)
    assert first['send_trace'] == second['send_trace']
    assert barrier['started'] <= first['started']
    assert first['finished'] <= health['started'] <= health['finished'] <= second['started']
    assert second['finished'] <= barrier['finished'] <= barrier['started'] + 1
    assert barrier['finished'] - [v for v in trace if v['direction'] == 'send'][-1]['completed'] <= 1


def validate_completion(rows, name, bus_id_hex):
    """The unchanged donor registration checks body/signals; retain its order oracle."""
    rows = [dict(row, fields={int(k): v for k, v in row['fields'].items()}) for row in rows]
    replies = [row for row in rows if row['type'] == 2]
    signals = [row for row in rows if row['type'] == 4]
    assert len(rows) == 3 and len(replies) == 2 and len(signals) == 1
    assert [row['fields'].get(5) for row in replies] == [1, 2]
    assert all(row['fields'].get(6) == name and row['fields'].get(7) == 'org.freedesktop.DBus'
               and row['fields'].get(8) == 's' and row['fields'].get(9, 0) == 0 for row in replies)
    expected = struct.pack('<I', len(name.encode())) + name.encode() + b'\0'
    assert replies[0]['body'] == expected.hex() and replies[1]['body'] == bus_id_hex
    signal_row = signals[0]
    assert signal_row['fields'].get(3) == 'NameAcquired'
    assert signal_row['fields'].get(6) == name and signal_row['body'] == expected.hex()


def validate_cases(cases):
    assert len(cases) == 127 and [v['split'] for v in cases] == list(range(1, 128))
    assert all(v['result'] == 'PASS' for v in cases)


def kernel_control():
    """Same finite initial/unread/partial/exact-full control as SEC07, local kernel."""
    began = time.monotonic()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    data = bytes(range(256)) * 64
    report = dict(kernel=os.uname().release, ioctl=int(termios.TIOCOUTQ),
                  units='transmit allocation accounting', steps=[],
                  sockets=[connection(v) for v in (sender, receiver)])
    def sample(phase):
        assert time.monotonic() <= began + 1
        assert [connection(v) for v in (sender, receiver)] == report['sockets']
        value = array.array('i', [0])
        assert value.itemsize == 4
        fcntl.ioctl(sender.fileno(), termios.TIOCOUTQ, value, True)
        report['steps'].append(dict(phase=phase, allocation=value[0], observed=time.monotonic()))
        return value[0]
    try:
        assert sample('before_send') == 0
        sender.settimeout(1)
        receiver.settimeout(1)
        sender.sendall(data)
        report['send_completed'] = time.monotonic()
        assert sample('unread') > 0
        received = receiver.recv(1)
        assert received == data[:1] and sample('partial_read') > 0
        while len(received) < len(data):
            assert time.monotonic() < began + 1
            receiver.settimeout(max(0.001, began + 1 - time.monotonic()))
            part = receiver.recv(len(data) - len(received))
            assert part
            received += part
        assert received == data and sample('complete_read') == 0
        report.update(payload_sha256=hashlib.sha256(data).hexdigest(),
                      received_sha256=hashlib.sha256(received).hexdigest(), passed=True)
    finally:
        sender.close()
        receiver.close()
        report['seconds'] = time.monotonic() - began
        emit('kernel_control', **report)
    assert report['seconds'] <= 1
    return report


class TracedSocket:
    def __init__(self, raw, role, trace):
        self.raw, self.role, self.trace = raw, role, trace

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def record(self, direction, data, began, **details):
        row = dict(direction=direction, role=self.role, hex=data.hex(), monotonic=began,
                   completed=time.monotonic(), **details)
        self.trace.append(row)
        emit('wire', **row)

    def sendall(self, data):
        began = time.monotonic()
        try:
            self.raw.sendall(data)
        except Exception as error:
            self.record('send', data, began, outcome='failed', error=repr(error))
            raise
        self.record('send', data, began, outcome='sent')

    def recv(self, length, flags=0):
        began = time.monotonic()
        try:
            data = self.raw.recv(length, flags)
        except Exception as error:
            self.record('receive', b'', began, requested=length, flags=flags,
                        controls=[], error=repr(error))
            raise
        self.record('receive', data, began, requested=length, flags=flags, controls=[])
        return data

    def recvmsg(self, length, control_size):
        began = time.monotonic()
        try:
            data, controls, flags, address = self.raw.recvmsg(length, control_size)
        except Exception as error:
            self.record('receive', b'', began, requested=length, error=repr(error))
            raise
        self.record('receive', data, began, requested=length, flags=flags,
                    controls=[dict(level=a, kind=b, hex=c.hex()) for a, b, c in controls])
        return data, controls, flags, address


def run(path, fixture_dir, daemon_pid):
    assert not sys.flags.optimize and sys.platform == 'linux'
    assert os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    assert Path(path).is_absolute() and Path(path).parent.stat().st_mode & 0o777 == 0o700
    assert not any(k.startswith('DBUS_') for k in os.environ)
    sys.path.insert(0, fixture_dir)
    donor = importlib.import_module('peer_hello_split_boundaries_actor')
    wire = importlib.import_module('transport_actor')
    assert len(donor.HELLO) == len(donor.GET_ID) == 128
    emit('literals', hello=donor.HELLO.hex(), get_id=donor.GET_ID.hex(),
         hello_sha256=hashlib.sha256(donor.HELLO).hexdigest(),
         get_id_sha256=hashlib.sha256(donor.GET_ID).hexdigest())
    signal.alarm(45)
    identity = dict(pid=os.getpid(), uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(),
                    egid=os.getegid(), starttime_ticks=starttime(), proc_status=Path('/proc/self/status').read_text())
    emit('identity', **identity)
    control = kernel_control()

    class Client(donor.NormalClient):
        def __init__(self, role):
            self.role, self.trace = role, []
            super().__init__(path)
            self.connection = connection(self.sock)
            peer = struct.unpack('3i', self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            assert peer == (daemon_pid, os.getuid(), os.getgid()), peer
            emit('connection', role=role, connection=self.connection, peer_credentials=list(peer),
                 endpoint=path, auth=self.auth.hex())

        def send(self, data):
            if not isinstance(self.sock, TracedSocket):
                self.sock = TracedSocket(self.sock, self.role, self.trace)
            super().send(data)

    observer = source = None
    cases = []
    serial = 10
    def health():
        nonlocal serial
        began = time.monotonic()
        rows = donor.health(observer, owned, bus_id, serial)
        serial += 2
        return dict(started=began, finished=time.monotonic(), receipts=rows,
                    observer=observer.name, owned=owned, bus_id=bus_id.hex())

    def query(member, name):
        nonlocal serial
        request_serial = serial
        observer.send(wire.call(member, request_serial, 's', wire.string(name)))
        serial += 1
        row, = observer.messages(1)
        observer.empty()
        return row, request_serial

    try:
        observer = Client('observer')
        observer.send(b'BEGIN\r\n' + donor.HELLO + donor.GET_ID)
        registration, bus_id = donor.registration(observer)
        owned = 'org.foundation.HelloSplitObserver'
        request = wire.string(owned)
        observer.send(wire.call('RequestName', 3, 'su', request + b'\0' * (-len(request) % 4) + wire.u32(0)))
        ownership = observer.messages(2)
        returns = [r for r in ownership if r['type'] == 2]
        signals = [r for r in ownership if r['type'] == 4]
        assert len(returns) == len(signals) == 1
        assert donor.reply(returns[0], 3) == wire.u32(1)
        donor.acquired(signals[0], owned, observer.name)
        observer.empty()
        emit('ready', observer=observer.name, owned=owned, bus_id=bus_id.hex(),
             registration=registration, ownership=ownership, hello=donor.HELLO.hex(),
             get_id=donor.GET_ID.hex(), hello_sha256=hashlib.sha256(donor.HELLO).hexdigest(),
             get_id_sha256=hashlib.sha256(donor.GET_ID).hexdigest())
        for split in range(1, 128):
            source = Client('source-' + str(split))
            source.send(b'BEGIN\r\n' + donor.HELLO[:split])
            barrier = dict(started=time.monotonic(), samples=[])
            deadline = [v for v in source.trace if v['direction'] == 'send'][-1]['completed'] + 1
            while True:
                assert time.monotonic() < deadline, 'held-prefix queue deadline'
                sample = queue(source.sock, source.connection, source.trace)
                barrier['samples'].append(sample)
                emit('queue', split=split, sample=sample)
                if sample['allocation'] == 0:
                    barrier['first'] = sample
                    break
            source.sock.settimeout(max(0.001, deadline - time.monotonic()))
            observer.sock.settimeout(max(0.001, deadline - time.monotonic()))
            barrier['health'] = health()
            barrier['second'] = queue(source.sock, source.connection, source.trace)
            barrier['finished'] = time.monotonic()
            validate_barrier(barrier, source.connection, source.trace, control['ioctl'], control['kernel'])
            prefix_trace = list(source.trace)
            source.empty()
            source.sock.settimeout(3)
            observer.sock.settimeout(3)
            source.send(donor.HELLO[split:] + donor.GET_ID)
            rows, _ = donor.registration(source, bus_id)
            assert source.name != observer.name
            validate_completion(rows, source.name, bus_id.hex())
            source_name = source.name
            owner, owner_serial = query('GetNameOwner', source_name)
            assert donor.reply(owner, owner_serial) == wire.string(source_name)
            uid, uid_serial = query('GetConnectionUnixUser', source_name)
            assert donor.reply(uid, uid_serial) == wire.u32(os.getuid())
            pid, pid_serial = query('GetConnectionUnixProcessID', source_name)
            assert donor.reply(pid, pid_serial) == wire.u32(os.getpid())
            source.empty()
            source.close()
            source = None
            after_health = health()
            began = time.monotonic()
            gone = []
            while True:
                assert time.monotonic() < began + 1, 'ownership disappearance deadline'
                observer.sock.settimeout(max(0.001, began + 1 - time.monotonic()))
                row, request_serial = query('GetNameOwner', source_name)
                gone.append(row)
                if row['type'] == 3:
                    assert row['fields'].get(5) == request_serial
                    assert row['fields'].get(4) == 'org.freedesktop.DBus.Error.NameHasNoOwner'
                    break
                assert donor.reply(row, request_serial) == wire.string(source_name)
            observer.sock.settimeout(3)
            case = dict(split=split, result='PASS', source=source_name, connection=barrier['first']['connection'],
                        prefix_trace=prefix_trace, barrier=barrier, receipts=rows, owner=owner,
                        uid=uid, pid=pid, after_close_health=after_health, ownership_disappearance=gone,
                        ownership_disappearance_seconds=time.monotonic() - began,
                        source_pending=False, received_fds=0, internal_accounting='UNSUPPORTED',
                        source_parser_buffer='UNSUPPORTED')
            cases.append(case)
            emit('case', **case)
        validate_cases(cases)
        emit('result', result='PASS', cases=127, observer=observer.name, owned=owned,
             bus_id=bus_id.hex(), final_health=health(), internal_accounting='UNSUPPORTED',
             source_parser_buffer='UNSUPPORTED', native_frames_per_read='UNSUPPORTED')
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == '__main__':
    assert len(sys.argv) == 4
    run(sys.argv[1], sys.argv[2], int(sys.argv[3]))
