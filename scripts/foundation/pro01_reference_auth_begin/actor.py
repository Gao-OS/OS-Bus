"""Thirty ordinary reference AUTH/BEGIN splits; kernel evidence only."""
import hashlib
import importlib
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts.foundation.pro01_reference_hello.actor import (
    TracedSocket, connection, emit, kernel_control, queue, send_signature,
    starttime, validate_barrier, validate_completion,
)

BEGIN = b'BEGIN\r\n'
OBSERVER = 'org.foundation.AuthBeginSplitObserver'
CASE_ORDER = [('AUTH', split) for split in range(1, 25)] + [
    ('BEGIN', split) for split in range(1, 7)]


def auth_command(uid):
    assert type(uid) is int and uid > 0
    command = b'\0AUTH EXTERNAL ' + str(uid).encode().hex().encode() + b'\r\n'
    assert len(command) == 25, 'actual UID does not give the required AUTH25 census'
    return command


def validate_ok(reply, expected=None):
    assert len(reply) == 37 and reply[:3] == b'OK ' and reply[-2:] == b'\r\n'
    assert all(value in b'0123456789abcdef' for value in reply[3:-2])
    if expected is not None:
        assert reply == expected


def role(family, split):
    return 'source-' + family + '-' + str(split)


def validate_cases(cases):
    assert len(cases) == 30
    assert [(row['family'], row['split']) for row in cases] == CASE_ORDER
    assert all(row['result'] == 'PASS' for row in cases)


def binary_frames(data):
    """Slice only the ordinary little-endian reply/signal corpus's fixed extents."""
    frames = []
    while data:
        assert len(data) >= 16 and data[:1] == b'l' and data[3] == 1
        assert data[1] in (2, 3, 4)
        body_size, _, header_size = struct.unpack_from('<III', data, 4)
        assert body_size + header_size < 2**21
        size = 16 + header_size + (-header_size % 8) + body_size
        assert len(data) >= size
        frames.append(data[:size])
        data = data[size:]
    return frames


def run(path, fixture_dir, daemon_pid):
    assert not sys.flags.optimize and sys.platform == 'linux'
    assert os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    assert Path(path).is_absolute() and Path(path).parent.stat().st_mode & 0o777 == 0o700
    assert not any(key.startswith('DBUS_') for key in os.environ)
    auth = auth_command(os.getuid())
    sys.path.insert(0, fixture_dir)
    donor = importlib.import_module('peer_hello_split_boundaries_actor')
    wire = importlib.import_module('transport_actor')
    assert len(donor.HELLO) == len(donor.GET_ID) == 128
    emit('literals', auth=auth.hex(), begin=BEGIN.hex(), hello=donor.HELLO.hex(),
         get_id=donor.GET_ID.hex(), hello_sha256=hashlib.sha256(donor.HELLO).hexdigest(),
         get_id_sha256=hashlib.sha256(donor.GET_ID).hexdigest())
    signal.alarm(45)
    emit('identity', pid=os.getpid(), uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(),
         egid=os.getegid(), starttime_ticks=starttime(), proc_status=Path('/proc/self/status').read_text())
    control = kernel_control()

    class Client(donor.NormalClient):
        def __init__(self, name):
            # NormalClient.__init__ sends complete AUTH; deliberately open raw.
            self.role, self.trace, self.writes = name, [], []
            raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock = TracedSocket(raw, name, self.trace)
            try:
                self.sock.settimeout(3)
                self.sock.connect(path)
                self.connection = connection(self.sock)
                peer = struct.unpack('3i', self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                assert peer == (daemon_pid, os.getuid(), os.getgid()), peer
                emit('connection', role=name, connection=self.connection,
                     peer_credentials=list(peer), endpoint=path)
            except BaseException:
                raw.close()
                raise

        def authenticate(self):
            self.auth = self.line()
            validate_ok(self.auth, None if self.role == 'observer' else observer.auth)
            self.empty()
            emit('authenticated', role=self.role, auth=self.auth.hex())

        def messages(self, count):
            began = len(self.trace)
            rows = super().messages(count)
            raw = b''.join(bytes.fromhex(row['hex']) for row in self.trace[began:]
                           if row['direction'] == 'receive')
            frames = binary_frames(raw)
            assert len(frames) == len(rows)
            for row, frame in zip(rows, frames):
                row['wire_hex'] = frame.hex()
            return rows

    observer = source = None
    cases, serial = [], 10

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
        observer.send(auth)
        observer.authenticate()
        observer.send(BEGIN + donor.HELLO + donor.GET_ID)
        registration, bus_id = donor.registration(observer)
        validate_completion(registration, observer.name, bus_id.hex())
        owned = OBSERVER
        request = wire.string(owned)
        observer.send(wire.call('RequestName', 3, 'su', request + b'\0' * (-len(request) % 4) + wire.u32(0)))
        ownership = observer.messages(2)
        returns = [row for row in ownership if row['type'] == 2]
        signals = [row for row in ownership if row['type'] == 4]
        assert len(returns) == len(signals) == 1
        assert donor.reply(returns[0], 3) == wire.u32(1)
        donor.acquired(signals[0], owned, observer.name)
        observer.empty()
        emit('ready', observer=observer.name, owned=owned, bus_id=bus_id.hex(), auth=auth.hex(),
             ok=observer.auth.hex(), begin=BEGIN.hex(), registration=registration, ownership=ownership,
             hello=donor.HELLO.hex(), get_id=donor.GET_ID.hex(),
             hello_sha256=hashlib.sha256(donor.HELLO).hexdigest(),
             get_id_sha256=hashlib.sha256(donor.GET_ID).hexdigest())
        for family, split in CASE_ORDER:
            source = Client(role(family, split))
            if family == 'BEGIN':
                source.send(auth)
                source.authenticate()
            prefix = auth[:split] if family == 'AUTH' else BEGIN[:split]
            source.send(prefix)
            barrier = dict(started=time.monotonic(), samples=[])
            deadline = [row for row in source.trace if row['direction'] == 'send'][-1]['completed'] + 1
            while True:
                assert time.monotonic() < deadline, 'held-prefix queue deadline'
                sample = queue(source.sock, source.connection, source.trace)
                barrier['samples'].append(sample)
                emit('queue', family=family, split=split, sample=sample)
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
            if family == 'AUTH':
                source.send(auth[split:])
                source.authenticate()
                source.send(BEGIN + donor.HELLO + donor.GET_ID)
            else:
                source.send(BEGIN[split:] + donor.HELLO + donor.GET_ID)
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
            began, gone, gone_serials = time.monotonic(), [], []
            while True:
                assert time.monotonic() < began + 1, 'ownership disappearance deadline'
                observer.sock.settimeout(max(0.001, began + 1 - time.monotonic()))
                row, request_serial = query('GetNameOwner', source_name)
                gone.append(row)
                gone_serials.append(request_serial)
                if row['type'] == 3:
                    assert row['fields'].get(5) == request_serial
                    assert row['fields'].get(4) == 'org.freedesktop.DBus.Error.NameHasNoOwner'
                    break
                assert donor.reply(row, request_serial) == wire.string(source_name)
            observer.sock.settimeout(3)
            case = dict(family=family, split=split, result='PASS', source=source_name,
                        connection=barrier['first']['connection'], prefix_trace=prefix_trace,
                        barrier=barrier, receipts=rows, owner=owner, owner_serial=owner_serial,
                        uid=uid, uid_serial=uid_serial, pid=pid, pid_serial=pid_serial,
                        after_close_health=after_health, ownership_disappearance=gone,
                        disappearance_serials=gone_serials, ownership_disappearance_seconds=time.monotonic() - began,
                        source_pending=False, received_fds=0, internal_accounting='UNSUPPORTED',
                        source_parser_buffer='UNSUPPORTED')
            cases.append(case)
            emit('case', **case)
        validate_cases(cases)
        emit('result', result='PASS', cases=30, auth_cases=24, begin_cases=6, connections=31,
             observer=observer.name, owned=owned, bus_id=bus_id.hex(), final_health=health(),
             internal_accounting='UNSUPPORTED', source_parser_buffer='UNSUPPORTED',
             native_frames_per_read='UNSUPPORTED')
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == '__main__':
    assert len(sys.argv) == 4
    run(sys.argv[1], sys.argv[2], int(sys.argv[3]))
