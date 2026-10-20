"""Positive reference D286, independent exec roles and external kernel evidence."""
import array
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
# The unchanged fixture modules internally import transport_actor by this path.
FIXTURES = ROOT / 'apps/gao_bus/test/fixtures'
sys.path.insert(0, str(FIXTURES))
from apps.gao_bus.test.fixtures import transport_actor as wire
from apps.gao_bus.test.fixtures import peer_hello_split_boundaries_actor as hello
from apps.gao_bus.test.fixtures import peer_fd_split_boundaries_actor as fd_donor
from scripts.foundation.pro01_reference_hello import actor as reference
from scripts.foundation.pro01_reference_auth_begin.actor import binary_frames, validate_ok
from scripts.foundation.pro01_reference_get_id.actor import auth_command

BEGIN = b'BEGIN\r\n'
NEGOTIATE = b'NEGOTIATE_UNIX_FD\r\n'
AGREE = b'AGREE_UNIX_FD\r\n'
OBSERVER = 'org.foundation.FdSplitObserver'
TARGET = ':1.2'
FIRST_SHA256 = 'aece49fad72a9746c85ca850925e3081960904ba870160162c6c940fc853e521'
SECOND_SHA256 = '4bdb8a7b2933e0b1dfddd4155f27d9f351c3805e30747cf0b8ef04a7ebf77c33'
TAIL_SHA256 = '47833429f51dbaed75517f1b7f63608e4426d3d42033d8ee2a9cf63c34849aaf'
FIRST = bytes.fromhex(
    '6c040001080000000a0000007800000001016f000b0000002f666f756e646174696f6e'
    '000000000002017300180000006f72672e666f756e646174696f6e2e5472616e73706f'
    '7274000000000000000003017300080000005265736f757263650000000000000000'
    '080167000268680006017300040000003a312e32000000000901750002000000010000'
    '0000000000')
SECOND = FIRST[:8] + b'\x0b\0\0\0' + FIRST[12:136] + b'\0\0\0\0\x01\0\0\0'
TAIL = bytes.fromhex(
    '6c040001000000000c0000006d00000001016f000b0000002f666f756e646174696f6e'
    '000000000002017300180000006f72672e666f756e646174696f6e2e5472616e73706f'
    '7274000000000000000003017300080000005265736f757263650000000000000000'
    '080167000000000006017300040000003a312e3200000000')
send_signature = reference.send_signature
emit = reference.emit


def vectors():
    values = FIRST, SECOND, TAIL
    assert [len(v) for v in values] == [144, 144, 128]
    assert [hashlib.sha256(v).hexdigest() for v in values] == [FIRST_SHA256, SECOND_SHA256, TAIL_SHA256]
    assert values == (wire.signal(10, TARGET, 2, wire.u32(1) + wire.u32(0), 'hh'),
                      wire.signal(11, TARGET, 2, wire.u32(0) + wire.u32(1), 'hh'),
                      wire.signal(12, TARGET, None, b'', ''))
    return values


def selection():
    return [(mode, split) for mode in ('rights_with_prefix', 'rights_at_split') for split in range(1, 144)]


def role(index):
    return 'source-' + str(index)


def placement(mode, split):
    assert (mode, split) in selection()
    if mode == 'rights_with_prefix':
        return [(FIRST[:split], True)]
    return ([(FIRST[:split - 1], False)] if split > 1 else []) + [(FIRST[split - 1:split], True)]


def fields(row):
    return {int(k): v for k, v in row['fields'].items()}


def validate_cases(cases):
    assert [(row['mode'], row['split']) for row in cases] == selection()
    assert all(row['result'] == 'PASS' for row in cases)


def control_ids(controls):
    identities = []
    for control in controls:
        assert (control['level'], control['kind']) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        raw = bytes.fromhex(control['hex'])
        assert raw and len(raw) % 4 == 0
        fds = list(struct.unpack('=' + 'i' * (len(raw) // 4), raw))
        assert fds == control['fds'] and len(fds) == len(control['identities'])
        assert len(set(fds)) == len(fds) and all(fd >= 0 for fd in fds)
        assert all(name.startswith('pipe:[') and name.endswith(']') for name in control['identities'])
        identities.extend(control['identities'])
    return identities


def validate_send(row):
    data, requested = bytes.fromhex(row['hex']), bytes.fromhex(row['requested_hex'])
    assert row['outcome'] == 'sent' and row['method'] in ('send', 'sendmsg')
    assert row['monotonic'] <= row['completed']
    assert row['requested'] == len(requested) and row['count'] == len(data) > 0
    assert data == requested[:len(data)] and len(data) <= len(requested)
    assert row['method'] == 'sendmsg' or row['controls'] == []
    control_ids(row['controls'])
    return data


def validate_placement(rows, mode, split, identities):
    """Validate actual partial completions, with exactly one ancillary transfer."""
    expected = [(data, identities if rights else []) for data, rights in placement(mode, split)]
    validate_chunks(rows, expected)
    assert b''.join(bytes.fromhex(row['hex']) for row in rows) == FIRST[:split]


def validate_chunks(rows, expected):
    assert rows and expected
    cursor, part_index = 0, 0
    for row in rows:
        assert part_index < len(expected)
        data = validate_send(row)
        wanted, identities = expected[part_index]
        assert bytes.fromhex(row['requested_hex']) == wanted[cursor:]
        assert control_ids(row['controls']) == (identities if cursor == 0 else [])
        assert row['method'] == ('sendmsg' if identities and cursor == 0 else 'send')
        cursor += len(data)
        assert cursor <= len(wanted)
        if cursor == len(wanted):
            cursor, part_index = 0, part_index + 1
    assert part_index == len(expected) and cursor == 0


def validate_hold(barrier, identity, trace, ioctl, kernel, baseline, identities):
    reference.validate_barrier(barrier, identity, trace, ioctl, kernel)
    held = barrier['inventory']
    assert barrier['first']['finished'] <= held['started'] <= held['finished'] <= barrier['second']['started']
    assert len(held['fds']) == len(baseline) + 2
    assert all(held['fds'].get(fd) == value for fd, value in baseline.items())
    added = {fd: value for fd, value in held['fds'].items() if fd not in baseline}
    assert sorted(added.values()) == sorted(identities) and len(set(identities)) == 2
    assert set(held['fdinfo']) == set(added)
    for fd, identity in added.items():
        info = held['fdinfo'][fd]
        flags, = [int(line.split()[1], 8) for line in info['raw'].splitlines() if line.startswith('flags:')]
        inode, = [int(line.split()[1]) for line in info['raw'].splitlines() if line.startswith('ino:')]
        assert info['flags'] == flags and flags & os.O_CLOEXEC
        assert identity == 'pipe:[' + str(inode) + ']'
    assert barrier['fences']
    for fence in barrier['fences']:
        assert fence['pending'] is False
        assert barrier['first']['finished'] <= fence['started'] <= fence['finished'] <= barrier['second']['started']


def validate_receipts(rows, source, bundles):
    assert len(rows) == 3 and len(bundles) == 2
    assert set(bundles[0]['identities']).isdisjoint(bundles[1]['identities'])
    for index, row in enumerate(rows):
        bundle = bundles[index] if index < 2 else dict(identities=[], payloads=[])
        body = (wire.u32(1) + wire.u32(0), wire.u32(0) + wire.u32(1), b'')[index]
        normalized = dict(row, fields=fields(row))
        fd_donor.validate(normalized, 10 + index, source, TARGET, body,
                          bundle['identities'], bundle['payloads'])
        assert fields(row).get(1) == '/foundation'
        assert fields(row).get(2) == 'org.foundation.Transport'
        validate_wire_receipt(row)


def validate_wire_receipt(row):
    """The existing bounded reference frame oracle, also allowing header9."""
    raw = bytes.fromhex(row['wire_hex'])
    assert binary_frames(raw) == [raw]
    header_size = struct.unpack_from('<I', raw, 12)[0]
    header, values, ordered, offset = raw[16:16 + header_size], fields(row), [], 0
    signatures = {1:'o', 2:'s', 3:'s', 4:'s', 5:'u', 6:'s', 7:'s', 8:'g', 9:'u'}
    while offset < header_size:
        offset += -offset % 8
        assert offset + 4 <= header_size
        code = header[offset]
        assert code in signatures and code in values and code not in [v[0] for v in ordered]
        signature, value = signatures[code], values[code]
        assert header[offset:offset + 4] == bytes([code, 1]) + signature.encode() + b'\0'
        ordered.append((code, signature, value))
        offset += 4 + (5 + len(value.encode()) if signature in ('s', 'o') else
                       2 + len(value.encode()) if signature == 'g' else 4)
    assert offset == header_size and len(ordered) == len(values)
    assert raw == wire.frame(row['type'], row['serial'], ordered, bytes.fromhex(row['body']), flags=raw[2])
    return raw


def validate_stream(trace, prelude, receipts):
    """Consume exact frame extents; controls must belong to that frame's reads."""
    received = [row for row in trace if row['direction'] == 'receive']
    expected = prelude + b''.join(validate_wire_receipt(row) for row in receipts)
    assert b''.join(bytes.fromhex(row['hex']) for row in received) == expected
    bounds, offset = [], len(prelude)
    for receipt in receipts:
        end = offset + len(bytes.fromhex(receipt['wire_hex']))
        bounds.append((offset, end, receipt))
        offset = end
    cursor, assigned = 0, [[] for _ in bounds]
    for row in received:
        data = bytes.fromhex(row['hex'])
        assert data and row['requested'] >= len(data) and row.get('error') is None
        assert row['flags'] == 0 and row['monotonic'] <= row['completed']
        end = cursor + len(data)
        ids = control_ids(row['controls'])
        if cursor < len(prelude):
            assert end <= len(prelude) and not ids
        else:
            matches = [i for i, (lo, hi, _) in enumerate(bounds) if lo <= cursor < end <= hi]
            assert len(matches) == 1, 'receive crosses an unaccounted frame boundary'
            assigned[matches[0]].extend(ids)
        cursor = end
    assert cursor == len(expected)
    for ids, (_, _, receipt) in zip(assigned, bounds):
        assert ids == receipt.get('identities', [])
        assert len(ids) == fields(receipt).get(9, 0)


class TracedSocket(reference.TracedSocket):
    def sendall(self, data):
        while data:
            began = time.monotonic()
            count = self.raw.send(data)
            assert 0 < count <= len(data)
            self.record('send', data[:count], began, method='send', requested_hex=data.hex(),
                        requested=len(data), count=count, outcome='sent', controls=[])
            data = data[count:]

    def sendmsg(self, buffers, controls):
        data = b''.join(buffers)
        assert data
        evidence = []
        for level, kind, value in controls:
            assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            descriptors = array.array('i')
            descriptors.frombytes(bytes(value))
            evidence.append(dict(level=level, kind=kind, hex=bytes(value).hex(), fds=list(descriptors),
                                 identities=[os.readlink('/proc/self/fd/' + str(fd)) for fd in descriptors]))
        began = time.monotonic()
        count = self.raw.sendmsg(buffers, controls)
        assert 0 < count <= len(data)
        self.record('send', data[:count], began, method='sendmsg', requested_hex=data.hex(),
                    requested=len(data), count=count, outcome='sent', controls=evidence)
        return count

    def recvmsg(self, length, control_size):
        began = time.monotonic()
        data, controls, flags, address = self.raw.recvmsg(length, control_size, socket.MSG_CMSG_CLOEXEC)
        evidence = []
        try:
            for level, kind, value in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                descriptors = array.array('i')
                descriptors.frombytes(value)
                evidence.append(dict(level=level, kind=kind, hex=value.hex(), fds=list(descriptors),
                                     identities=[os.readlink('/proc/self/fd/' + str(fd)) for fd in descriptors]))
            self.record('receive', data, began, requested=length, flags=flags & ~socket.MSG_CMSG_CLOEXEC,
                        returned_flags=flags, call_flags=socket.MSG_CMSG_CLOEXEC, controls=evidence)
        except BaseException:
            for level, kind, value in controls:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    descriptors = array.array('i')
                    descriptors.frombytes(value)
                    wire.close_fds(descriptors)
            raise
        return data, controls, flags & ~socket.MSG_CMSG_CLOEXEC, address


class Client(hello.NormalClient):
    def __init__(self, path, daemon_pid, name, negotiate):
        self.role, self.trace, self.writes, self.receipts = name, [], [], []
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock = TracedSocket(raw, name, self.trace)
        try:
            raw.settimeout(3)
            raw.connect(path)
            self.connection = reference.connection(raw)
            peer = list(struct.unpack('3i', raw.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
            assert peer == [daemon_pid, os.getuid(), os.getgid()]
            emit('identity', role=name, pid=os.getpid(), starttime_ticks=reference.starttime(),
                 uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
                 proc_status=Path('/proc/self/status').read_text())
            emit('connection', role=name, connection=self.connection, peer_credentials=peer, endpoint=path)
            self.send(auth_command(os.getuid()))
            self.auth = self.line()
            validate_ok(self.auth)
            self.empty()
            if negotiate:
                self.send(NEGOTIATE)
                self.agree = self.line()
                assert self.agree == AGREE
                self.empty()
            else:
                self.agree = b''
            self.send(BEGIN + hello.HELLO + hello.GET_ID)
            self.registration, self.bus_id = hello.registration(self)
            reference.validate_completion(self.registration, self.name, self.bus_id.hex())
            emit('registered', role=name, name=self.name, auth=self.auth.hex(), agree=self.agree.hex(),
                 registration=self.registration, bus_id=self.bus_id.hex(), connection=self.connection)
        except BaseException:
            raw.close()
            raise

    def receive(self):
        began = len(self.trace)
        row = wire.Client.receive(self)
        raw = b''.join(bytes.fromhex(v['hex']) for v in self.trace[began:] if v['direction'] == 'receive')
        assert binary_frames(raw) == [raw]
        self.last_wire = raw.hex()
        return row

    def messages(self, count):
        rows = []
        for _ in range(count):
            message = self.receive()
            if message['fds']:
                wire.close_fds(message['fds'])
                raise AssertionError('rights outside Resource receipts')
            row = dict(type=message['type'], serial=message['serial'], fields=message['fields'],
                       body=message['body'].hex(), wire_hex=self.last_wire)
            self.receipts.append(row)
            emit('receipt', role=self.role, receipt=row)
            rows.append(row)
        return rows

    def reply(self, serial):
        raise AssertionError('unaccounted Client.reply is forbidden')

    def resource(self):
        row = dict(fd_donor.receipt(self), wire_hex=self.last_wire)
        self.receipts.append(row)
        emit('receipt', role=self.role, receipt=row)
        return row

    def fence(self):
        began = time.monotonic()
        identity = reference.connection(self.sock)
        assert identity == self.connection
        pending = bool(select.select([self.sock], [], [], 0)[0])
        result = dict(started=began, finished=time.monotonic(), pending=pending, connection=identity)
        assert not pending, result
        return result


def inventory(pid, baseline=None):
    began = time.monotonic()
    fds = fd_donor.inventory(str(pid))
    fdinfo = {}
    if baseline is not None:
        for fd in fds.keys() - baseline.keys():
            raw = Path('/proc', str(pid), 'fdinfo', fd).read_text()
            flags, = [int(line.split()[1], 8) for line in raw.splitlines() if line.startswith('flags:')]
            fdinfo[fd] = dict(flags=flags, raw=raw)
    return dict(started=began, finished=time.monotonic(), fds=fds, fdinfo=fdinfo)


def role_process(path, daemon_pid, name):
    """One exec-created source/target owns its socket and every pipe it creates."""
    signal.alarm(45)
    client = None
    readers, writers, bundles = [], [], []
    try:
        assert select.select([sys.stdin], [], [], 3)[0], 'role OPEN3s deadline'
        line = sys.stdin.buffer.readline(65537)
        assert line and len(line) <= 65536
        request = json.loads(line)
        raw = Path('/proc/self/stat').read_text()
        ticks = int(raw[raw.rfind(')') + 2:].split()[19])
        accepted = time.monotonic()
        assert request['command'] == 'open' and request['role'] == name
        assert request['pid'] == os.getpid() and request['starttime_ticks'] == ticks
        assert request['requested'] <= accepted <= request['deadline']
        emit('role_open_gate', role=name, pid=os.getpid(), starttime_ticks=ticks,
             command='open', accepted=accepted, deadline=request['deadline'],
             client_created=client is not None, resource_fds=len(readers) + len(writers))
        client = Client(path, daemon_pid, name, True)
        emit('response', command='open', name=client.name, connection=client.connection,
             registration=client.registration, bus_id=client.bus_id.hex())
        health_serial = 20
        while True:
            assert select.select([sys.stdin], [], [], 3)[0], 'role command3s deadline'
            line = sys.stdin.buffer.readline(65537)
            assert line and len(line) <= 65536
            request = json.loads(line)
            command = request['command']
            if command == 'prefix':
                assert name.startswith('source-') and not readers and not writers
                new_readers, new_writers, ids, payloads = fd_donor.bundle(name + '-first')
                readers.extend(new_readers)
                writers.extend(new_writers)
                bundles.append(dict(identities=ids, payloads=payloads))
                began = len(client.trace)
                for data, rights in placement(request['mode'], request['split']):
                    if rights: client.send_fds(data, readers)
                    else: client.send(data)
                wire.close_fds(readers)
                readers.clear()
                prefix = client.trace[began:]
                validate_placement(prefix, request['mode'], request['split'], ids)
                deadline = prefix[-1]['completed'] + 1
                emit('response', command=command, bundle=bundles[0], prefix_sends=prefix,
                     prefix_trace=list(client.trace), deadline=deadline)
            elif command == 'sample':
                sample = reference.queue(client.sock, client.connection, client.trace)
                emit('response', command=command, sample=sample)
            elif command == 'fence':
                emit('response', command=command, fence=client.fence())
            elif command == 'release':
                client.send(FIRST[request['split']:])
                new_readers, new_writers, ids, payloads = fd_donor.bundle(name + '-second')
                readers.extend(new_readers)
                writers.extend(new_writers)
                bundles.append(dict(identities=ids, payloads=payloads))
                client.send_fds(SECOND, readers)
                wire.close_fds(readers)
                readers.clear()
                client.send(TAIL)
                emit('response', command=command, bundles=bundles)
            elif command == 'receipts':
                rows = [client.resource() for _ in range(3)]
                client.empty()
                emit('response', command=command, receipts=rows, fence=client.fence())
            elif command == 'health':
                began = time.monotonic()
                rows = hello.health(client, client.name, client.bus_id, health_serial)
                health_serial += 2
                emit('response', command=command, name=client.name, bus_id=client.bus_id.hex(),
                     receipts=rows, started=began, finished=time.monotonic(), fence=client.fence())
            elif command == 'reclaim':
                # One actual write per writer; never infer reclamation from descriptor counts.
                checks = []
                for writer, identity in zip(writers, [i for b in bundles for i in b['identities']]):
                    began = time.monotonic()
                    fd_donor.reclaimed([writer])
                    checks.append(dict(writer=writer, identity=identity, outcome='BrokenPipeError',
                                       started=began, finished=time.monotonic()))
                assert len(checks) == 4
                wire.close_fds(writers)
                writers.clear()
                emit('response', command=command, checks=checks, fence=client.fence())
            elif command == 'stop':
                assert not readers and not writers
                client.empty()
                client.close()
                client = None
                emit('response', command=command, closed=True, readers=0, writers=0)
                break
            else:
                raise AssertionError(command)
    finally:
        wire.close_fds(readers)
        wire.close_fds(writers)
        if client is not None:
            client.close()


class Role:
    def __init__(self, path, daemon_pid, name):
        self.name, self.buffer, self.events, self.errors, self.closed = name, b'', [], b'', False
        self.path, self.daemon_pid = path, daemon_pid
        self.process = self.opened = None
        self.ticks = None

    def launch(self):
        assert self.process is None
        began = time.monotonic()
        self.process = subprocess.Popen([sys.executable, '-S', '-B', str(Path(__file__).resolve()),
                                        '--role', self.path, str(self.daemon_pid), self.name],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=dict(PATH=os.defpath, LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1'))
        completed = time.monotonic()
        self.deadline = completed + 3
        raw = Path('/proc', str(self.process.pid), 'stat').read_text()
        self.ticks = int(raw[raw.rfind(')') + 2:].split()[19])
        emit('role_launch', role=self.name, pid=self.process.pid, starttime_ticks=self.ticks,
             started=began, completed=completed, deadline=self.deadline)

    def open(self):
        assert self.process is not None and self.opened is None
        requested = time.monotonic()
        assert requested < self.deadline, 'original role launch3s deadline'
        values = dict(role=self.name, pid=self.process.pid, starttime_ticks=self.ticks,
                      requested=requested)
        emit('role_open_request', command='open', deadline=self.deadline, **values)
        self.opened = self.ask('open', deadline=self.deadline, launch_deadline=self.deadline, **values)
        completed = time.monotonic()
        assert completed <= self.deadline, 'original role OPEN completion3s deadline'
        assert self.opened['connection']['pid'] == self.process.pid
        proc = Path('/proc', str(self.process.pid))
        raw = (proc / 'stat').read_text()
        ticks = int(raw[raw.rfind(')') + 2:].split()[19])
        assert ticks == self.ticks == self.opened['connection']['starttime_ticks']
        executable = os.readlink(proc / 'exe')
        assert Path(executable).resolve() == Path(sys.executable).resolve()
        emit('role_process', role=self.name, pid=self.process.pid, starttime_ticks=ticks,
             proc_stat=raw, executable=executable, cmdline=(proc / 'cmdline').read_bytes().hex(),
             opened_completed=completed, deadline=self.deadline)

    def response(self, command, deadline):
        while True:
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                assert len(line) <= 2**20
                row = json.loads(line)
                self.events.append(row)
                if row['event'] == 'response':
                    assert row['command'] == command
                    # Preserve every child's protocol output as well as wire rows.
                    emit('role_response', role=self.name, response=row)
                    return row
                emit(**row)
            remaining = deadline - time.monotonic()
            assert remaining > 0, (self.name, command, 'stdio deadline')
            ready = select.select([self.process.stdout, self.process.stderr], [], [], remaining)[0]
            assert ready, (self.name, command, 'stdio timeout')
            for stream in ready:
                chunk = os.read(stream.fileno(), 65536)
                if stream is self.process.stderr:
                    self.errors += chunk
                    if chunk:
                        emit('role_stderr', role=self.name, hex=chunk.hex())
                    assert not chunk, (self.name, 'child stderr')
                else:
                    assert chunk, (self.name, command, 'unexpected EOF', self.process.poll())
                    self.buffer += chunk
                    assert len(self.buffer) <= 2**21

    def ask(self, command, deadline=None, **values):
        deadline = min(deadline or time.monotonic() + 3, time.monotonic() + 3)
        if command == 'open':
            values['deadline'] = values.pop('launch_deadline')
        data = (json.dumps(dict(command=command, **values)) + '\n').encode()
        assert len(data) < 4096
        assert select.select([], [self.process.stdin], [], max(0, deadline - time.monotonic()))[1]
        assert os.write(self.process.stdin.fileno(), data) == len(data)
        return self.response(command, deadline)

    def shutdown(self, normal, deadline=None):
        if self.closed or self.process is None:
            return
        began = time.monotonic()
        deadline = deadline if deadline is not None else began + 5
        failure = None
        try:
            try:
                if normal:
                    assert self.ask('stop', deadline=deadline)['closed'] is True
            except BaseException as error:
                failure = repr(error)
            if (not normal or failure) and self.process.poll() is None:
                self.process.terminate()
            try:
                code = self.process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                # Failed cleanup remains failed evidence; the unchanged lifecycle
                # monitor also checks the complete owned process/group census.
                failure = failure or 'role cleanup5s deadline'
                self.process.kill()
                code = self.process.wait(timeout=max(0, deadline - time.monotonic()))
            remaining_out = self.process.stdout.read()
            remaining_err = self.process.stderr.read()
            finished = time.monotonic()
            emit('role_shutdown', role=self.name, pid=self.process.pid, starttime_ticks=self.ticks, returncode=code,
                 stdout_tail=(self.buffer + remaining_out).hex(), stderr_tail=remaining_err.hex(),
                 pid_absent=not Path('/proc', str(self.process.pid)).exists(),
                 seconds=finished - began, started=began, finished=finished, deadline=deadline,
                 normal=normal, failure=failure)
            assert finished <= deadline, 'role cleanup5s deadline'
            assert not normal or (failure is None and code == 0 and not self.buffer and not remaining_out and not remaining_err)
            assert not Path('/proc', str(self.process.pid)).exists()
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
            self.closed = True


def run(path, fixture_dir, daemon_pid):
    assert not sys.flags.optimize and sys.platform == 'linux'
    assert os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    assert Path(fixture_dir).resolve() == FIXTURES
    assert Path(path).is_absolute() and Path(path).parent.stat().st_mode & 0o777 == 0o700
    assert not any(key.startswith('DBUS_') for key in os.environ)
    vectors()
    emit('literals', vectors=[v.hex() for v in vectors()], sha256=[FIRST_SHA256, SECOND_SHA256, TAIL_SHA256])
    signal.alarm(45)
    control = reference.kernel_control()
    observer = source = target = pending = None
    cases, serial = [], 10
    def query(member, name):
        nonlocal serial
        current = serial
        serial += 1
        observer.send(wire.call(member, current, 's', wire.string(name)))
        row, = observer.messages(1)
        observer.empty()
        return dict(member=member, name=name, serial=current, receipt=row)
    def health(source_name=None):
        nonlocal serial
        began = time.monotonic()
        rows = hello.health(observer, OBSERVER, observer.bus_id, serial)
        serial += 2
        result = dict(started=began, observer=observer.name, owned=OBSERVER,
                      bus_id=observer.bus_id.hex(), receipts=rows)
        if source_name is not None:
            result['owner'] = query('GetNameOwner', source_name)
            assert hello.reply(result['owner']['receipt'], result['owner']['serial']) == wire.string(source_name)
        result['finished'] = time.monotonic()
        return result
    def credentials(opened):
        name, identity = opened['name'], opened['connection']
        rows = [query(member, name) for member in ('GetNameOwner', 'GetConnectionUnixUser', 'GetConnectionUnixProcessID')]
        for row, expected in zip(rows, (wire.string(name), wire.u32(os.getuid()), wire.u32(identity['pid']))):
            assert hello.reply(row['receipt'], row['serial']) == expected
        return rows
    try:
        observer = Client(path, daemon_pid, 'observer', False)
        assert observer.name == ':1.0'
        request = wire.string(OBSERVER)
        observer.send(wire.call('RequestName', 3, 'su', request + b'\0' * (-len(request) % 4) + wire.u32(0)))
        ownership = observer.messages(2)
        returns = [v for v in ownership if v['type'] == 2]
        signals = [v for v in ownership if v['type'] == 4]
        assert len(returns) == len(signals) == 1
        assert hello.reply(returns[0], 3) == wire.u32(1)
        hello.acquired(signals[0], OBSERVER, observer.name)
        observer.empty()
        source = Role(path, daemon_pid, role(0))
        source.launch()
        source.open()
        assert source.opened['name'] == ':1.1'
        target = Role(path, daemon_pid, 'target')
        target.launch()
        target.open()
        assert target.opened['name'] == TARGET
        observer_opened = dict(name=observer.name, connection=observer.connection)
        initial_credentials = dict(observer=credentials(observer_opened), target=credentials(target.opened))
        emit('ready', observer=observer.name, target=TARGET, owned=OBSERVER, bus_id=observer.bus_id.hex(),
             ownership=ownership, credentials=initial_credentials)
        for index, (mode, split) in enumerate(selection()):
            if index:
                source, pending = pending, None
                assert source is not None and source.name == role(index)
                source.open()
            source_name = source.opened['name']
            assert source_name == ':1.' + str(1 if index == 0 else index + 2)
            assert source.opened['bus_id'] == target.opened['bus_id'] == observer.bus_id.hex()
            if index < 285:
                assert pending is None
                pending = Role(path, daemon_pid, role(index + 1))
                pending.launch()
            credential_rows = credentials(source.opened)
            before = health(source_name)
            target_health = target.ask('health')
            baseline_snapshot = inventory(daemon_pid)
            baseline = baseline_snapshot['fds']
            prefix = source.ask('prefix', mode=mode, split=split)
            barrier = dict(started=time.monotonic(), samples=[])
            deadline = prefix['deadline']
            while True:
                assert time.monotonic() < deadline, 'held-prefix1s deadline'
                sample = source.ask('sample', deadline=deadline)['sample']
                barrier['samples'].append(sample)
                if sample['allocation'] == 0:
                    barrier['first'] = sample
                    break
            observer.sock.settimeout(max(.001, deadline - time.monotonic()))
            barrier['health'] = health(source_name)
            barrier['fences'] = [target.ask('fence', deadline=deadline)['fence']]
            barrier['inventory'] = inventory(daemon_pid, baseline)
            barrier['second'] = source.ask('sample', deadline=deadline)['sample']
            barrier['finished'] = time.monotonic()
            validate_hold(barrier, source.opened['connection'], prefix['prefix_trace'],
                          control['ioctl'], control['kernel'], baseline, prefix['bundle']['identities'])
            observer.sock.settimeout(3)
            release = source.ask('release', split=split)
            delivered = target.ask('receipts')
            validate_receipts(delivered['receipts'], source_name, release['bundles'])
            settlement = time.monotonic()
            while True:
                assert time.monotonic() < settlement + 1.5, 'FD settlement1.5s deadline'
                final_snapshot = inventory(daemon_pid)
                if final_snapshot['fds'] == baseline:
                    break
            reclaim = source.ask('reclaim', deadline=settlement + 1.5)
            after_reclaim = inventory(daemon_pid)
            assert after_reclaim['fds'] == baseline
            assert time.monotonic() <= settlement + 1.5
            settlement_evidence = dict(started=settlement, finished=time.monotonic(),
                                       restored=final_snapshot, after_reclaim=after_reclaim)
            source_fence = reclaim['fence']
            source.shutdown(True)
            source = None
            began, gone = time.monotonic(), []
            while True:
                assert time.monotonic() < began + 1.5, 'name disappearance1.5s deadline'
                observer.sock.settimeout(max(.001, began + 1.5 - time.monotonic()))
                row = query('GetNameOwner', source_name)
                gone.append(row)
                if row['receipt']['type'] == 3:
                    assert fields(row['receipt']).get(4) == 'org.freedesktop.DBus.Error.NameHasNoOwner'
                    break
                assert hello.reply(row['receipt'], row['serial']) == wire.string(source_name)
            observer.sock.settimeout(3)
            disappearance_seconds = time.monotonic() - began
            after = health()
            live_health = target.ask('health')
            case = dict(mode=mode, split=split, index=index, result='PASS', source=source_name,
                        source_role=role(index), connection=barrier['first']['connection'],
                        credentials=credential_rows, before_health=before, target_before=target_health,
                        baseline=baseline, baseline_snapshot=baseline_snapshot,
                        prefix=prefix, barrier=barrier, bundles=release['bundles'],
                        receipts=delivered['receipts'], target_fence=delivered['fence'],
                        reclaim=reclaim, settlement=settlement_evidence, final_fds=final_snapshot['fds'],
                        source_pending=source_fence['pending'], target_pending=delivered['fence']['pending'],
                        target_health=live_health, disappearance=gone,
                        disappearance_seconds=disappearance_seconds, after_health=after,
                        internal_accounting='UNSUPPORTED', source_parser_buffer='UNSUPPORTED')
            cases.append(case)
            emit('case', **case)
            emit('case_retired', role=role(index), index=index,
                 pid=case['connection']['pid'], starttime_ticks=case['connection']['starttime_ticks'],
                 finished=time.monotonic())
        validate_cases(cases)
        final_health = health()
        final_target = target.ask('health')
        target.shutdown(True)
        target = None
        observer.empty()
        observer.close()
        observer = None
        emit('result', result='PASS', cases=286, connections=288, fd_frames=572, usable_resources=1144,
             non_fd_tails=286, final_health=final_health, target_health=final_target,
             internal_accounting='UNSUPPORTED', source_parser_buffer='UNSUPPORTED', native_frames_per_read='UNSUPPORTED')
    finally:
        children = [child for child in (pending, source, target)
                    if child is not None and child.process is not None and not child.closed]
        failures = []
        if children:
            began = time.monotonic()
            deadline = began + 5
            emit('failure_cleanup', started=began, deadline=deadline)
            for child in children:
                if child.process.poll() is None:
                    child.process.terminate()
            for child in children:
                try:
                    child.shutdown(False, deadline=deadline)
                except BaseException as error:
                    failures.append(repr(error))
        if observer is not None:
            observer.close()
        assert not failures, failures


if __name__ == '__main__':
    assert not sys.flags.optimize and os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    if len(sys.argv) == 5 and sys.argv[1] == '--role':
        vectors()
        role_process(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    else:
        assert len(sys.argv) == 4
        run(sys.argv[1], sys.argv[2], int(sys.argv[3]))
