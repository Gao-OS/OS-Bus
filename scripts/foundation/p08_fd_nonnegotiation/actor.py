"""Independent FD-05 Linux actor; frozen wire helpers, explicit private socket."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

sys.dont_write_bytecode = True

WORKLOAD = json.loads(Path(__file__).with_name('workload.json').read_text())
BUS = 'org.freedesktop.DBus'
wire = mixed = None


def load_wire(directory):
    global wire, mixed
    directory = Path(directory)
    for name in ('transport_actor', 'broadcast_delivery_actor'):
        spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        if name == 'transport_actor':
            wire = module
        else:
            mixed = module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fd_inventory():
    rows = []
    for item in sorted(os.listdir('/proc/self/fd'), key=int):
        fd = int(item)
        try:
            info = os.fstat(fd)
            target = os.readlink('/proc/self/fd/' + item)
        except FileNotFoundError:
            continue  # os.listdir's already-closed directory descriptor.
        except OSError as error:
            if error.errno == 9:
                continue
            raise
        rows.append({'fd': fd, 'target': target, 'dev': info.st_dev, 'ino': info.st_ino,
                     'mode': info.st_mode, 'size': info.st_size})
    return {'count': len(rows), 'targets': rows}


def identity():
    pid, uid, gid = os.getpid(), os.getuid(), os.getgid()
    status = Path('/proc/self/status').read_text().splitlines()
    ids = {line.split(':', 1)[0]: [int(value) for value in line.split(':', 1)[1].split()]
           for line in status if line.startswith(('Uid:', 'Gid:', 'NSpid:', 'NStgid:'))}
    process = {'pid': pid, 'uid': uid, 'gid': gid,
               'executable': os.readlink('/proc/self/exe'),
               'argv': Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
               'starttime_ticks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]),
               'kernel_ids': ids, 'python_version': sys.version, 'kernel_release': os.uname().release}
    return {'pid': pid, 'uid': uid, 'gid': gid, 'process': process, 'fds': fd_inventory()}


class DeadlineSocket:
    """Apply one absolute operation deadline to the unchanged recvmsg primitive."""
    def __init__(self, client, sock):
        self.client, self.raw = client, sock

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def bounded(self):
        if self.client.deadline_at is not None:
            remaining = self.client.deadline_at - time.monotonic()
            assert remaining > 0, 'absolute actor socket deadline'
            self.raw.settimeout(remaining)

    def recvmsg(self, *args):
        self.bounded()
        data, controls, flags, address = self.raw.recvmsg(*args)
        self.client.capture.extend(data)
        for level, kind, rights in controls:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                received = wire.array.array('i')
                received.frombytes(rights)
                self.client.received_rights += len(received)
                for fd in received:
                    info = os.fstat(fd)
                    self.client.received_fd_targets.append({'fd': fd,
                        'target': os.readlink('/proc/self/fd/%d' % fd),
                        'dev': info.st_dev, 'ino': info.st_ino, 'mode': info.st_mode, 'size': info.st_size})
        # The frozen reader validates truncation before adopting the controls.
        # Close any kernel-installed rights here on that early failure path.
        if flags & socket.MSG_CTRUNC or not data:
            for level, kind, rights in controls:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    received = wire.array.array('i'); received.frombytes(rights)
                    wire.close_fds(received)
            raise AssertionError('closed or truncated actor frame')
        return data, controls, flags, address

    def recv(self, *args):
        self.bounded()
        return self.raw.recv(*args)

    def sendall(self, data):
        self.bounded()
        if data.startswith(b'l'):
            self.client.record_sent(data, 0)
        elif data.startswith(b'BEGIN\r\n'):
            self.client.record_sent(data[7:], 0)
        return self.raw.sendall(data)

    def sendmsg(self, data, controls):
        self.bounded()
        self.client.record_sent(b''.join(data), sum(len(control[2]) for control in controls))
        return self.raw.sendmsg(data, controls)


class ObservedClient:
    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, value):
        self._sock = DeadlineSocket(self, value)

    def configure(self, sock, role, events):
        self.role, self.events = role, events
        self.deadline_at, self.capture = None, bytearray()
        self.received_rights, self.received_fd_targets = 0, []
        self.last_received_fds = []
        self.phase = 'setup'
        self.negotiation = {'requested': False, 'auth_reply': None, 'fd_reply': None}
        if sock is not None:
            sock.settimeout(WORKLOAD['socket_ms'] / 1000)
            self.sock = sock

    def __init__(self, path, role, events, negotiate=True):
        self.configure(None, role, events)
        self.negotiation['requested'] = negotiate
        try:
            with self.deadline(WORKLOAD['socket_ms']):
                wire.Client.__init__(self, path, negotiate)
            self.phase = 'active'
        except BaseException:
            if hasattr(self, '_sock'):
                self.close()
            raise

    @contextmanager
    def deadline(self, milliseconds):
        previous = self.deadline_at
        candidate = time.monotonic() + milliseconds / 1000
        self.deadline_at = candidate if previous is None else min(previous, candidate)
        try:
            yield
            assert time.monotonic() <= self.deadline_at, 'absolute actor socket deadline'
        finally:
            self.deadline_at = previous
            if hasattr(self, '_sock'):
                self.sock.settimeout(WORKLOAD['socket_ms'] / 1000)

    def line(self):
        result = wire.Client.line(self)
        if result.startswith(b'OK '):
            self.negotiation['auth_reply'] = result.decode().rstrip('\r\n')
        elif result == b'AGREE_UNIX_FD\r\n':
            self.negotiation['fd_reply'] = result.decode().rstrip('\r\n')
        return result

    def record_sent(self, data, rights):
        self.events['sent'].append({'role': self.role, 'phase': self.phase,
             'wire_hex': data.hex(), 'wire_sha256': digest(data), 'wire_bytes': len(data),
             'rights': rights})

    def read(self, length, fds):
        return wire.Client.read(self, length, fds)

    def receive(self):
        self.capture = bytearray()
        self.received_rights, self.received_fd_targets = 0, []
        with self.deadline(WORKLOAD['socket_ms']):
            try:
                message = wire.Client.receive(self)
            except BaseException as error:
                self.events['received'].append({'role': self.role, 'phase': self.phase,
                     'wire_hex': self.capture.hex(), 'wire_sha256': digest(self.capture),
                     'rights': self.received_rights, 'fd_targets': self.received_fd_targets, 'error': repr(error)})
                raise
        self.last_received_fds = message['fds']
        self.events['received'].append({'role': self.role, 'phase': self.phase,
             'type': message['type'], 'serial': message['serial'], 'fields': message['fields'],
             'body_hex': message['body'].hex(), 'rights': len(message['fds']),
             'fd_targets': self.received_fd_targets,
             'wire_hex': self.capture.hex(), 'wire_sha256': digest(self.capture)})
        return message

    def reply(self, serial):
        assert self.phase == 'setup', 'permissive reply filtering forbidden after setup'
        try:
            message = wire.Client.reply(self, serial)
            assert not message['fds'], 'resource-bearing bootstrap reply'
            return message
        except BaseException:
            wire.close_fds(self.last_received_fds)
            self.last_received_fds = []
            raise

    def barrier(self, serial):
        if self.phase == 'setup':
            return wire.Client.barrier(self, serial)
        return barrier(self, serial)

    def send_fds(self, data, fds):
        with self.deadline(WORKLOAD['socket_ms']):
            return wire.Client.send_fds(self, data, fds)

    def close(self):
        self.sock.close()

    def receipt(self):
        return {'role': self.role, 'name': self.name, 'unique_name': self.name,
                'negotiated': self.negotiation['fd_reply'] == 'AGREE_UNIX_FD',
                'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
                'socket_fd': self.sock.fileno(), 'negotiation': self.negotiation.copy()}


def healthy(client, serial):
    started = time.monotonic()
    with client.deadline(WORKLOAD['healthy_ms']):
        mixed.healthy(client, serial)
        observed = client.events['received'][-1]
        assert observed['fields'].get(8) == 's' and observed['fields'].get(9, 0) == 0, 'invalid healthy signature/resources'
    assert (time.monotonic() - started) * 1000 <= WORKLOAD['healthy_ms'], 'absolute health deadline'
    result = {'role': client.role, 'serial': serial, 'latency_ms': (time.monotonic() - started) * 1000}
    client.events['health'].append(result)
    return result


def barrier(client, serial):
    started = time.monotonic()
    with client.deadline(WORKLOAD['socket_ms']):
        client.sock.sendall(wire.call('ListNames', serial))
        message = client.receive()
        try:
            assert message['type'] == 2 and message['fields'].get(5) == serial, 'unexpected barrier frame'
            assert message['fields'].get(7) == BUS and message['fields'].get(6) == client.name
            assert message['fields'].get(8) == 'as' and not message['fds'], 'invalid barrier reply'
        finally:
            wire.close_fds(message['fds'])
    result = {'role': client.role, 'serial': serial, 'latency_ms': (time.monotonic() - started) * 1000}
    client.events['barriers'].append(result)
    return result


def denied(client):
    message = client.receive()
    try:
        assert message['type'] == 3 and message['fields'].get(5) == 3, 'unexpected denial frame'
        assert message['fields'].get(4) == WORKLOAD['unicast']['error'], 'wrong denial error'
        assert message['fields'].get(7) == BUS and message['fields'].get(6) == client.name
        assert not message['fds'], 'resource-bearing denial'
        return {'error_name': message['fields'][4], 'error_reply_serial': message['fields'][5]}
    finally:
        wire.close_fds(message['fds'])


def resource_receipt(fd, contents, role, pipe=False):
    info = os.fstat(fd)
    target = os.readlink('/proc/self/fd/%d' % fd)
    actual = os.read(fd, len(contents) + 1) if pipe else os.pread(fd, len(contents) + 1, 0)
    result = {'role': role, 'fd': fd, 'target': target, 'dev': info.st_dev, 'ino': info.st_ino,
              'mode': info.st_mode, 'size': info.st_size, 'contents_hex': actual.hex(),
              'contents_sha256': digest(actual), 'closed': False}
    assert actual == contents, 'wrong or unusable resource contents'
    return result


def receive_resource(client, source):
    message = mixed.received_signal(client, source, 100, 'Resource')
    result = None
    try:
        assert message['body'] == wire.u32(0) and message['fields'].get(8) == 'h'
        assert message['fields'].get(9) == 1 and len(message['fds']) == 1
        fd = message['fds'][0]
        result = resource_receipt(fd, mixed.CONTENTS, client.role)
        assert stat.S_ISREG(result['mode'])
        assert result['target'] == '/memfd:foundation-broadcast-%d (deleted)' % os.getpid()
        client.events['resources'].append(result)
    finally:
        wire.close_fds(message['fds'])
        if result is not None:
            result['closed'] = True
    return result


def receive_plain(client, source):
    message = mixed.received_signal(client, source, 200, 'Plain')
    try:
        assert message['fields'].get(8) == 's' and message['fields'].get(9, 0) == 0
        assert message['body'] == wire.string(mixed.PLAIN) and not message['fds']
    finally:
        wire.close_fds(message['fds'])


class Workload:
    def __init__(self, path):
        self.path, self.clients, self.case = path, [], None
        self.reset_events()

    def reset_events(self):
        self.events = {key: [] for key in ('sent', 'received', 'resources', 'health', 'barriers')}
        for client in self.clients:
            client.events = self.events

    def result(self, **details):
        return {**identity(), 'connections': [client.receipt() for client in self.clients],
                **self.events, **details}

    def connect(self, role, negotiate=True):
        client = ObservedClient(self.path, role, self.events, negotiate)
        self.clients.append(client)
        return client

    def open(self, case):
        assert not self.clients and case in WORKLOAD['cases'], 'case/state mismatch'
        self.reset_events()
        self.case = case
        self.connect('source')
        self.connect('target')
        self.connect('ordinary', False)
        if case == 'mixed':
            rule = "type='signal',interface='%s'" % mixed.INTERFACE
            for client in self.clients[1:]:
                with client.deadline(WORKLOAD['socket_ms']):
                    client.sock.sendall(wire.call('AddMatch', 3, 's', wire.string(rule)))
                    reply = client.receive()
                    try:
                        assert reply['type'] == 2 and reply['fields'].get(5) == 3
                        assert reply['fields'].get(7) == BUS and reply['fields'].get(6) == client.name
                        assert reply['body'] == b'' and not reply['fds']
                    finally:
                        wire.close_fds(reply['fds'])
        return self.result(case=case)

    def exercise(self):
        assert self.case is not None and len(self.clients) == 3, 'case not open'
        self.reset_events()
        before = fd_inventory()['count']
        source, target, ordinary = self.clients
        details = {}
        if self.case == 'unicast':
            fd = wire.pipe_payload(WORKLOAD['unicast']['contents'].encode())
            resource = None
            try:
                fields = [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
                     (3, 's', 'Resource'), (6, 's', ordinary.name), (8, 'g', 'h'), (9, 'u', 1)]
                source.send_fds(wire.frame(1, 3, fields, wire.u32(0)), [fd])
                details = denied(source)
                resource = resource_receipt(fd, b'DO-NOT-DELIVER', 'source', pipe=True)
                self.events['resources'].append(resource)
            finally:
                os.close(fd)
                if resource is not None:
                    resource['closed'] = True
            healthy(ordinary, 4)
            healthy(source, 5)
            assertions = {'resource_deliveries': 0, 'rights0_deliveries': 0, 'healthy_replies': 2}
        else:
            fd = os.memfd_create('foundation-broadcast-%d' % os.getpid(), os.MFD_CLOEXEC)
            resource = None
            try:
                assert os.write(fd, mixed.CONTENTS) == len(mixed.CONTENTS)
                resource = resource_receipt(fd, mixed.CONTENTS, 'source')
                self.events['resources'].append(resource)
                source.send_fds(mixed.signal(100, 'Resource', 'h', wire.u32(0), 1), [fd])
            finally:
                os.close(fd)
                if resource is not None:
                    resource['closed'] = True
            barrier(source, 101)
            receive_resource(target, source)
            for index, client in enumerate(self.clients):
                healthy(client, 110 + index)
            source.sock.sendall(mixed.signal(200, 'Plain', 's', wire.string(mixed.PLAIN)))
            barrier(source, 201)
            for client in (target, ordinary):
                receive_plain(client, source)
            for index, client in enumerate(self.clients):
                healthy(client, 210 + index)
            assertions = {'resource_deliveries': 1, 'rights0_deliveries': 2, 'healthy_replies': 6}
        growth = fd_inventory()['count'] - before
        assert growth == 0, 'actor descriptor leak'
        assertions.update(actor_fd_growth=growth, strict_first_message=True)
        return self.result(case=self.case, assertions=assertions, **details)

    def close(self):
        started = time.monotonic()
        for client in self.clients:
            client.close()
        self.clients = []
        self.case = None
        return self.result(closed=True, close_ms=(time.monotonic() - started) * 1000)

    def warmup(self):
        assert not self.clients, 'warmup requires closed actor'
        self.reset_events()
        before = fd_inventory()
        try:
            source = self.connect('source')
            target = self.connect('target')
            fd = os.memfd_create('foundation-broadcast-%d' % os.getpid(), os.MFD_CLOEXEC)
            resource = None
            try:
                assert os.write(fd, mixed.CONTENTS) == len(mixed.CONTENTS)
                resource = resource_receipt(fd, mixed.CONTENTS, 'source')
                self.events['resources'].append(resource)
                fields = [(1, 'o', '/broadcast'), (2, 's', mixed.INTERFACE),
                    (3, 's', 'Resource'), (8, 'g', 'h'), (9, 'u', 1), (6, 's', target.name)]
                source.send_fds(wire.frame(4, 100, fields, wire.u32(0)), [fd])
            finally:
                os.close(fd)
                if resource is not None:
                    resource['closed'] = True
            message = target.receive()
            received = None
            try:
                assert message['type'] == 4 and message['serial'] == 100
                assert message['fields'].get(1) == '/broadcast'
                assert message['fields'].get(2) == mixed.INTERFACE and message['fields'].get(3) == 'Resource'
                assert message['fields'].get(7) == source.name and message['fields'].get(6) == target.name
                assert message['fields'].get(8) == 'h' and message['fields'].get(9) == 1
                assert message['body'] == wire.u32(0) and len(message['fds']) == 1
                received = resource_receipt(message['fds'][0], mixed.CONTENTS, 'target')
                assert received['target'] == resource['target'] and received['ino'] == resource['ino']
                self.events['resources'].append(received)
            finally:
                wire.close_fds(message['fds'])
                if received is not None:
                    received['closed'] = True
            healthy(source, 110)
            healthy(target, 111)
            connections = [client.receipt() for client in self.clients]
        finally:
            self.close()
        assert fd_inventory() == before, 'warmup actor descriptors not reclaimed'
        return self.result(usable_transfer=True, closed=True, warmup_connections=connections, actor_fd_growth=0)

    def command(self, row):
        op = row['op']
        if op == 'warmup':
            return self.warmup()
        if op == 'open':
            return self.open(row['case'])
        if op == 'exercise':
            return self.exercise()
        if op == 'close':
            return self.close()
        raise AssertionError('unknown operation: %s' % op)


def main():
    path, directory = sys.argv[1:]
    assert path == WORKLOAD['socket'], 'explicit private socket required'
    load_wire(directory)
    worker = Workload(path)
    print(json.dumps({'ok': True, 'result': worker.result()}), flush=True)
    try:
        for line in sys.stdin:
            try:
                response = {'ok': True, 'result': worker.command(json.loads(line))}
            except Exception as error:
                response = {'ok': False, 'result': worker.result(), 'error': repr(error)}
            print(json.dumps(response), flush=True)
    finally:
        worker.close()


if __name__ == '__main__':
    main()
