"""One normal negotiated client; the selected frame's final byte is never sent."""
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

from transport import Client, call, close_fds, signal, string, u32

WORKLOAD = json.loads(Path(__file__).with_name('workload.json').read_text())
BUS = 'org.freedesktop.DBus'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def resource(serial):
    return ('sec17-frame-resource-%d' % serial).encode()


def packet(serial, target):
    return signal(serial, target, 1, u32(0), 'h')


def fd_state():
    targets = []
    for entry in Path('/proc/self/fd').iterdir():
        try:
            targets.append(os.readlink(entry))
        except FileNotFoundError:
            pass
    return {'fds': len(targets), 'memfds': sorted(x for x in targets if '/memfd:' in x)}


def fd_record(fd, serial):
    info = os.fstat(fd)
    expected = resource(serial)
    assert stat.S_ISREG(info.st_mode) and info.st_size == len(expected)
    assert os.pread(fd, len(expected) + 1, 0) == expected
    return dict(dev=info.st_dev, ino=info.st_ino, mode=info.st_mode, size=info.st_size,
                target=os.readlink('/proc/self/fd/%d' % fd), sha256=digest(expected))


class Workload:
    def __init__(self, path, role):
        self.path, self.role, self.client = path, role, None
        self.prefix_sent = False

    def send_resource(self, serial, target, partial):
        assert self.role == 'source' and not self.prefix_sent
        raw = packet(serial, target)
        sent = raw[:-1] if partial else raw
        fd = os.memfd_create('sec17-frame-%d' % serial, os.MFD_CLOEXEC)
        try:
            assert os.write(fd, resource(serial)) == len(resource(serial))
            identity = fd_record(fd, serial)
            self.client.send_fds(sent, [fd])
        finally:
            os.close(fd)
        self.prefix_sent = partial
        return dict(serial=serial, target=target, packet_hex=raw.hex(), packet_sha256=digest(raw),
                    sent_hex=sent.hex(), sent_sha256=digest(sent), sent_bytes=len(sent), rights=1,
                    suffix_bytes=len(raw) - len(sent), suffix_sent=False, source_closed=True,
                    resource=identity, fd_state=fd_state())

    def read_deadline(self, length, fds, deadline):
        result = b''
        while len(result) < length:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'absolute health deadline'
            self.client.sock.settimeout(remaining)
            data, controls, flags, _ = self.client.sock.recvmsg(length - len(result), socket.CMSG_SPACE(253 * 4))
            for level, kind, rights in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                incoming = array.array('i')
                incoming.frombytes(rights)
                fds.extend(incoming)
            assert data and not flags & socket.MSG_CTRUNC
            assert time.monotonic() <= deadline
            result += data
        return result

    def health(self):
        assert self.role == 'observer'
        serial = WORKLOAD['health_serial']
        sent = call('GetNameOwner', serial, 's', string(self.client.name))
        started = time.monotonic()
        deadline = started + WORKLOAD['healthy_ms'] / 1000
        previous_read, previous_timeout = self.client.read, self.client.sock.gettimeout()
        reply = None
        try:
            self.client.sock.settimeout(max(deadline - time.monotonic(), .001))
            self.client.sock.sendall(sent)
            self.client.read = lambda length, fds: self.read_deadline(length, fds, deadline)
            reply = self.client.receive()
            assert reply['type'] == 2 and reply['fields'].get(5) == serial
            assert reply['fields'].get(7) == BUS and not reply['fds']
            assert reply['body'] == string(self.client.name)
            elapsed = (time.monotonic() - started) * 1000
            assert elapsed <= WORKLOAD['healthy_ms']
            return dict(name=self.client.name, owner=self.client.name, serial=serial,
                        latency_ms=elapsed, sent_hex=sent.hex(), reply_type=reply['type'],
                        fields={str(k): v for k, v in reply['fields'].items()},
                        body_hex=reply['body'].hex(), rights=len(reply['fds']))
        finally:
            if reply is not None:
                close_fds(reply['fds'])
            self.client.read = previous_read
            self.client.sock.settimeout(previous_timeout)

    def command(self, row):
        op = row['op']
        if op == 'connect':
            assert self.client is None and not self.prefix_sent
            self.client = Client(self.path)
            return dict(name=self.client.name, negotiated=True, **fd_state())
        if op == 'close':
            self.client.close()
            self.client = None
            return fd_state()
        assert self.client is not None
        if op in ('warm_send', 'prefix'):
            serial = WORKLOAD['warmup_serial'] if op == 'warm_send' else WORKLOAD['serial']
            return self.send_resource(serial, row['target'], op == 'prefix')
        if op == 'warm_receive':
            assert self.role == 'observer'
            message = self.client.receive()
            try:
                assert message['type'] == 4 and message['serial'] == WORKLOAD['warmup_serial']
                assert len(message['fds']) == 1 and message['body'] == u32(0)
                receipt = dict(type=message['type'], serial=message['serial'],
                               fields={str(k): v for k, v in message['fields'].items()},
                               body_hex=message['body'].hex(), rights=len(message['fds']),
                               resource=fd_record(message['fds'][0], message['serial']))
            finally:
                close_fds(message['fds'])
            return dict(**receipt, fd_state=fd_state())
        if op == 'health':
            return self.health()
        if op == 'eof':
            assert self.role == 'source' and self.prefix_sent
            self.client.sock.settimeout(WORKLOAD['cleanup_ms'] / 1000)
            assert self.client.sock.recv(1) == b''
            return dict(eof=True, suffix_sent=False)
        raise AssertionError(row)


def main():
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    path, role = sys.argv[1:]
    assert path == WORKLOAD['socket'] and os.getuid() == WORKLOAD['roles'][role]
    worker = Workload(path, role)
    print(json.dumps(dict(ok=True, result=dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
                                              role=role, **fd_state()))), flush=True)
    try:
        for line in sys.stdin:
            try:
                response = dict(ok=True, result=worker.command(json.loads(line)))
            except Exception as error:
                response = dict(ok=False, error=repr(error))
            print(json.dumps(response), flush=True)
    finally:
        if worker.client is not None:
            worker.client.close()


if __name__ == '__main__':
    main()
