"""Independent real-rights worker using the existing native transport actor."""
import json
import os
from pathlib import Path
import random
import stat
import socket
import struct
import sys
import tempfile
import time

from transport import Client, call, close_fds, frame, padding, pipe_payload, signal, string, u32

BUS = 'org.freedesktop.DBus'


def request_name_body(name, flags):
    encoded = string(name)
    return encoded + padding(len(encoded), 4) + u32(flags)


class Workload:
    def __init__(self, path, healthy=False):
        self.path = path
        self.source = Client(path)
        self.target = None if healthy else Client(path)
        self.serial = 10
        self.index = 0
        self.order = list(range(7))
        workload = json.loads(Path(__file__).with_name('workload.json').read_text())
        random.Random(workload['seed']).shuffle(self.order)
        if healthy:
            result = self.rpc(self.source, 'RequestName', 'su', request_name_body('org.foundation.Observer', 0))
            assert result['type'] == 2 and result['body'] == u32(1), result

    def rpc(self, client, member, signature='', body=b''):
        self.serial += 1
        client.sock.sendall(call(member, self.serial, signature, body))
        return client.reply(self.serial)

    def health(self):
        started = time.monotonic()
        result = self.rpc(self.source, 'GetNameOwner', 's', string('org.foundation.Observer'))
        assert result['type'] == 2 and result['body'] == string(self.source.name), result
        return {'latency_ms': (time.monotonic() - started) * 1000, 'name': self.source.name}

    def operation(self):
        kind = self.order[self.index % 7]
        self.index += 1
        payload = ('p08-%012d' % self.index).encode().ljust(64, b'.')
        self.serial += 1
        serial = self.serial
        if kind == 0:
            descriptor = pipe_payload(payload)
            with tempfile.TemporaryFile() as file:
                file.write(payload)
                file.seek(0)
                first, second = socket.socketpair()
                try:
                    second.sendall(payload)
                    self.source.send_fds(signal(serial, self.target.name, 3, u32(0) + u32(1) + u32(2), 'hhh'),
                                         [descriptor, file.fileno(), first.fileno()])
                    result = self.target.receive()
                    try:
                        assert result['serial'] == serial and result['body'] == u32(0) + u32(1) + u32(2), result
                        assert result['fields'][7] == self.source.name and len(result['fds']) == 3, result
                        modes = [os.fstat(fd).st_mode for fd in result['fds']]
                        assert stat.S_ISFIFO(modes[0]) and stat.S_ISREG(modes[1]) and stat.S_ISSOCK(modes[2])
                        assert [os.read(fd, 128) for fd in result['fds']] == [payload] * 3
                    finally:
                        close_fds(result['fds'])
                finally:
                    os.close(descriptor)
                    first.close()
                    second.close()
        elif kind in (1, 6):
            victim = Client(self.path)
            name = 'org.foundation.Service.Churn'
            result = self.rpc(victim, 'RequestName', 'su', request_name_body(name, 0))
            assert result['type'] == 2 and result['body'] == u32(1), result
            rule = "type='signal',interface='org.foundation.Churn'"
            assert self.rpc(victim, 'AddMatch', 's', string(rule))['type'] == 2
            if kind == 6:
                # Root controller kills this actual Peer under a process monitor.
                return {'kind': 'abrupt_kill', 'victim': victim.name, 'retained': victim}
            victim.close()
        elif kind == 2:
            victim = Client(self.path)
            descriptor = pipe_payload(payload)
            try:
                victim.send_fds(signal(serial, self.target.name, 1, u32(1)), [descriptor])
                assert victim.sock.recv(1) == b'', 'invalid FD index accepted'
            finally:
                os.close(descriptor)
                victim.close()
        elif kind == 3:
            result = self.rpc(self.source, 'RequestName', 'su', request_name_body('org.foundation.Forbidden', 0))
            assert result['type'] == 3 and result['fields'][4] == BUS + '.Error.AccessDenied', result
        else:
            caller = self.source if kind == 4 else Client(self.path)
            fields = [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
                      (3, 's', 'NeverReply'), (6, 's', self.target.name), (8, 'g', '')]
            caller.sock.sendall(frame(1, serial, fields))
            received = self.target.receive()
            assert received['serial'] == serial and received['fields'][7] == caller.name
            assert not received['fds'] and received['body'] == b''
            if kind == 4:
                result = caller.reply(serial)
                assert result['type'] == 3 and result['fields'][4] == BUS + '.Error.NoReply', result
            else:
                caller.close()
        return {'kind': ['transfer', 'churn', 'invalid_fd', 'denied_ownership', 'pending_timeout', 'pending_cancel'][kind]}

    def close(self):
        self.source.close()
        if self.target:
            self.target.close()


def main():
    assert os.path.exists('/etc/osbus-security-guest'), 'disposable VM required'
    path, mode = sys.argv[1:]
    assert path.startswith('/run/osbus-p08/') and '/..' not in path
    worker = Workload(path, healthy=mode == 'healthy')
    retained = None
    print(json.dumps({'ok': True, 'result': {'pid': os.getpid(), 'uid': os.getuid(), 'name': worker.source.name}}), flush=True)
    try:
        for line in sys.stdin:
            try:
                command = json.loads(line)
                if command['op'] == 'health':
                    result = worker.health()
                elif command['op'] == 'operation':
                    result = worker.operation()
                    retained = result.pop('retained', None)
                elif command['op'] == 'killed':
                    assert retained.sock.recv(1) == b''
                    retained.close()
                    retained = None
                    result = {'closed': True}
                elif command['op'] == 'barrier':
                    worker.source.barrier(1000000 + worker.index)
                    worker.target.barrier(1000000 + worker.index)
                    result = {'completed': worker.index}
                else:
                    raise AssertionError(command)
                print(json.dumps({'ok': True, 'result': result}), flush=True)
            except Exception as error:
                print(json.dumps({'ok': False, 'error': repr(error)}), flush=True)
    finally:
        if retained:
            retained.close()
        worker.close()


if __name__ == '__main__':
    main()
