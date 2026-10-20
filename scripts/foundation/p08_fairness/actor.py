"""Independent framed actors; helpers are read-only from the frozen FD fixture."""
import json
import os
import select
import sys
import time

from transport import Client, call, frame, padding, read_string, string, u32

IFACE = 'org.foundation.Fairness'


def payload(sender, serial):
    return ('%s:%d:' % (sender, serial)).ljust(65536, 'x')


def pulse(sender, serial):
    return frame(4, serial, [(1, 'o', '/fairness'), (2, 's', IFACE),
                              (3, 's', 'FairPulse'), (8, 'g', 's')], string(payload(sender, serial)))


def request_name_body(name):
    body = string(name)
    return body + padding(len(body), 4) + u32(0)


class Worker:
    def __init__(self, path, role, index):
        self.client = Client(path)
        self.client.sock.settimeout(1 if role == 'healthy' else 5)
        self.role, self.index = role, index
        self.serial = 10
        self.pumping = False
        self.messages = {}
        self.calls = {}
        self.expected_senders = set()
        if role in ('healthy', 'victim'):
            name = 'org.foundation.Observer' if role == 'healthy' else 'org.foundation.Victim'
            result = self.rpc('RequestName', 'su', request_name_body(name))
            assert result['type'] == 2 and result['body'] == u32(1), result
            if role == 'victim':
                assert self.rpc('AddMatch', 's', string("type='signal',member='NeverVictim'"))['type'] == 2
        if role == 'receiver':
            for n in range(32):
                member = 'FairPulse' if n == 0 else 'Never%d' % n
                rule = "type='signal',interface='%s',member='%s'" % (IFACE, member)
                assert self.rpc('AddMatch', 's', string(rule))['type'] == 2

    def rpc(self, member, signature='', body=b''):
        self.serial += 1
        self.client.sock.sendall(call(member, self.serial, signature, body))
        return self.client.reply(self.serial)

    def ingest(self):
        msg = self.client.receive()
        assert not msg['fds'], 'rights0 workload unexpectedly received descriptors'
        sender = msg['fields'].get(7)
        if msg['type'] == 4 and msg['fields'].get(3) == 'FairPulse':
            assert sender in self.expected_senders, ('wrong broadcast sender', sender)
            assert msg['body'] == string(payload(sender, msg['serial'])), 'broadcast bytes/serial mismatch'
            key = sender + ':' + str(msg['serial'])
            assert key not in self.messages, ('duplicate broadcast delivery', key)
            self.messages[key] = {'sender': sender, 'serial': msg['serial'], 'bytes': 65536}
        elif msg['type'] == 1 and msg['fields'].get(3) == 'Hold':
            assert sender in self.expected_senders and msg['body'] == b'', msg
            key = sender + ':' + str(msg['serial'])
            assert key not in self.calls, key
            self.calls[key] = {'sender': sender, 'serial': msg['serial']}
        else:
            raise AssertionError(('unexpected receiver frame', msg))

    def command(self, request):
        operation = request['op']
        if operation == 'configure':
            self.expected_senders = set(request['senders'])
            return {'configured': True}
        if operation == 'start':
            self.pumping = True
            return {'pumping': True}
        if operation == 'load':
            messages = [pulse(self.client.name, 100000 + self.index * 1000 + n) for n in range(64)]
            call_serials = [200000 + self.index * 1000 + n for n in range(8)]
            messages += [frame(1, serial, [(1, 'o', '/fairness'), (2, 's', IFACE),
                         (3, 's', 'Hold'), (6, 's', request['callee']), (8, 'g', '')]) for serial in call_serials]
            self.client.sock.sendall(b''.join(messages))
            return {'attempted': 64, 'calls': call_serials, 'sender': self.client.name}
        if operation == 'barrier':
            self.client.barrier(900000 + self.index)
            return {'barrier': True}
        if operation == 'health':
            started = time.monotonic()
            result = self.rpc('GetNameOwner', 's', string('org.foundation.Observer'))
            assert result['type'] == 2 and result['body'] == string(self.client.name), result
            return {'latency_ms': (time.monotonic() - started) * 1000, 'name': self.client.name}
        if operation == 'finish':
            expected = set(request['expected'])
            deadline = time.monotonic() + 3
            while set(self.messages) != expected or len(self.calls) != request.get('calls', 0):
                assert time.monotonic() < deadline, ('receiver completion deadline', len(self.messages), len(expected), len(self.calls))
                self.ingest()
            self.pumping = True
            return {'delivered': list(self.messages.values()), 'calls': list(self.calls.values())}
        if operation == 'release':
            for n, data in enumerate(self.calls.values()):
                self.client.sock.sendall(frame(2, 300000 + n,
                    [(5, 'u', data['serial']), (6, 's', data['sender']), (8, 'g', 'u')], u32(data['serial'])))
            return {'released': len(self.calls)}
        if operation == 'collect':
            replies = []
            for serial in request['serials']:
                result = self.client.reply(serial)
                assert result['type'] == 2 and result['fields'][7] == request['callee'], result
                assert result['body'] == u32(serial) and not result['fds'], result
                replies.append(serial)
            return {'replies': replies}
        if operation == 'closed':
            while self.client.sock.recv(65536):
                pass
            return {'closed': True}
        raise AssertionError(request)


def main():
    assert os.path.exists('/etc/osbus-security-guest')
    path, role, index = sys.argv[1:]
    assert path.startswith('/run/osbus-fairness/') and '/..' not in path
    worker = Worker(path, role, int(index))
    print(json.dumps({'ok': True, 'result': {'pid': os.getpid(), 'uid': os.getuid(), 'name': worker.client.name, 'role': role}}), flush=True)
    try:
        while True:
            readers = [sys.stdin]
            if worker.pumping:
                readers.append(worker.client.sock)
            ready, _, _ = select.select(readers, [], [], 60)
            assert ready, 'actor command deadline'
            if worker.client.sock in ready:
                worker.ingest()
            if sys.stdin in ready:
                line = sys.stdin.readline()
                if not line:
                    break
                try:
                    result = worker.command(json.loads(line))
                    print(json.dumps({'ok': True, 'result': result}), flush=True)
                except Exception as error:
                    print(json.dumps({'ok': False, 'error': repr(error)}), flush=True)
    finally:
        worker.client.close()


if __name__ == '__main__':
    main()
