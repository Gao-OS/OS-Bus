"""Finite independent policy actor for explicitly addressed disposable guest buses."""
import array
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import sys
import time

from transport import Client, call, close_fds, frame, padding, string, u32

ALLOWED = 'org.foundation.Allowed'
DENIED = 'org.foundation.ReceiveDenied'
OBSERVER = 'org.foundation.Observer'
PROTECTED = 'org.foundation.Service.Protected'


def packet(kind, serial, destination, interface=None, reply_serial=None):
    assert type(serial) is int and serial > 0
    assert isinstance(destination, str) and re.fullmatch(r':[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+', destination)
    assert kind in (1, 2, 3, 4) and interface in (None, ALLOWED, DENIED)
    fields = [(6, 's', destination), (8, 'g', '')]
    if kind in (1, 4):
        assert kind != 4 or interface is not None, 'signal requires interface'
        fields += [(1, 'o', '/foundation'), (3, 's', 'Probe')]
        if interface is not None:
            fields += [(2, 's', interface)]
    else:
        assert type(reply_serial) is int and reply_serial > 0
        fields += [(5, 'u', reply_serial)]
        if kind == 3:
            fields += [(4, 's', 'org.foundation.Expected')]
    return frame(kind, serial, fields)


class PolicyClient(Client):
    """Retain independent transport decoding with one absolute command budget."""
    def __init__(self, path):
        self.deadline = time.monotonic() + 3
        super().__init__(path, negotiate=False)
        self.serial = 100
        self.reply_kind = None
        self.responses = []
        self.queued_messages = []

    def budget(self):
        remaining = self.deadline - time.monotonic()
        assert remaining > 0, 'policy actor deadline'
        self.sock.settimeout(remaining)

    def line(self):
        result = b''
        while not result.endswith(b'\r\n'):
            self.budget()
            byte = self.sock.recv(1)
            assert byte and len(result) < 4096, 'invalid auth response'
            result += byte
        return result

    def read(self, length, fds):
        result = bytearray()
        while len(result) < length:
            self.budget()
            data, controls, flags, _ = self.sock.recvmsg(length-len(result), socket.CMSG_SPACE(253*4))
            assert data and not flags & socket.MSG_CTRUNC, 'closed/truncated policy transport'
            result.extend(data)
            for level, kind, rights in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                received = array.array('i')
                received.frombytes(rights)
                fds.extend(received)
        return bytes(result)

    def next_serial(self):
        self.serial += 1
        return self.serial

    def send(self, data):
        self.budget()
        self.sock.sendall(data)

    def summary(self, message):
        try:
            assert not message['fds'], 'unexpected policy descriptors'
            return dict(type=message['type'], serial=message['serial'],
                        fields={str(key): value for key, value in message['fields'].items()},
                        body_hex=message['body'].hex())
        finally:
            close_fds(message['fds'])

    def rpc(self, member, signature='', body=b''):
        serial = self.next_serial()
        self.send(call(member, serial, signature, body))
        reply = self.reply(serial)
        assert not reply['fds'] and reply['type'] == 2, self.summary(reply)
        return reply['body']

    def collected_barrier(self):
        serial = self.next_serial()
        self.send(call('ListNames', serial))
        messages = []
        while True:
            self.budget()
            message = self.receive()
            if message['fields'].get(5) == serial:
                assert message['type'] == 2 and not message['fds'], self.summary(message)
                return messages
            messages.append(self.summary(message))
            self.answer(message)
            assert len(messages) <= 128, 'policy observation overflow'

    def answer(self, message):
        if self.reply_kind is None or message['type'] != 1:
            return
        assert message['fields'].get(1) == '/foundation' and message['fields'].get(3) == 'Probe'
        assert message['fields'].get(2) == ALLOWED
        serial, kind = self.next_serial(), self.reply_kind
        self.reply_kind = None
        sent_at = time.monotonic()
        self.send(packet(kind, serial, message['fields'][7], reply_serial=message['serial']))
        self.responses.append(dict(serial=serial, kind=kind, reply_serial=message['serial'],
                                   destination=message['fields'][7], sent_at=sent_at))

    def wait_armed(self):
        # After the arm acknowledgement, read the socket rather than waiting
        # for another parent command. This removes parent IPC from reply time.
        while self.reply_kind is not None:
            self.budget()
            message = self.receive()
            self.queued_messages.append(self.summary(message))
            self.answer(message)
            assert len(self.queued_messages) <= 128, 'policy observation overflow'

    def identity(self):
        uid = self.rpc('GetConnectionUnixUser', 's', string(self.name))
        pid = self.rpc('GetConnectionUnixProcessID', 's', string(self.name))
        assert len(uid) == len(pid) == 4
        return dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid(), groups=sorted(os.getgroups()),
                    name=self.name, broker_uid=struct.unpack('<I', uid)[0], broker_pid=struct.unpack('<I', pid)[0])

    def command(self, command):
        self.deadline = time.monotonic() + 3
        operation = command['op']
        if operation != 'observe':
            self.responses = []
        if operation == 'arm_reply':
            assert self.reply_kind is None and command['kind'] in (2, 3)
            self.reply_kind = command['kind']
            return {'armed': self.reply_kind}
        if operation == 'identity':
            return self.identity()
        if operation == 'own':
            name = command['name']
            assert name in (OBSERVER, PROTECTED)
            encoded = string(name)
            assert self.rpc('RequestName', 'su', encoded + padding(len(encoded), 4) + u32(0)) == u32(1)
            return {'owned': name, 'messages': self.collected_barrier()}
        if operation == 'send':
            serial = self.next_serial()
            sent_at = time.monotonic()
            self.send(packet(command['kind'], serial, command['destination'],
                             command.get('interface'), command.get('reply_serial')))
            return {'serial': serial, 'sent_at': sent_at, 'messages': self.collected_barrier()}
        if operation == 'observe':
            prior_serial = command.get('prior_serial')
            if prior_serial is not None:
                assert type(prior_serial) is int and prior_serial == command.get('expect_serial'), 'unbound prior observation'
            messages = self.queued_messages + self.collected_barrier()
            self.queued_messages = []
            if 'expect_serial' in command:
                # Independent Peer scheduling can deliver after the first
                # target barrier. Wait for the bound frame, then fence again.
                while prior_serial is None and not any(item['serial'] == command['expect_serial'] and
                              item['fields'].get('7') != 'org.freedesktop.DBus' for item in messages):
                    self.budget()
                    message = self.receive()
                    messages.append(self.summary(message))
                    self.answer(message)
                    assert len(messages) <= 128, 'policy observation overflow'
                messages += self.collected_barrier()
            # Source barrier precedes this target barrier. Negative rows also
            # observe readiness for 150ms then complete another ordered barrier.
            if command.get('negative', False):
                until = time.monotonic() + .15
                while time.monotonic() < until:
                    remaining = min(until, self.deadline) - time.monotonic()
                    assert remaining > 0, 'policy negative deadline'
                    if not select.select([self.sock], [], [], remaining)[0]:
                        break
                    messages.append(self.summary(self.receive()))
                    assert len(messages) <= 128, 'policy observation overflow'
                messages += self.collected_barrier()
            return {'messages': messages, 'responses': self.responses,
                    'barriers': 2 if command.get('negative', False) or 'expect_serial' in command else 1}
        raise AssertionError(('unsupported policy actor operation', operation))


def main():
    assert Path('/etc/osbus-security-guest').is_file(), 'disposable VM required'
    assert os.getuid() in (1100, 1101), 'named policy actor UID required'
    assert len(sys.argv) == 2
    path = Path(sys.argv[1])
    assert path.is_absolute() and '..' not in path.parts
    assert path.resolve().is_relative_to('/run/osbus-p08/'), 'explicit private socket required'
    client = None
    try:
        client = PolicyClient(str(path))
        print(json.dumps({'ok': True, 'result': client.identity()}), flush=True)
        for line in sys.stdin:
            assert len(line) < 4096, 'policy command too large'
            try:
                result = client.command(json.loads(line))
                print(json.dumps({'ok': True, 'result': result}), flush=True)
                if client.reply_kind is not None:
                    client.wait_armed()
            except Exception as error:
                print(json.dumps({'ok': False, 'error': repr(error)}), flush=True)
    except Exception as error:
        print(json.dumps({'ok': False, 'error': repr(error)}), flush=True)
        raise
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    main()
