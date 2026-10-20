"""Disposable-guest adapter; wire construction remains in the pinned actor."""
import json
import os
from pathlib import Path
import socket
import sys
import time

sys.path.insert(0, sys.argv[2] if __name__ == '__main__' else str(Path(__file__).parent.parent / 'vm_security'))
from actor import Client, packet


class HeldClient(Client):
    def command(self, request):
        operation = request['op']
        if operation == 'close':
            if self.socket is not None:
                self.socket.close()
                self.socket = None
            self.buffer, self.pending = b'', []
            return {'closed': True}
        if operation == 'hold':
            assert self.socket is None, 'existing socket must retire first'
            started = time.monotonic()
            deadline = request['deadline']
            assert started < deadline and deadline - started <= 0.4
            self.socket = socket.socket(socket.AF_UNIX)
            self.socket.settimeout(max(deadline - time.monotonic(), 0.001))
            wire = b'\0AUTH EXTERNAL ' + str(os.getuid()).encode().hex().encode() + b'\r\n'
            try:
                self.socket.connect(self.path)
                self.socket.sendall(wire)
                response = self.line()
            except (ConnectionResetError, BrokenPipeError) as error:
                response = self.buffer
                result = dict(admitted=False, closed=True, reset=type(error).__name__)
            except AssertionError as error:
                assert str(error) == 'authentication closed', error
                response = self.buffer
                result = dict(admitted=False, closed=True, reset=None)
            else:
                assert response.startswith(b'OK '), response
                result = dict(admitted=True, closed=False, reset=None)
            result.update(response_hex=response.hex(), sent_hex=wire.hex(),
                          started=started, finished=time.monotonic(), begin_sent=False)
            assert result['finished'] < deadline, 'held authentication phase deadline'
            if not result['admitted']:
                assert b'OK ' not in response, result
                self.command({'op': 'close'})
            return result
        if operation == 'complete':
            assert self.socket is not None
            self.socket.settimeout(max(request['deadline'] - time.monotonic(), 0.001))
            self.serial = 1
            self.socket.sendall(b'BEGIN\r\n' + packet(1, 'Hello'))
            # Client.reply owns the unchanged parser; the runner also bounds the read.
            result = self.reply(1)
            assert result['type'] == 2 and result['reply_serial'] == 1
            assert len(result['body']) == 1 and result['body'][0].startswith(':')
            assert time.monotonic() < request['deadline'], 'held completion deadline'
            return dict(reply=result, request_serial=1, begin_sent=True)
        result = super().command(request)
        if operation == 'call':
            return dict(reply=result, request_serial=self.serial)
        return result


if __name__ == '__main__':
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    client = HeldClient(sys.argv[1])
    print(json.dumps(dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid())), flush=True)
    try:
        for line in sys.stdin:
            try:
                result = client.command(json.loads(line))
                print(json.dumps(dict(ok=True, result=result)), flush=True)
            except Exception as error:
                print(json.dumps(dict(ok=False, error=repr(error))), flush=True)
    finally:
        client.command({'op': 'close'})
