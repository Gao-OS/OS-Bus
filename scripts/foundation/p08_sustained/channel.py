"""Process channels reused verbatim from the VM security backend fixture."""
import json
import os
import select
import signal
import subprocess
import time

class Channel:
    def __init__(self, command, log, prefix=''):
        self.command = command
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
        self.log, self.prefix = log, prefix
        self.buffer = b''

    def read(self, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            assert time.monotonic() < deadline, ('channel deadline', self.command)
            while b'\n' not in self.buffer:
                assert time.monotonic() < deadline, ('channel deadline', self.command)
                assert select.select([self.process.stdout], [], [], max(deadline - time.monotonic(), 0))[0], ('channel deadline', self.command)
                piece = os.read(self.process.stdout.fileno(), 65536)
                assert piece, ('process exited', self.command, self.process.poll())
                self.buffer += piece
                assert len(self.buffer) <= 4_194_304, 'fixture output line too large'
            raw, self.buffer = self.buffer.split(b'\n', 1)
            line = raw.decode() + '\n'
            with self.log.open('a') as output:
                output.write(line)
            if line.startswith(self.prefix):
                return json.loads(line[len(self.prefix):])

    def write(self, line):
        self.process.stdin.write((line + '\n').encode())
        self.process.stdin.flush()
        return self.read()

    def stop(self, grace=5):
        method = 'eof'
        self.process.stdin.close()
        try:
            self.process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            method = 'terminate'
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                method = 'kill'
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        # A runner may exit before descendants; contain only our new process group.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.set_blocking(self.process.stdout.fileno(), False)
        tail = self.buffer
        while True:
            try:
                piece = os.read(self.process.stdout.fileno(), 65536)
            except BlockingIOError:
                break
            if not piece:
                break
            tail += piece
        if tail:
            with self.log.open('ab') as output:
                output.write(tail)
        self.process.stdout.close()
        return dict(command=self.command, pid=self.process.pid,
                    returncode=self.process.returncode, method=method)

class Actor(Channel):
    def begin(self, **command):
        self.process.stdin.write((json.dumps(command) + '\n').encode())
        self.process.stdin.flush()

    def finish(self):
        response = self.read()
        assert response['ok'], response
        return response['result']

    def call(self, member, signature='', body=(), **options):
        return self.request(op='call', member=member, signature=signature, body=body, **options)

    def request(self, **command):
        response = self.write(json.dumps(command))
        assert response['ok'], response
        return response['result']
