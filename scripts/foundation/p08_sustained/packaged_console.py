"""Bounded local IEx transport for the disposable packaged-resource fixture."""
import base64
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time

from channel import Channel


def validate_request(request):
    assert isinstance(request, dict), 'request must be an object'
    operation = request.get('operation')
    expected = {'schema', 'nonce', 'request_id', 'operation'}
    if operation == 'kill':
        expected.add('name')
        name = request.get('name')
        assert isinstance(name, str) and len(name) <= 255 and re.fullmatch(
            r':[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+', name), 'invalid victim unique name'
    assert set(request) == expected, 'unexpected request fields'
    assert operation in ('snapshot', 'quiescent', 'metrics', 'kill'), 'unsupported operation'
    assert type(request['schema']) is int and request['schema'] == 1, 'request schema'
    assert isinstance(request['nonce'], str) and re.fullmatch(r'[0-9a-f]{32}', request['nonce']), 'run nonce'
    assert type(request['request_id']) is int and request['request_id'] > 0, 'request ID'


def expression(request):
    validate_request(request)
    encoded = base64.b64encode(json.dumps(request, separators=(',', ':')).encode()).decode()
    return 'OSBusFoundationPackagedInspector.reply("' + encoded + '")'


def validate_response(response, request, pid):
    validate_request(request)
    assert isinstance(response, dict), 'response must be an object'
    assert type(response.get('ok')) is bool, 'response status'
    expected = {'schema', 'nonce', 'request_id', 'pid', 'ok',
                'result' if response['ok'] else 'error'}
    assert set(response) == expected, 'unexpected response fields'
    for field in ('schema', 'request_id'):
        assert type(response[field]) is int and response[field] == request[field], ('response binding', field)
    assert response['nonce'] == request['nonce'], 'response run binding'
    assert type(response['pid']) is int and response['pid'] == pid, 'response daemon PID'
    if not response['ok']:
        assert isinstance(response['error'], str), 'inspector error must be text'
        raise AssertionError(response['error'])
    assert isinstance(response['result'], dict), 'response result must be an object'
    event = 'killed' if request['operation'] == 'kill' else 'snapshot'
    assert response['result'].get('event') == event, 'response operation binding'
    return response


class Console(Channel):
    def __init__(self, command, log, nonce):
        assert re.fullmatch(r'[0-9a-f]{32}', nonce), 'invalid run nonce'
        super().__init__(command, log, 'FIXTURE ')
        self.nonce, self.request_id, self.daemon_pid = nonce, 0, None
        self.stopped = None
        os.set_blocking(self.process.stdin.fileno(), False)

    def send_line(self, line, deadline):
        remaining = memoryview((line + '\n').encode())
        while remaining:
            timeout = deadline - time.monotonic()
            assert timeout > 0 and select.select([], [self.process.stdin], [], timeout)[1], 'console write deadline'
            try:
                written = os.write(self.process.stdin.fileno(), remaining)
            except BlockingIOError:
                continue
            assert written > 0, 'console input closed'
            remaining = remaining[written:]

    def receive_bytes(self, deadline):
        timeout = deadline - time.monotonic()
        assert timeout > 0 and select.select([self.process.stdout], [], [], timeout)[0], 'console read deadline'
        piece = os.read(self.process.stdout.fileno(), 65536)
        assert piece, ('console EOF: process exited', self.process.poll())
        with self.log.open('ab') as output:
            output.write(piece)
        self.buffer += piece
        assert len(self.buffer) <= 4_194_304, 'fixture output line too large'

    def reject_extra_records(self, deadline):
        # Drain immediately available output; a later stale reply is rejected by
        # the next request binding or by final shutdown inspection.
        while True:
            assert time.monotonic() < deadline, 'console drain deadline'
            if not select.select([self.process.stdout], [], [], 0)[0]:
                break
            assert time.monotonic() < deadline, 'console drain deadline'
            piece = os.read(self.process.stdout.fileno(), 65536)
            if not piece:
                break
            with self.log.open('ab') as output:
                output.write(piece)
            self.buffer += piece
            assert len(self.buffer) <= 4_194_304, 'fixture output line too large'
        assert not any(line.startswith(b'FIXTURE ') for line in self.buffer.split(b'\n')), 'duplicate/unconsumed console reply'

    def read_reply(self, deadline):
        def unique_keys(pairs):
            result = {}
            for key, value in pairs:
                assert key not in result, ('duplicate JSON key', key)
                result[key] = value
            return result

        while True:
            assert time.monotonic() < deadline, 'console read deadline'
            while b'\n' not in self.buffer:
                self.receive_bytes(deadline)
            raw, self.buffer = self.buffer.split(b'\n', 1)
            if raw.startswith(b'FIXTURE '):
                response = json.loads(raw[len(b'FIXTURE '):], object_pairs_hook=unique_keys)
                self.reject_extra_records(deadline)
                return response

    def bind_pid(self, pid):
        assert self.daemon_pid is None and type(pid) is int and pid > 0, 'daemon PID binding'
        self.daemon_pid = pid

    def request(self, operation, name=None, bootstrap=None):
        assert self.daemon_pid is not None, 'bind actual manager MainPID before inspection'
        self.request_id += 1
        request = dict(schema=1, nonce=self.nonce, request_id=self.request_id, operation=operation)
        if name is not None:
            request['name'] = name
        code = expression(request)
        if bootstrap is not None:
            path, digest = bootstrap
            assert Path(path).is_absolute() and '..' not in Path(path).parts, 'inspector path'
            assert re.fullmatch(r'[0-9a-f]{64}', digest), 'inspector hash'
            encoded = base64.b64encode(str(path).encode()).decode()
            file = 'Base.decode64!("' + encoded + '")'
            code = ('true = Base.encode16(:crypto.hash(:sha256, File.read!(' + file +
                    ')), case: :lower) == "' + digest + '"; Code.compile_file(' + file + '); ' + code)
        deadline = time.monotonic() + 10
        self.reject_extra_records(deadline)
        self.send_line(code, deadline)
        response = self.read_reply(deadline)
        return validate_response(response, request, self.daemon_pid)['result']

    def stop(self, grace=5):
        if self.stopped is not None:
            return self.stopped
        # One I/O budget covers the request, wrapper exit and stdout tail. The
        # service has a separate cgroup: the controller must contain it after
        # this bounded return, including when that service keeps stdout open.
        deadline = time.monotonic() + grace
        requested = self.process.poll() is None
        result = dict(command=self.command, pid=self.process.pid, method='eof',
                      shutdown_request='System.stop(0)' if requested else 'already exited',
                      tail_eof=False, tail_bytes=0,
                      emergency_reap_budget_seconds=1,
                      service_cgroup_cleanup_required=True)
        # Inspect already logged bytes without rereading or duplicating the log.
        prefix = b''
        def inspect(piece):
            nonlocal prefix
            fragments = piece.split(b'\n')
            for index, fragment in enumerate(fragments):
                if index:
                    prefix = b''
                prefix = (prefix + fragment[:8])[:8]
                if prefix == b'FIXTURE ':
                    result['protocol_error'] = 'unconsumed console reply'

        inspect(self.buffer)
        self.buffer = b''
        try:
            if requested:
                try:
                    self.send_line('System.stop(0)', deadline)
                except (OSError, AssertionError) as error:
                    result['shutdown_error'] = repr(error)
            # Pinned IEx treats input EOF as System.halt(0). Keep input open
            # until orderly application shutdown finishes; close it in finally.
            os.set_blocking(self.process.stdout.fileno(), False)
            while not result['tail_eof']:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result['tail_error'] = 'stdout drain deadline'
                    break
                if not select.select([self.process.stdout], [], [], min(remaining, .05))[0]:
                    continue
                if time.monotonic() >= deadline:
                    result['tail_error'] = 'stdout drain deadline'
                    break
                try:
                    piece = os.read(self.process.stdout.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not piece:
                    result['tail_eof'] = True
                    break
                with self.log.open('ab') as output:
                    output.write(piece)
                result['tail_bytes'] += len(piece)
                inspect(piece)
            if self.process.poll() is None:
                try:
                    self.process.wait(timeout=max(deadline - time.monotonic(), 0))
                except subprocess.TimeoutExpired:
                    result['method'] = 'kill'
            if 'tail_error' in result and result['method'] == 'eof':
                result['method'] = 'incomplete-tail'
        except (OSError, AssertionError, ValueError) as error:
            result['tail_error'] = repr(error)
            result['method'] = 'shutdown-error'
        finally:
            # Reap only our wrapper group. This fixed emergency reap budget is
            # separate from I/O and can never count as graceful service shutdown.
            if self.process.poll() is None:
                result['method'] = 'kill'
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=1)
            self.process.stdin.close()
            self.process.stdout.close()
        result['returncode'] = self.process.returncode
        if requested and result['method'] == 'eof':
            result['method'] = 'shutdown-error' if 'shutdown_error' in result else 'console-System.stop'
        self.stopped = result
        return self.stopped
