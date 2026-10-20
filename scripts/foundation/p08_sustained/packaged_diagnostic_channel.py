"""Original Actor exchange with additive buffered controller/actor phase binding."""
import json
import os
import select
import time

from channel import Actor


class DiagnosticActor(Actor):
    def __init__(self, command, log, diagnostics):
        super().__init__(command, log)
        self.diagnostics, self.request_id, self.active = diagnostics, 0, None
        self.emissions = set()

    def emission(self, row, expected):
        assert isinstance(row, dict) and row.get('schema') == 1, 'diagnostic emission schema'
        assert row.get('nonce') == self.diagnostics.nonce, 'diagnostic nonce'
        assert type(row.get('request_id')) is int and row['request_id'] == expected, 'diagnostic emission request ID'
        assert expected not in self.emissions, 'duplicate diagnostic emission'
        keys = ['response_encode_started_ns', 'response_encode_finished_ns', 'write_started_ns',
                'write_finished_ns', 'flush_started_ns', 'flush_finished_ns']
        values = [row.get(key) for key in keys]
        assert all(type(value) is int and value >= 0 for value in values), 'diagnostic emission clock'
        assert values == sorted(values), 'diagnostic emission order'
        self.emissions.add(expected)
        self.diagnostics.record(dict(owner='actor-emission', request_id=expected, emission=row))

    def read(self, timeout=10):
        if self.active is None:
            return super().read(timeout)
        phases = self.active['phases']
        phases['read_started_ns'] = time.monotonic_ns()
        deadline = time.monotonic() + timeout
        while True:
            assert time.monotonic() < deadline, ('channel deadline', self.command)
            while b'\n' not in self.buffer:
                assert time.monotonic() < deadline, ('channel deadline', self.command)
                waiting = dict(started_ns=time.monotonic_ns())
                ready = select.select([self.process.stdout], [], [], max(deadline-time.monotonic(), 0))[0]
                waiting['finished_ns'] = time.monotonic_ns()
                phases['selects'].append(waiting)
                assert ready, ('channel deadline', self.command)
                reading = dict(started_ns=time.monotonic_ns())
                piece = os.read(self.process.stdout.fileno(), 65536)
                reading.update(finished_ns=time.monotonic_ns(), bytes=len(piece))
                phases['reads'].append(reading)
                assert piece, ('process exited', self.command, self.process.poll())
                self.buffer += piece
                assert len(self.buffer) <= 4_194_304, 'fixture output line too large'
            raw, self.buffer = self.buffer.split(b'\n', 1)
            phases['line_available_ns'] = time.monotonic_ns()
            line = raw.decode() + '\n'
            phases['log_started_ns'] = time.monotonic_ns()
            with self.log.open('a') as output:
                output.write(line)
            phases['log_finished_ns'] = time.monotonic_ns()
            if line.startswith(self.prefix):
                phases['decode_started_ns'] = time.monotonic_ns()
                result = json.loads(line[len(self.prefix):])
                phases['decode_finished_ns'] = time.monotonic_ns()
                return result

    def request(self, **command):
        self.request_id += 1
        phases = dict(request_enter_ns=time.monotonic_ns(), selects=[], reads=[])
        row = dict(owner='controller', request_id=self.request_id, phases=phases)
        self.active = row
        try:
            row['command_json'] = json.dumps(command)
            phases['command_ready_ns'] = time.monotonic_ns()
            phases['write_started_ns'] = time.monotonic_ns()
            self.process.stdin.write((row['command_json'] + '\n').encode())
            phases['write_finished_ns'] = time.monotonic_ns()
            self.process.stdin.flush()
            phases['flush_finished_ns'] = time.monotonic_ns()
            response = self.read()
            diagnostic = response.get('diagnostic')
            row['actor'] = diagnostic
            assert isinstance(diagnostic, dict) and diagnostic.get('schema') == 1, 'diagnostic response schema'
            assert diagnostic.get('nonce') == self.diagnostics.nonce, 'diagnostic nonce'
            assert type(diagnostic.get('request_id')) is int and diagnostic['request_id'] == self.request_id, 'diagnostic request ID'
            assert diagnostic.get('command_json') == row['command_json'], 'diagnostic command binding'
            if self.request_id == 1:
                assert diagnostic.get('previous_emission') is None, 'unexpected previous emission'
            else:
                self.emission(diagnostic.get('previous_emission'), self.request_id-1)
            assert response['ok'], response
            return response['result']
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            phases['request_finished_ns'] = time.monotonic_ns()
            self.diagnostics.record(row)
            self.active = None

    def stop(self, grace=5):
        result = super().stop(grace)
        lines = self.log.read_text().splitlines()
        final = [json.loads(line) for line in lines if line.startswith('{"diagnostic_eof":')]
        assert len(final) == 1, 'missing/duplicate diagnostic EOF receipt'
        receipt = final[0]['diagnostic_eof']
        assert receipt.get('schema') == 1 and receipt.get('nonce') == self.diagnostics.nonce, 'diagnostic EOF nonce/schema'
        assert type(receipt.get('requests')) is int and receipt['requests'] == self.request_id, 'diagnostic EOF request count'
        if self.request_id:
            self.emission(receipt.get('emission'), self.request_id)
        else:
            assert receipt.get('emission') is None, 'unexpected diagnostic EOF emission'
        assert self.emissions == set(range(1, self.request_id+1)), 'unfinished diagnostic emission binding'
        self.diagnostics.record(dict(owner='actor-eof', requests=self.request_id, receipt=receipt))
        result['diagnostic_eof_bound'] = True
        return result
