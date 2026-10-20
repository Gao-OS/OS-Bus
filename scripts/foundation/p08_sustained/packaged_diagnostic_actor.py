"""Healthy-only telemetry wrapper around the original Workload.health protocol."""
import json
import os
import re
import sys
import time

from actor import Workload


def serve(workload, nonce, source, output):
    assert re.fullmatch('[0-9a-f]{32}', nonce), 'diagnostic nonce'
    request_id, previous = 0, None
    for line in source:
        request_id += 1
        phases = dict(received_ns=time.monotonic_ns())
        diagnostic = dict(schema=1, nonce=nonce, request_id=request_id,
                          command_json=line.rstrip('\n'), phases=phases, previous_emission=previous)
        try:
            command = json.loads(line)
            phases['decoded_ns'] = time.monotonic_ns()
            assert command == {'op': 'health'}, 'healthy diagnostic command'
            phases['rpc_started_ns'] = time.monotonic_ns()
            result = workload.health()
            phases['rpc_finished_ns'] = time.monotonic_ns()
            response = dict(ok=True, result=result, diagnostic=diagnostic)
        except Exception as error:
            response = dict(ok=False, error=repr(error), diagnostic=diagnostic)
        # Encoding/write/flush completion cannot be embedded in the response
        # they describe. Bind them in the next response, or the final EOF line.
        emission = dict(schema=1, nonce=nonce, request_id=request_id,
                        response_encode_started_ns=time.monotonic_ns())
        payload = json.dumps(response)
        emission['response_encode_finished_ns'] = time.monotonic_ns()
        emission['write_started_ns'] = time.monotonic_ns()
        output.write(payload + '\n')
        emission['write_finished_ns'] = time.monotonic_ns()
        emission['flush_started_ns'] = time.monotonic_ns()
        output.flush()
        emission['flush_finished_ns'] = time.monotonic_ns()
        previous = emission
    output.write(json.dumps(dict(diagnostic_eof=dict(schema=1, nonce=nonce,
                      requests=request_id, emission=previous))) + '\n')
    output.flush()


def main():
    assert os.path.exists('/etc/osbus-security-guest'), 'disposable VM required'
    path, nonce = sys.argv[1:]
    assert path.startswith('/run/osbus-p08/') and '/..' not in path
    workload = Workload(path, healthy=True)
    print(json.dumps(dict(ok=True, result=dict(pid=os.getpid(), uid=os.getuid(),
                                             name=workload.source.name))), flush=True)
    try:
        serve(workload, nonce, sys.stdin, sys.stdout)
    finally:
        workload.close()


if __name__ == '__main__':
    main()
