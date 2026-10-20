"""Original actor operations with payload-free socket/RPC timing; no retry/deadline changes."""
import json
from pathlib import Path
import time

from actor import Worker, main
import diagnostic_actor  # Reuse only its observed-drain command.

PATH = Path('/run/osbus-fairness/timing-health.jsonl')
original_init, original_rpc = Worker.__init__, Worker.rpc


def record(worker, event, **fields):
    row = {'event': event, 'monotonic_ns': time.monotonic_ns(), 'realtime_ns': time.time_ns(),
           'serial': worker.serial, **fields}
    with PATH.open('a') as output:
        output.write(json.dumps(row, sort_keys=True) + '\n')


class ObservedSocket:
    def __init__(self, sock, worker):
        self.sock, self.worker = sock, worker

    def __getattr__(self, key):
        return getattr(self.sock, key)

    def sendall(self, data, *args, **kwargs):
        record(self.worker, 'socket_begin', stage='sendall', bytes=len(data))
        try:
            result = self.sock.sendall(data, *args, **kwargs)
        except Exception as error:
            record(self.worker, 'socket_error', stage='sendall', error_type=type(error).__name__, errno=getattr(error, 'errno', None))
            raise
        record(self.worker, 'socket_end', stage='sendall')
        return result

    def recvmsg(self, size, *args, **kwargs):
        record(self.worker, 'socket_begin', stage='recvmsg', requested_bytes=size)
        try:
            result = self.sock.recvmsg(size, *args, **kwargs)
        except Exception as error:
            record(self.worker, 'socket_error', stage='recvmsg', error_type=type(error).__name__, errno=getattr(error, 'errno', None))
            raise
        record(self.worker, 'socket_end', stage='recvmsg', received_bytes=len(result[0]))
        return result


def observed_init(worker, path, role, index):
    original_init(worker, path, role, index)
    if role == 'healthy':
        worker.client.sock = ObservedSocket(worker.client.sock, worker)
        record(worker, 'health_ready', socket_timeout_seconds=worker.client.sock.gettimeout())


def observed_rpc(worker, member, signature='', body=b''):
    if worker.role != 'healthy':
        return original_rpc(worker, member, signature, body)
    record(worker, 'rpc_begin', requested_serial=worker.serial + 1, member=member)
    try:
        result = original_rpc(worker, member, signature, body)
    except Exception as error:
        record(worker, 'rpc_error', member=member, error_type=type(error).__name__, errno=getattr(error, 'errno', None))
        raise
    record(worker, 'rpc_end', member=member)
    return result


Worker.__init__, Worker.rpc = observed_init, observed_rpc

if __name__ == '__main__':
    main()
