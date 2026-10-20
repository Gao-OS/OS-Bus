"""One finite batch of terminal prefixes on an explicit private native endpoint."""
import hashlib
import json
import os
import signal
import socket
import stat
import struct
import sys
import time

from peer_hello_split_boundaries_actor import (
    GET_ID, HELLO, NormalClient, acquired, command, health, registration, reply,
)
from transport_actor import call, string, u32


OWNED = "org.foundation.PrefixObserver"
# The established vm_security/workload.json burst.per_kind iteration envelope.
CASES = 32
PREFIX = bytes([255, 1, 0, 1]) + struct.pack("<III", 0, 3, 0)
PREFIX_HEX = "ff010001000000000300000000000000"


def receipt(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def writes(client):
    # Derive receipts only from successful sends recorded by the unchanged helper.
    return [receipt(bytes.fromhex(value)) for value in client.writes]


def emit(event, **values):
    line = json.dumps(dict(event=event, **values), separators=(",", ":"))
    assert len(line.encode("ascii")) + 1 <= 16_384, "actor control line exceeds bound"
    print(line, flush=True)


def registered(path, bus_id=None):
    client = NormalClient(path)
    client.send(b"BEGIN\r\n" + HELLO + GET_ID)
    rows, observed_id = registration(client, bus_id)
    assert len(client.writes) == 2
    return client, rows, observed_id


def observer_health(client, bus_id, serial):
    started = time.monotonic_ns()
    rows = health(client, OWNED, bus_id, serial)
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    assert elapsed_ms <= 1000, elapsed_ms
    assert [row["fields"][5] for row in rows] == [serial, serial + 1]
    assert all(row["fields"][6] == client.name and row["fields"][8] == "s"
               for row in rows)
    return rows, elapsed_ms


def run(path, expected_uid, expected_gid):
    assert os.path.isabs(path) and len(os.fsencode(path)) < 108
    assert not sys.flags.optimize
    assert 0 < expected_uid < 0xFFFFFFFF and 0 < expected_gid < 0xFFFFFFFF
    assert os.getuid() == os.geteuid() == expected_uid
    assert os.getgid() == os.getegid() == expected_gid
    directory = os.stat(os.path.dirname(path))
    endpoint = os.stat(path)
    assert stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
    assert stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o600
    assert directory.st_uid == endpoint.st_uid == expected_uid
    assert directory.st_gid == endpoint.st_gid == expected_gid
    assert CASES == 32
    assert len(PREFIX) == 16 and PREFIX == bytes.fromhex(PREFIX_HEX)
    signal.alarm(30)
    observer = source = None
    source_names = []
    source_writes = None
    try:
        observer, control, bus_id = registered(path)
        request = string(OWNED)
        observer.send(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        ownership = observer.messages(2)
        returns = [row for row in ownership if row["type"] == 2]
        signals = [row for row in ownership if row["type"] == 4]
        assert len(returns) == len(signals) == 1
        assert reply(returns[0], 3) == u32(1)
        acquired(signals[0], OWNED, observer.name)
        observer.empty()
        assert len(observer.writes) == 3
        emit("ready", observer=observer.name, owned=OWNED,
             actor_pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             auth=observer.writes[0], ok=observer.auth.hex(), hello=HELLO.hex(),
             get_id=GET_ID.hex(), bus_id=bus_id.hex(), control=control,
             ownership=ownership, writes=writes(observer), prefix=PREFIX_HEX,
             cases=CASES, buffered_hex="", socket_pending=False, pending_fds=0)
        for iteration in range(1, CASES + 1):
            assert source is None
            command("open")
            source, rows, _ = registered(path, bus_id)
            assert source.name != observer.name and source.name not in source_names
            source_names.append(source.name)
            emit("opened", iteration=iteration, source=source.name,
                 auth=source.writes[0], ok=source.auth.hex(), receipts=rows,
                 writes=writes(source), buffered_hex="", socket_pending=False,
                 pending_fds=0)
            command("prefix")
            source.send(PREFIX)
            assert len(source.writes) == 3
            source_writes = writes(source)
            assert source.sock.fileno() >= 0
            emit("sent", iteration=iteration, source=source.name, prefix=PREFIX_HEX,
                 writes=source_writes, observer_writes=writes(observer),
                 source_socket_open=True, pending_fds=0)
            # The controller proves normal Peer DOWN and full authority/accounting
            # restoration before permitting this read. The actor never closes first.
            command("closed")
            source_socket_open = source.sock.fileno() >= 0
            assert source_socket_open
            started = time.monotonic_ns()
            terminal, controls, flags, _ = source.sock.recvmsg(1, socket.CMSG_SPACE(253 * 4))
            eof_ms = (time.monotonic_ns() - started) / 1_000_000
            assert eof_ms <= 3000, eof_ms
            assert terminal == b"", "invalid prefix produced output instead of EOF"
            assert controls == [] and flags == 0, "unexpected rights or flags at EOF"
            emit("closed", iteration=iteration, source=source.name,
                 disposition="automatic-eof", source_socket_open=source_socket_open,
                 terminal_hex=terminal.hex(), eof_ms=eof_ms, writes=source_writes,
                 buffered_hex="", socket_pending=False, pending_fds=0)
            source.close()
            source = None
            command("observe")
            serial = 10 + (iteration - 1) * 2
            rows, elapsed_ms = observer_health(observer, bus_id, serial)
            assert len(observer.writes) == 3 + 2 * iteration
            emit("observed", iteration=iteration, observer=observer.name, owned=OWNED,
                 bus_id=bus_id.hex(), health=rows, observer_health_ms=elapsed_ms,
                 writes=writes(observer), buffered_hex="", socket_pending=False,
                 pending_fds=0)
        command("stop")
        observer.empty()
        assert len(source_names) == len(set(source_names)) == CASES
        assert len(observer.writes) == 67
        emit("result", result="PASS", cases=CASES, source_names=source_names,
             observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             prefix=PREFIX_HEX, source_writes=source_writes,
             observer_writes=writes(observer), buffered_hex="",
             socket_pending=False, pending_fds=0)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 4
    run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
