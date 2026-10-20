"""One FD-free native static array-depth boundary on a private socket."""
import os
import signal
import stat
import sys
import time

from peer_hello_split_boundaries_actor import (
    BUS, GET_ID, HELLO, NormalClient, acquired, command, emit, health,
    registration, reply,
)
from transport_actor import call, string, u32


OWNED = "org.foundation.ArrayDepthObserver"
SIGNATURE32 = "a" * 32 + "y"
SIGNATURE33 = "a" + SIGNATURE32
BODY32 = b"".join(u32(size) for size in range(125, 0, -4)) + b"\x2a"
BODY33 = u32(129) + BODY32
FRAME32 = call("GetId", 3, SIGNATURE32, BODY32)
FRAME33 = call("GetId", 6, SIGNATURE33, BODY33)
INVALID_ARGS = "org.freedesktop.DBus.Error.InvalidArgs"
ERROR_TEXT = "Arguments do not match the bus method signature"


def registered(path, bus_id=None):
    client = NormalClient(path)
    client.send(b"BEGIN\r\n" + HELLO + GET_ID)
    rows, observed_id = registration(client, bus_id)
    return client, rows, observed_id


def checked_health(client, owned, bus_id, serial):
    rows = health(client, owned, bus_id, serial)
    assert [row["fields"][5] for row in rows] == [serial, serial + 1]
    assert all(row["fields"][6] == client.name and row["fields"][8] == "s"
               for row in rows)
    return rows


def observer_health(client, bus_id, serial):
    started = time.monotonic_ns()
    rows = checked_health(client, OWNED, bus_id, serial)
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    assert elapsed_ms <= 1000, elapsed_ms
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
    assert len(BODY32) == 129 and len(BODY33) == 133
    assert len(FRAME32) == 297 and len(FRAME33) == 301
    assert FRAME32[:16] == b"l\x01\0\x01" + u32(129) + u32(3) + u32(151)
    assert FRAME33[:16] == b"l\x01\0\x01" + u32(133) + u32(6) + u32(152)
    assert FRAME32[167:] == b"\0" + BODY32
    assert FRAME33[168:] == BODY33
    signal.alarm(30)
    observer = source = None
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
        emit("ready", observer=observer.name, owned=OWNED,
             actor_pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             auth=observer.writes[0], ok=observer.auth.hex(), hello=HELLO.hex(),
             get_id=GET_ID.hex(), bus_id=bus_id.hex(), control=control,
             ownership=ownership, writes=observer.writes,
             frame32=FRAME32.hex(), frame33=FRAME33.hex(),
             body32=BODY32.hex(), body33=BODY33.hex(), pending_fds=0)
        command("open")
        source, rows, _ = registered(path, bus_id)
        assert source.name != observer.name
        emit("opened", source=source.name, auth=source.writes[0],
             ok=source.auth.hex(), receipts=rows, writes=source.writes, pending_fds=0)
        command("depth32")
        source.send(FRAME32)
        errors = source.messages(1)
        error = errors[0]
        assert error["type"] == 3 and error["fields"][4] == INVALID_ARGS, error
        assert error["fields"][5] == 3 and error["fields"][6] == source.name, error
        assert error["fields"][7] == BUS and error["fields"][8] == "s", error
        assert bytes.fromhex(error["body"]) == string(ERROR_TEXT), error
        source.empty()
        source_health = checked_health(source, source.name, bus_id, 4)
        first_health, first_ms = observer_health(observer, bus_id, 10)
        emit("depth32", source=source.name, frame=FRAME32.hex(), body=BODY32.hex(),
             error=error, source_health=source_health, observer_health=first_health,
             observer_health_ms=first_ms, writes=source.writes,
             buffered_hex="", socket_pending=False, pending_fds=0)
        command("depth33")
        source.send(FRAME33)
        emit("sent33", source=source.name, frame=FRAME33.hex(), body=BODY33.hex(),
             writes=source.writes, pending_fds=0)
        # Keep the source socket open and unread until ExUnit observes normal Peer DOWN.
        command("observe-close")
        assert source.sock.fileno() >= 0
        assert source.sock.recv(1) == b"", "depth33 produced output instead of exact EOF"
        emit("closed", disposition="automatic-eof", terminal_hex="",
             source_socket_open=True, pending_fds=0)
        source.close()
        source = None
        command("settled")
        final_health, final_ms = observer_health(observer, bus_id, 12)
        emit("settled", observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             health=final_health, observer_health_ms=final_ms,
             buffered_hex="", socket_pending=False, pending_fds=0)
        command("stop")
        observer.empty()
        emit("result", result="PASS", cases=1, boundaries=[32, 33],
             observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             frame32=FRAME32.hex(), frame33=FRAME33.hex(),
             body32=BODY32.hex(), body33=BODY33.hex(), error=error,
             source_health=source_health, observer_health=[first_health, final_health],
             observer_health_ms=[first_ms, final_ms],
             disposition="automatic-eof", pending_fds=0)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 4
    run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
