"""One native maximum-frame byte array with compact actual-write receipts."""
import hashlib
import json
import os
import signal
import stat
import sys
import time

from peer_hello_split_boundaries_actor import (
    BUS, GET_ID, HELLO, NormalClient, acquired, command, health,
    registration, reply,
)
from transport_actor import call, string, u32


OWNED = "org.foundation.CollectionObserver"
FRAME_BYTES = 1_048_576
PAYLOAD_COUNT = FRAME_BYTES - 16 - 120 - 4
PAYLOAD = b"\x2a" * PAYLOAD_COUNT
BODY = u32(PAYLOAD_COUNT) + PAYLOAD
FRAME = call("GetId", 3, "ay", BODY)
HEADER = bytes.fromhex(
    "6c01000178ff0f000300000078000000"
    "01016f00150000002f6f72672f667265656465736b746f702f44427573000000"
    "02017300140000006f72672e667265656465736b746f702e4442757300000000"
    "03017300050000004765744964000000"
    "06017300140000006f72672e667265656465736b746f702e4442757300000000"
    "0801670002617900"
)
INVALID_ARGS = "org.freedesktop.DBus.Error.InvalidArgs"
ERROR_TEXT = "Arguments do not match the bus method signature"


def receipt(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


TARGET = dict(
    serial=3, signature="ay", header_hex=HEADER.hex(), array_length_hex="74ff0f00",
    payload=dict(count=PAYLOAD_COUNT, byte=42, **receipt(PAYLOAD)),
    body=receipt(BODY), packet=receipt(FRAME),
)


def writes(client):
    # NormalClient records each successful sendall in hexadecimal. Preserve that
    # shared helper and derive compact receipts from its actual recorded bytes.
    return [receipt(bytes.fromhex(value)) for value in client.writes]


def emit(event, **values):
    line = json.dumps(dict(event=event, **values), separators=(",", ":"))
    assert len(line.encode("ascii")) + 1 <= 16_384, "actor control line exceeds bound"
    print(line, flush=True)


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
    assert PAYLOAD_COUNT == len(PAYLOAD) == 1_048_436
    assert len(HEADER) == 136 and FRAME[:136] == HEADER
    assert len(BODY) == 1_048_440 and len(FRAME) == FRAME_BYTES
    assert FRAME[:16] == bytes.fromhex("6c01000178ff0f000300000078000000")
    assert BODY[:4] == bytes.fromhex("74ff0f00")
    assert FRAME[136:] == BODY and BODY[4:] == PAYLOAD
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
             ownership=ownership, writes=writes(observer), target=TARGET, pending_fds=0)
        command("open")
        source, rows, _ = registered(path, bus_id)
        assert source.name != observer.name
        emit("opened", source=source.name, auth=source.writes[0],
             ok=source.auth.hex(), receipts=rows, writes=writes(source), pending_fds=0)
        command("collection")
        started = time.monotonic_ns()
        source.send(FRAME)
        error, = source.messages(1)
        assert error["type"] == 3 and error["fields"][4] == INVALID_ARGS, error
        assert error["fields"][5] == 3 and error["fields"][6] == source.name, error
        assert error["fields"][7] == BUS and error["fields"][8] == "s", error
        assert bytes.fromhex(error["body"]) == string(ERROR_TEXT), error
        source.empty()
        source_health = checked_health(source, source.name, bus_id, 4)
        collection_ms = (time.monotonic_ns() - started) / 1_000_000
        assert collection_ms <= 3000, collection_ms
        emit("collected", source=source.name, target=TARGET, error=error,
             source_health=source_health, collection_ms=collection_ms,
             writes=writes(source), observer_writes=writes(observer),
             buffered_hex="", socket_pending=False, pending_fds=0)
        # Controller records the settled source/authority endpoint before probes.
        command("observe")
        first_health, first_ms = observer_health(observer, bus_id, 10)
        emit("observed", observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             health=first_health, observer_health_ms=first_ms, writes=writes(observer),
             buffered_hex="", socket_pending=False, pending_fds=0)
        command("close-source")
        source.empty()
        source_writes = writes(source)
        source.close()
        source = None
        emit("closed", disposition="controller-close", writes=source_writes, pending_fds=0)
        command("settled")
        final_health, final_ms = observer_health(observer, bus_id, 12)
        emit("settled", observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             health=final_health, observer_health_ms=final_ms, writes=writes(observer),
             buffered_hex="", socket_pending=False, pending_fds=0)
        command("stop")
        observer.empty()
        emit("result", result="PASS", cases=1,
             observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             target=TARGET, error=error, source_health=source_health,
             collection_ms=collection_ms, source_writes=source_writes,
             observer_writes=writes(observer), observer_health=[first_health, final_health],
             observer_health_ms=[first_ms, final_ms],
             disposition="controller-close", pending_fds=0)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 4
    run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
