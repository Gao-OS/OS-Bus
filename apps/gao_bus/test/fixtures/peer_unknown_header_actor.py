"""One valid unknown string header on an explicit private, FD-free D-Bus connection."""
import json
import os
import re
import signal
import socket
import stat
import struct
import sys

from peer_hello_split_boundaries_actor import (
    BUS, GET_ID, HELLO, NormalClient, acquired, command, health, registration, reply,
)
from transport_actor import call, frame, read_string, string


def unknown_header_call():
    return frame(1, 3, [(1, "o", "/org/freedesktop/DBus"), (2, "s", BUS),
                        (3, "s", "GetId"), (6, "s", BUS), (8, "g", ""),
                        (42, "s", "org.foundation.UnknownHeader")])


def normalized(row):
    return dict(row, fields={int(key): value for key, value in row["fields"].items()})


def check_reply(row, serial, destination, body):
    row = normalized(row)
    assert row["fields"].get(6) == destination and row["fields"].get(8) == "s"
    assert row["fields"].get(9, 0) == 0
    assert reply(row, serial).hex() == body


def check_registration(rows, name, bus_id):
    assert len(rows) == 3
    returns = [row for row in rows if row["type"] == 2]
    signals = [row for row in rows if row["type"] == 4]
    assert len(returns) == 2 and len(signals) == 1
    check_reply(returns[0], 1, name, string(name).hex())
    check_reply(returns[1], 2, name, bus_id)
    signal_row = normalized(signals[0])
    assert signal_row["fields"].get(9, 0) == 0
    acquired(signal_row, name, name)


def validate_run(events):
    assert [row["event"] for row in events] == ["ready", "opened", "completed", "closed", "result"]
    ready, opened, completed, closed, result = events
    observer, source, bus_id = ready["observer"], opened["source"], ready["bus_id"]
    assert observer.startswith(":") and source.startswith(":") and observer != source
    body = bytes.fromhex(bus_id)
    assert body == string(read_string(body)) and re.fullmatch("[0-9a-f]{32}", read_string(body))
    assert ready["frame"] == completed["frame"] == unknown_header_call().hex()
    assert completed["identity"] == ready["identity"]
    uid = ready["identity"]["uid"]
    assert type(uid) is int and uid > 0
    auth = b"\0AUTH EXTERNAL " + str(uid).encode().hex().encode() + b"\r\n"
    for row in (ready, opened):
        assert row["writes"] == [auth.hex(), (b"BEGIN\r\n" + HELLO + GET_ID).hex()]
    check_registration(ready["control"], observer, bus_id)
    check_registration(opened["registration"], source, bus_id)
    assert opened["connection"] == completed["connection"]
    assert opened["peer_credentials"] == completed["peer_credentials"]
    assert completed["source"] == closed["source"] == source
    assert completed["writes"] == [unknown_header_call().hex(), call("GetId", 4).hex()]
    assert completed["reply_serials"] == [3, 4] and len(completed["receipts"]) == 2
    for row, serial in zip(completed["receipts"], (3, 4)):
        check_reply(row, serial, source, bus_id)
    assert type(completed["received_fds"]) is int and completed["received_fds"] == 0
    assert completed["buffered_hex"] == "" and completed["socket_pending"] is False
    for row, serial in zip((completed, closed, result), (10, 20, 30)):
        assert row["observer"] == observer and row["bus_id"] == bus_id
        assert len(row["health"]) == 2
        check_reply(row["health"][0], serial, observer, string(observer).hex())
        check_reply(row["health"][1], serial + 1, observer, bus_id)
    assert type(result["cases"]) is int and result["cases"] == 1 and result["result"] == "PASS"


def identity():
    with open("/proc/self/stat") as handle:
        raw = handle.read()
    return dict(pid=os.getpid(), starttime_ticks=int(raw[raw.rfind(")") + 2:].split()[19]),
                uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid())


def emit(row):
    print(json.dumps(row), flush=True)


def connect(path, bus_id=None):
    client = NormalClient(path)
    try:
        client.send(b"BEGIN\r\n" + HELLO + GET_ID)
        rows, observed_id = registration(client, bus_id)
        return client, rows, observed_id
    except BaseException:
        client.close()
        raise


def run(path):
    assert not sys.flags.optimize and os.path.isabs(path)
    parent, endpoint = os.stat(os.path.dirname(path)), os.stat(path)
    assert stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_uid == os.getuid()
    assert stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o600
    signal.alarm(30)
    who, extension = identity(), unknown_header_call()
    observer = source = None
    try:
        observer, control, bus_id = connect(path)
        common = dict(observer=observer.name, bus_id=bus_id.hex())
        ready = dict(event="ready", **common, identity=who, control=control,
                     writes=list(observer.writes), frame=extension.hex())
        emit(ready)
        command("open")
        source, receipts, _ = connect(path, bus_id)
        assert source.name != observer.name
        info = os.fstat(source.sock.fileno())
        connection = dict(pid=who["pid"], starttime_ticks=who["starttime_ticks"],
                          fd=source.sock.fileno(), device=info.st_dev, inode=info.st_ino)
        credentials = list(struct.unpack("3i", source.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
        opened = dict(event="opened", source=source.name, registration=receipts,
                      connection=connection, peer_credentials=credentials, writes=list(source.writes))
        emit(opened)
        command("send")
        write_start = len(source.writes)
        source.send(extension)
        first, = source.messages(1)
        check_reply(first, 3, source.name, bus_id.hex())
        source.empty()
        source.send(call("GetId", 4))
        second, = source.messages(1)
        check_reply(second, 4, source.name, bus_id.hex())
        source.empty()
        completed = dict(event="completed", **common, source=source.name, identity=who,
                         connection=connection, peer_credentials=credentials, frame=extension.hex(),
                         writes=source.writes[write_start:], receipts=[first, second], reply_serials=[3, 4],
                         received_fds=0, buffered_hex="", socket_pending=False,
                         health=health(observer, observer.name, bus_id, 10))
        emit(completed)
        command("close")
        source.close()
        source = None
        closed = dict(event="closed", **common, source=completed["source"],
                      health=health(observer, observer.name, bus_id, 20))
        emit(closed)
        command("stop")
        result = dict(event="result", **common, cases=1, result="PASS",
                      health=health(observer, observer.name, bus_id, 30))
        observer.close()
        observer = None
        validate_run([ready, opened, completed, closed, result])
        emit(result)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2
    run(sys.argv[1])
