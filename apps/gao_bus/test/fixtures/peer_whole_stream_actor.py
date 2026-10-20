"""One ordinary AUTH+BEGIN+Hello+GetId write on an explicit private endpoint."""
import hashlib
import json
import os
import re
import signal
import socket
import stat
import struct
import sys
import time

from peer_hello_split_boundaries_actor import (
    BUS, GET_ID, HELLO, NormalClient, acquired, command, health, registration, reply,
)
from transport_actor import call, read_string, string


def build_stream(uid):
    assert type(uid) is int and uid > 0
    auth = b"\0AUTH EXTERNAL " + str(uid).encode().hex().encode() + b"\r\n"
    assert len(auth) == 25, "actual UID must produce AUTH25"
    assert len(HELLO) == len(GET_ID) == 128
    assert hashlib.sha256(HELLO).hexdigest() == "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31"
    assert hashlib.sha256(GET_ID).hexdigest() == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"
    stream = auth + b"BEGIN\r\n" + HELLO + GET_ID
    assert len(stream) == 288
    return stream


def normalized(row):
    return dict(row, fields={int(k): v for k, v in row["fields"].items()})


def check_reply(row, serial, destination, body):
    row = normalized(row)
    assert 4 not in row["fields"]
    assert row["fields"].get(6) == destination and row["fields"].get(8) == "s"
    assert type(row["fields"].get(9, 0)) is int and row["fields"].get(9, 0) == 0
    assert reply(row, serial).hex() == body


def validate_registration(rows, source, bus_id):
    assert isinstance(rows, list) and len(rows) == 3
    replies = [row for row in rows if row["type"] == 2]
    signals = [row for row in rows if row["type"] == 4]
    assert len(replies) == 2 and len(signals) == 1
    check_reply(replies[0], 1, source, string(source).hex())
    check_reply(replies[1], 2, source, bus_id)
    signal_row = normalized(signals[0])
    assert 4 not in signal_row["fields"] and signal_row["fields"].get(9, 0) == 0
    acquired(signal_row, source, source)


def validate_health(receipts, observer, bus_id, first_serial):
    assert isinstance(receipts, list) and len(receipts) == 2
    check_reply(receipts[0], first_serial, observer, string(observer).hex())
    check_reply(receipts[1], first_serial + 1, observer, bus_id)


def validate_case(record):
    assert record["event"] == "completed" and record["family"] == "C"
    assert record["id"] == "coalesced" and record["result"] == "PASS"
    identity = record["identity"]
    for key in ("pid", "starttime_ticks", "uid", "euid", "gid", "egid"):
        assert type(identity[key]) is int and identity[key] > 0
    assert identity["uid"] == identity["euid"] and identity["gid"] == identity["egid"]
    stream = build_stream(identity["uid"])
    assert record["stream"] == stream.hex() and record["writes"] == [stream.hex()]
    assert record["stream_sha256"] == hashlib.sha256(stream).hexdigest()
    connection = record["connection"]
    assert connection["pid"] == identity["pid"]
    assert connection["starttime_ticks"] == identity["starttime_ticks"]
    assert type(connection["fd"]) is int and connection["fd"] >= 0
    assert type(connection["device"]) is int and connection["device"] >= 0
    assert type(connection["inode"]) is int and connection["inode"] > 0
    credentials = record["peer_credentials"]
    assert isinstance(credentials, list) and len(credentials) == 3
    assert all(type(v) is int and v > 0 for v in credentials)
    assert credentials[1:] == [identity["uid"], identity["gid"]]
    ok = bytes.fromhex(record["ok"])
    assert re.fullmatch(b"OK [0-9a-f]{32}\r\n", ok)
    assert record["source"].startswith(":") and record["observer"].startswith(":")
    assert record["source"] != record["observer"]
    bus_id = bytes.fromhex(record["bus_id"])
    assert bus_id == string(read_string(bus_id))
    assert re.fullmatch("[0-9a-f]{32}", read_string(bus_id))
    validate_registration(record["receipts"], record["source"], record["bus_id"])
    assert record["reply_serials"] == [1, 2]
    assert type(record["received_fds"]) is int and record["received_fds"] == 0
    assert record["buffered_hex"] == "" and record["socket_pending"] is False


def validate_run(events):
    assert isinstance(events, list) and [e["event"] for e in events] == [
        "ready", "opened", "completed", "closed", "result"]
    ready, opened, case, closed, result = events
    validate_case(case)
    for key in ("observer", "bus_id", "ok", "identity", "stream", "stream_sha256"):
        assert ready[key] == case[key]
    validate_registration(ready["control"], ready["observer"], ready["bus_id"])
    for key in ("connection", "peer_credentials"):
        assert opened[key] == case[key]
    validate_health(case["health"], case["observer"], case["bus_id"], 10)
    for event in (closed, result):
        assert event["observer"] == case["observer"] and event["bus_id"] == case["bus_id"]
    assert closed["source"] == case["source"]
    validate_health(closed["health"], case["observer"], case["bus_id"], 20)
    elapsed = closed["ownership_disappearance_seconds"]
    assert type(elapsed) in (int, float) and 0 <= elapsed <= 1.5
    rows, serials = closed["ownership_disappearance"], closed["disappearance_serials"]
    assert rows and len(rows) == len(serials) and serials == list(range(100, 100 + len(rows)))
    for row, serial in zip(rows[:-1], serials[:-1]):
        check_reply(row, serial, case["observer"], string(case["source"]).hex())
    last = normalized(rows[-1])
    assert last["type"] == 3
    assert last["fields"].get(4) == "org.freedesktop.DBus.Error.NameHasNoOwner"
    assert last["fields"].get(5) == serials[-1] and last["fields"].get(6) == case["observer"]
    assert last["fields"].get(7) == BUS and last["fields"].get(9, 0) == 0
    validate_health(result["health"], case["observer"], case["bus_id"], 30)
    assert type(result["cases"]) is int and result["cases"] == 1 and result["result"] == "PASS"


def identity():
    with open("/proc/self/stat") as handle:
        raw = handle.read()
    return dict(pid=os.getpid(), starttime_ticks=int(raw[raw.rfind(")") + 2:].split()[19]),
                uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid())


def emit(event):
    print(json.dumps(event), flush=True)


def run(path):
    assert not sys.flags.optimize and os.path.isabs(path)
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    assert stat.S_ISSOCK(os.stat(path).st_mode) and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    signal.alarm(30)
    who = identity()
    stream = build_stream(who["uid"])
    observer = source = None
    try:
        observer = NormalClient(path)
        observer.send(b"BEGIN\r\n" + HELLO + GET_ID)
        control, bus_id = registration(observer)
        ready = dict(event="ready", observer=observer.name, bus_id=bus_id.hex(),
                     ok=observer.auth.hex(), identity=who, control=control,
                     stream=stream.hex(), stream_sha256=hashlib.sha256(stream).hexdigest())
        emit(ready)
        source = NormalClient.__new__(NormalClient)
        source.writes = []
        source.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        source.sock.settimeout(3)
        source.sock.connect(path)
        info = os.fstat(source.sock.fileno())
        connection = dict(pid=who["pid"], starttime_ticks=who["starttime_ticks"],
                          fd=source.sock.fileno(), device=info.st_dev, inode=info.st_ino)
        credentials = list(struct.unpack("3i", source.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
        opened = dict(event="opened", connection=connection, peer_credentials=credentials)
        emit(opened)
        command("send")
        source.send(stream)
        source.auth = source.line()
        assert source.auth == observer.auth
        receipts, _ = registration(source, bus_id)
        case = dict(event="completed", family="C", id="coalesced", result="PASS",
                    source=source.name, observer=observer.name, bus_id=bus_id.hex(),
                    identity=who, connection=connection, peer_credentials=credentials,
                    writes=source.writes, stream=stream.hex(), stream_sha256=ready["stream_sha256"],
                    ok=source.auth.hex(), receipts=receipts, reply_serials=[1, 2],
                    received_fds=0, buffered_hex="", socket_pending=False,
                    health=health(observer, observer.name, bus_id, 10))
        validate_case(case)
        emit(case)
        command("close")
        source.close()
        source = None
        began = time.monotonic()
        gone, serials = [], []
        while True:
            assert time.monotonic() - began < 1.5, "source ownership disappearance deadline"
            serial = 100 + len(gone)
            observer.send(call("GetNameOwner", serial, "s", string(case["source"])))
            row, = observer.messages(1)
            gone.append(row)
            serials.append(serial)
            if row["type"] == 3:
                break
            assert reply(row, serial) == string(case["source"])
        closed = dict(event="closed", source=case["source"], observer=observer.name,
                      bus_id=bus_id.hex(), ownership_disappearance=gone,
                      disappearance_serials=serials, ownership_disappearance_seconds=time.monotonic() - began,
                      health=health(observer, observer.name, bus_id, 20))
        emit(closed)
        command("stop")
        result = dict(event="result", result="PASS", cases=1, observer=observer.name,
                      bus_id=bus_id.hex(), health=health(observer, observer.name, bus_id, 30))
        observer.close()
        observer = None
        validate_run([ready, opened, case, closed, result])
        emit(result)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2
    run(sys.argv[1])
