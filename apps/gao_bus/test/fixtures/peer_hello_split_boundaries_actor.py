"""Positive FD-free Hello splits on an explicit private Gao endpoint."""
import hashlib
import json
import os
import select
import signal
import socket
import sys

from transport_actor import Client, call, close_fds, read_string, string, u32


BUS = "org.freedesktop.DBus"
HELLO = bytes.fromhex(
    "6c01000100000000010000006d00000001016f00150000002f6f72672f667265656465"
    "736b746f702f4442757300000002017300140000006f72672e667265656465736b746f"
    "702e4442757300000000030173000500000048656c6c6f00000006017300140000006f"
    "72672e667265656465736b746f702e4442757300000000"
)
GET_ID = bytes.fromhex(
    "6c01000100000000020000006d00000001016f00150000002f6f72672f667265656465"
    "736b746f702f4442757300000002017300140000006f72672e667265656465736b746f"
    "702e44427573000000000301730005000000476574496400000006017300140000006f"
    "72672e667265656465736b746f702e4442757300000000"
)


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


def command(expected):
    assert sys.stdin.readline().strip() == expected, expected


class NormalClient(Client):
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(path)
        self.writes = []
        self.send(b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode() + b"\r\n")
        self.auth = self.line()
        assert self.auth.startswith(b"OK ") and len(self.auth) == 37

    def send(self, data):
        self.sock.sendall(data)
        self.writes.append(data.hex())

    def messages(self, count):
        rows = []
        for _ in range(count):
            row = self.receive()
            if row["fds"]:
                close_fds(row["fds"])
                raise AssertionError("unexpected rights on normal registration")
            assert row["fields"].get(9, 0) == 0
            rows.append(dict(type=row["type"], serial=row["serial"],
                             fields=row["fields"], body=row["body"].hex()))
        return rows

    def empty(self):
        # The inherited reader consumes exact extents and retains no byte buffer.
        assert not select.select([self.sock], [], [], 0)[0], "unconsumed socket bytes or EOF"


def reply(row, serial):
    assert row["type"] == 2 and row["fields"].get(5) == serial, row
    assert row["fields"][7] == BUS, row
    return bytes.fromhex(row["body"])


def acquired(row, name, destination):
    assert row["type"] == 4, row
    assert row["fields"][1] == "/org/freedesktop/DBus", row
    assert row["fields"][2] == row["fields"][7] == BUS, row
    assert row["fields"][3] == "NameAcquired" and row["fields"][8] == "s", row
    assert row["fields"][6] == destination and row["body"] == string(name).hex(), row


def registration(client, bus_id=None):
    rows = client.messages(3)
    replies = [row for row in rows if row["type"] == 2]
    signals = [row for row in rows if row["type"] == 4]
    assert len(replies) == 2 and len(signals) == 1, rows
    name_body = reply(replies[0], 1)
    name = read_string(name_body)
    assert name.startswith(":") and name_body == string(name)
    observed_id = reply(replies[1], 2)
    assert all(row["fields"][6] == name and row["fields"][8] == "s" for row in replies)
    acquired(signals[0], name, name)
    assert observed_id == string(read_string(observed_id))
    if bus_id is not None:
        assert observed_id == bus_id
    client.name = name
    client.empty()
    return rows, observed_id


def health(client, owned, bus_id, serial):
    client.send(call("GetNameOwner", serial, "s", string(owned)))
    client.send(call("GetId", serial + 1))
    rows = client.messages(2)
    assert reply(rows[0], serial) == string(client.name)
    assert reply(rows[1], serial + 1) == bus_id
    client.empty()
    return rows


def run(path):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    assert not sys.flags.optimize
    signal.alarm(45)
    observer = source = None
    try:
        observer = NormalClient(path)
        observer.send(b"BEGIN\r\n" + HELLO + GET_ID)
        control, bus_id = registration(observer)
        owned = "org.foundation.HelloSplitObserver"
        request = string(owned)
        observer.send(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        ownership = observer.messages(2)
        returns = [row for row in ownership if row["type"] == 2]
        signals = [row for row in ownership if row["type"] == 4]
        assert len(returns) == len(signals) == 1
        assert reply(returns[0], 3) == u32(1)
        acquired(signals[0], owned, observer.name)
        observer.empty()
        emit("ready", observer=observer.name, owned=owned, bus_id=bus_id.hex(),
             hello=HELLO.hex(), get_id=GET_ID.hex(), splits=list(range(1, 128)),
             control=control, ownership=ownership, writes=observer.writes)
        for split in range(1, 128):
            command("next")
            source = NormalClient(path)
            emit("opened", split=split, auth=source.auth.hex())
            command("prefix")
            source.send(b"BEGIN\r\n" + HELLO[:split])
            emit("partial", split=split, prefix=HELLO[:split].hex())
            command("finish")
            source.send(HELLO[split:] + GET_ID)
            rows, _ = registration(source, bus_id)
            assert source.name != observer.name
            probe = health(observer, owned, bus_id, 1000 + split * 2)
            emit("completed", split=split, source=source.name, receipts=rows,
                 reply_serials=[1, 2], writes=source.writes, health=probe,
                 buffered_hex="", socket_pending=False)
            command("close")
            source.close()
            source = None
            emit("closed", split=split)
            command("settled")
        command("stop")
        health(observer, owned, bus_id, 2000)
        emit("result", result="PASS", cases=127, observer=observer.name,
             owned=owned, bus_id=bus_id.hex(), hello_sha256=hashlib.sha256(HELLO).hexdigest(),
             get_id_sha256=hashlib.sha256(GET_ID).hexdigest())
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2
    run(sys.argv[1])
