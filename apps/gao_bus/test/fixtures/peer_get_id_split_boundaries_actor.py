"""Positive FD-free GetId splits after normal Hello on a private Gao endpoint."""
import hashlib
import os
import signal
import sys

from peer_hello_split_boundaries_actor import (
    BUS, GET_ID, HELLO, NormalClient, acquired, command, emit, health,
    registration, reply,
)
from transport_actor import call, read_string, string, u32


GET_ID_SUCCESSOR = GET_ID[:8] + u32(3) + GET_ID[12:]


def hello_registration(client):
    rows = client.messages(2)
    replies = [row for row in rows if row["type"] == 2]
    signals = [row for row in rows if row["type"] == 4]
    assert len(replies) == len(signals) == 1, rows
    body = reply(replies[0], 1)
    name = read_string(body)
    assert name.startswith(":") and body == string(name)
    assert replies[0]["fields"][6] == name and replies[0]["fields"][8] == "s"
    acquired(signals[0], name, name)
    client.name = name
    client.empty()
    return rows


def get_id_replies(client, bus_id):
    rows = client.messages(2)
    for row, serial in zip(rows, (2, 3)):
        assert reply(row, serial) == bus_id, row
        assert row["fields"][6] == client.name and row["fields"][8] == "s", row
    client.empty()
    return rows


def run(path):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    assert not sys.flags.optimize
    assert len(GET_ID) == 128
    assert hashlib.sha256(GET_ID).hexdigest() == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"
    signal.alarm(45)
    observer = source = None
    try:
        observer = NormalClient(path)
        observer.send(b"BEGIN\r\n" + HELLO + GET_ID)
        control, bus_id = registration(observer)
        owned = "org.foundation.GetIdSplitObserver"
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
            source.send(b"BEGIN\r\n" + HELLO)
            registration_rows = hello_registration(source)
            assert source.name != observer.name
            emit("opened", split=split, source=source.name, auth=source.auth.hex(),
                 receipts=registration_rows, writes=source.writes)
            command("prefix")
            source.send(GET_ID[:split])
            held_health = health(observer, owned, bus_id, 1000 + split * 4)
            emit("partial", split=split, prefix=GET_ID[:split].hex(), health=held_health)
            command("finish")
            source.send(GET_ID[split:] + GET_ID_SUCCESSOR)
            rows = get_id_replies(source, bus_id)
            probe = health(observer, owned, bus_id, 1002 + split * 4)
            emit("completed", split=split, source=source.name, bus_id=bus_id.hex(),
                 receipts=rows, reply_serials=[2, 3], writes=source.writes, health=probe,
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
