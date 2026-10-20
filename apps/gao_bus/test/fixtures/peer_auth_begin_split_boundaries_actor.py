"""Positive UID1101 AUTH/BEGIN splits on an explicit private Gao endpoint."""
import hashlib
import os
import signal
import socket
import sys

from peer_hello_split_boundaries_actor import (
    GET_ID, HELLO, NormalClient, acquired, command, emit, health,
    registration, reply,
)
from transport_actor import call, string, u32


AUTH = b"\0AUTH EXTERNAL 31313031\r\n"
BEGIN = b"BEGIN\r\n"
CASES = ([dict(family="AUTH", split=split) for split in range(1, 25)]
         + [dict(family="BEGIN", split=split) for split in range(1, 7)])


class SplitClient(NormalClient):
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(path)
        self.writes = []


def run(path):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    assert not sys.flags.optimize
    assert os.getuid() == os.getgid() == 1101
    assert len(AUTH) == 25 and len(BEGIN) == 7
    assert len(HELLO) == len(GET_ID) == 128
    assert hashlib.sha256(HELLO).hexdigest() == "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31"
    assert hashlib.sha256(GET_ID).hexdigest() == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"
    signal.alarm(30)
    observer = source = None
    try:
        observer = NormalClient(path)
        observer.send(BEGIN + HELLO + GET_ID)
        control, bus_id = registration(observer)
        owned = "org.foundation.AuthBeginSplitObserver"
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
             actor_pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             auth=AUTH.hex(), begin=BEGIN.hex(), ok=observer.auth.hex(),
             hello=HELLO.hex(), get_id=GET_ID.hex(), cases=CASES,
             control=control, ownership=ownership, writes=observer.writes)
        for index, case in enumerate(CASES):
            family, split = case["family"], case["split"]
            stream = AUTH if family == "AUTH" else BEGIN
            command("next")
            source = SplitClient(path)
            if family == "BEGIN":
                source.send(AUTH)
                source.auth = source.line()
                assert source.auth == observer.auth
                source.empty()
            emit("opened", index=index, **case, auth_completed=(family == "BEGIN"))
            command("prefix")
            source.send(stream[:split])
            source.empty()
            held_health = health(observer, owned, bus_id, 1000 + index * 4)
            emit("partial", index=index, **case, prefix=stream[:split].hex(),
                 writes=list(source.writes), health=held_health)
            command("finish")
            if family == "AUTH":
                source.send(AUTH[split:])
                source.auth = source.line()
                assert source.auth == observer.auth
                source.empty()
                source.send(BEGIN + HELLO + GET_ID)
            else:
                source.send(BEGIN[split:] + HELLO + GET_ID)
            rows, _ = registration(source, bus_id)
            assert source.name != observer.name
            probe = health(observer, owned, bus_id, 1002 + index * 4)
            emit("completed", index=index, **case, source=source.name,
                 bus_id=bus_id.hex(), ok=source.auth.hex(), receipts=rows,
                 reply_serials=[1, 2], writes=source.writes, health=probe,
                 buffered_hex="", socket_pending=False)
            command("close")
            source.close()
            source = None
            emit("closed", index=index, **case)
            command("settled")
        command("stop")
        health(observer, owned, bus_id, 2000)
        emit("result", result="PASS", cases=30, auth_cases=24, begin_cases=6,
             observer=observer.name, owned=owned, bus_id=bus_id.hex(),
             hello_sha256=hashlib.sha256(HELLO).hexdigest(),
             get_id_sha256=hashlib.sha256(GET_ID).hexdigest())
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2
    run(sys.argv[1])
