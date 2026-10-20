"""Finite FD-free fixed-header length checks on one explicit private endpoint."""
import os
import signal
import struct
import sys

from peer_hello_split_boundaries_actor import (
    GET_ID, HELLO, NormalClient, acquired, command, emit, health, registration, reply,
)
from transport_actor import call, string, u32


HEADER_MAX = 67_108_864
MESSAGE_CAP = 67_108_888


def prefix(endian, length):
    order = "<" if endian == "little" else ">"
    marker = b"l" if endian == "little" else b"B"
    return marker + bytes([1, 0, 1]) + struct.pack(order + "III", 0, 3, length)


def registered(path, bus_id=None):
    client = NormalClient(path)
    client.send(b"BEGIN\r\n" + HELLO + GET_ID)
    rows, observed_id = registration(client, bus_id)
    return client, rows, observed_id


def run(path, endian):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    assert endian in ("little", "big") and not sys.flags.optimize
    expected_uid = int(os.environ.get("OS_BUS_FIXED_HEADER_UID", "1101"))
    expected_gid = int(os.environ.get("OS_BUS_FIXED_HEADER_GID", "1101"))
    assert 0 < expected_uid < 0xFFFFFFFF and 0 < expected_gid < 0xFFFFFFFF
    assert os.getuid() == os.geteuid() == expected_uid
    assert os.getgid() == os.getegid() == expected_gid
    signal.alarm(30)
    observer = source = None
    try:
        observer, control, bus_id = registered(path)
        owned = "org.foundation.FixedHeaderObserver"
        request = string(owned)
        observer.send(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        ownership = observer.messages(2)
        returns = [row for row in ownership if row["type"] == 2]
        signals = [row for row in ownership if row["type"] == 4]
        assert len(returns) == len(signals) == 1
        assert reply(returns[0], 3) == u32(1)
        acquired(signals[0], owned, observer.name)
        observer.empty()
        emit("ready", endian=endian, observer=observer.name, owned=owned,
             actor_pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             auth=observer.writes[0], ok=observer.auth.hex(), hello=HELLO.hex(),
             get_id=GET_ID.hex(), bus_id=bus_id.hex(), control=control,
             ownership=ownership, writes=observer.writes, message_cap=MESSAGE_CAP)
        for index, family in enumerate(("valid", "invalid")):
            command("open-" + family)
            source, rows, _ = registered(path, bus_id)
            assert source.name != observer.name
            emit("opened", family=family, source=source.name, auth=source.writes[0],
                 ok=source.auth.hex(), receipts=rows, writes=source.writes)
            command("prefix-" + family)
            packet = prefix(endian, HEADER_MAX + index)
            assert len(packet) == 16
            source.send(packet)
            emit("sent", family=family, prefix=packet.hex(), writes=source.writes)
            if family == "valid":
                command("held")
                source.empty()
                probe = health(observer, owned, bus_id, 10)
                emit("held", family=family, prefix=packet.hex(), health=probe,
                     buffered_hex="", socket_pending=False)
                command("close-valid")
                source.close()
                source = None
                emit("closed", family=family, disposition="client-normal-close")
            else:
                # ExUnit must observe automatic Peer DOWN before this command.
                command("observe-close")
                assert source.sock.recv(1) == b"", "invalid prefix produced output instead of EOF"
                emit("closed", family=family, disposition="automatic-eof", terminal_hex="")
                source.close()
                source = None
            command("settled-" + family)
            probe = health(observer, owned, bus_id, 20 + index * 2)
            emit("settled", family=family, health=probe)
        command("stop")
        observer.empty()
        emit("result", result="PASS", endian=endian, cases=2,
             observer=observer.name, owned=owned, bus_id=bus_id.hex())
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 3
    run(sys.argv[1], sys.argv[2])
