"""Bounded private-socket actor for native coalesced receive boundaries."""
import json
import os
import select
import signal
import stat
import sys
from pathlib import Path

from transport_actor import Client, call, read_string, string


def emit(event, **details):
    print(json.dumps({"event": event, **details}), flush=True)


def command(expected):
    assert sys.stdin.readline().strip() == expected


def run(path, mode):
    assert mode in ("plain", "unknown", "negotiated", "ancillary", "limited")
    assert Path(path).is_absolute()
    assert stat.S_IMODE(os.stat(Path(path).parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    observer = Client(path, negotiate=False)
    source = None
    try:
        observer.sock.sendall(call("GetId", 3))
        identity = observer.receive()
        assert identity["type"] == 2 and identity["fields"][5] == 3
        assert identity["fds"] == []
        bus_id = read_string(identity["body"])
        source = Client(path, negotiate=mode == "negotiated")
        frames = [call("GetId", serial) for serial in range(10, 14 if mode == "unknown" else 13)]
        if mode == "unknown":
            frames[0] = frames[0][:1] + bytes([42]) + frames[0][2:]
        partial = frames[3][:8] if mode == "unknown" else b""
        queued = frames[0][16:] + frames[1] + frames[2] + partial
        emit("ready", source=source.name, observer=observer.name, bus_id=bus_id,
             frames=[frame.hex() for frame in frames])
        command("prefix")
        source.sock.sendall(frames[0][:16])
        emit("partial")
        command("queue")
        if mode == "ancillary":
            reader, writer = os.pipe()
            try:
                os.write(writer, b"PIPE")
                source.send_fds(queued, [reader])
            finally:
                os.close(reader)
                os.close(writer)
        else:
            source.sock.sendall(queued)
        emit("queued", bytes=len(queued))
        command("finish")
        if partial:
            source.sock.sendall(frames[3][8:])
        expected = ([11, 12, 13] if mode == "unknown" else
                    [] if mode == "ancillary" else [10, 11, 12])
        replies = []
        if mode == "ancillary":
            try:
                assert source.sock.recv(1) == b"", "unnegotiated rights reached routing"
            except ConnectionResetError:
                pass
        for serial in expected:
            # Read exactly once: reply() would silently skip an out-of-order reply.
            reply = source.receive()
            assert reply["type"] == 2 and reply["fields"][5] == serial, reply
            assert reply["fields"][6] == source.name, reply
            assert reply["fields"][7] == "org.freedesktop.DBus", reply
            assert reply["fields"][8] == "s", reply
            assert reply["fds"] == [] and reply["body"] == string(bus_id), reply
            replies.append(serial)
        if mode != "ancillary":
            assert not select.select([source.sock], [], [], 0)[0], "unexpected extra reply"
        observer.sock.sendall(call("GetId", 4))
        health = observer.receive()
        assert health["type"] == 2 and health["fields"][5] == 4
        assert health["fds"] == [] and health["body"] == string(bus_id)
        emit("completed", reply_serials=replies, bus_id=bus_id)
        command("close")
    finally:
        if source is not None:
            source.close()
        observer.close()
    emit("closed")


if __name__ == "__main__":
    signal.alarm(30)
    run(*sys.argv[1:])
