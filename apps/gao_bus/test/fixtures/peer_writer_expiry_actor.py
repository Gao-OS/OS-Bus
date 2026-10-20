"""Real blocked Peer expiry on one explicitly private Unix socket."""
import array
import json
import os
import select
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
import transport_actor as wire

BUS = "org.freedesktop.DBus"
OWNED = "org.foundation.WriterExpiry"
RESOURCE = b"ABSOLUTE-WRITER-EXPIRY"


def emit(event, **details):
    print(json.dumps({"event": event, **details}), flush=True)


def checkpoint(event, **details):
    emit(event, **details)
    assert sys.stdin.readline().strip() == "continue", "controller checkpoint"


def daemon_fds(pid, prefix):
    directory = "/proc/%s/fd" % pid
    entries = os.listdir(directory)
    resources = []
    for entry in entries:
        try:
            target = os.readlink(directory + "/" + entry)
        except FileNotFoundError:
            continue
        if prefix in target:
            resources.append(target)
    return {"daemon_fds": len(entries), "daemon_memfds": sorted(resources)}


def reclaimed(pid, prefix, count):
    deadline = time.monotonic() + 1
    while True:
        snapshot = daemon_fds(pid, prefix)
        assert not snapshot["daemon_memfds"], snapshot
        if snapshot["daemon_fds"] == count:
            return snapshot
        assert time.monotonic() < deadline, ("daemon descriptor recovery deadline", snapshot, count)


def probe(observer, serial):
    started = time.monotonic()
    deadline = started + 1
    observer.sock.sendall(wire.call("GetId", serial))
    readable, _, _ = select.select([observer.sock], [], [], max(deadline - time.monotonic(), 0))
    assert readable, "healthy wire deadline 1000ms"
    observer.sock.settimeout(max(deadline - time.monotonic(), 0.001))
    reply = observer.receive()
    assert reply["type"] == 2 and reply["fields"].get(5) == serial, reply
    assert reply["fields"].get(7) == BUS and reply["fields"].get(6) == observer.name, reply
    assert not reply["fds"] and reply["fields"].get(8) == "s", reply
    identifier = wire.read_string(reply["body"])
    assert len(identifier) == 32 and all(char in "0123456789abcdef" for char in identifier)
    assert time.monotonic() <= deadline, "healthy wire deadline 1000ms"
    return identifier, (time.monotonic() - started) * 1000


def drain_expired(target):
    received, rights = b"", []
    deadline = time.monotonic() + 3
    try:
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "expired recipient EOF deadline"
            readable, _, _ = select.select([target.sock], [], [], remaining)
            assert readable, "expired recipient EOF deadline"
            data, controls, flags, _ = target.sock.recvmsg(
                65536, socket.CMSG_SPACE(253 * 4), socket.MSG_CMSG_CLOEXEC)
            assert not flags & socket.MSG_CTRUNC, "truncated partial-output rights"
            for level, kind, raw in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                descriptors = array.array("i")
                descriptors.frombytes(raw)
                rights.extend(descriptors)
            if not data:
                break
            received += data
        assert len(received) >= 16 and received[:4] == b"l\x04\x00\x01"
        body, serial, header = struct.unpack_from("<III", received, 4)
        frame_bytes = 16 + header + (-header % 8) + body
        assert serial == 300 and len(received) < frame_bytes, "writer completed instead of expiring"
        assert len(rights) == 1, ("duplicated/queued partial-output rights", rights)
        assert os.pread(rights[0], 128, 0) == RESOURCE, "wrong or prematurely closed resource"
        return {"partial_bytes": len(received), "frame_bytes": frame_bytes, "rights": len(rights)}
    finally:
        wire.close_fds(rights)


def run(path, daemon_pid):
    clients = []
    prefix = "osbus-peer-expiry-%d" % os.getpid()
    try:
        for negotiated in [True, True, False]:
            clients.append(wire.Client(path, negotiate=negotiated))
        source, target, observer = clients
        body = wire.string(OWNED)
        target.sock.sendall(wire.call("RequestName", 10, "su",
            body + wire.padding(len(body), 4) + wire.u32(0)))
        assert target.reply(10)["body"] == wire.u32(1)
        rule = "type='signal',interface='org.foundation.WriterExpiry',member='Never'"
        target.sock.sendall(wire.call("AddMatch", 11, "s", wire.string(rule)))
        assert target.reply(11)["type"] == 2
        target.barrier(12)
        # Warm actual receive/duplication/Writer/closure paths before counting
        # daemon descriptors; the qualification never raises a noisy baseline.
        descriptor = os.memfd_create(prefix + "-warmup", os.MFD_CLOEXEC)
        try:
            os.write(descriptor, RESOURCE)
            source.send_fds(wire.signal(100, target.name), [descriptor])
        finally:
            os.close(descriptor)
        message = target.receive()
        try:
            assert message["serial"] == 100 and message["body"] == wire.u32(0), message
            assert len(message["fds"]) == 1, message
            assert os.pread(message["fds"][0], 128, 0) == RESOURCE
        finally:
            wire.close_fds(message["fds"])
        target.barrier(102)
        source.barrier(103)
        identifier, _ = probe(observer, 900000)
        baseline = daemon_fds(daemon_pid, prefix)
        assert baseline["daemon_memfds"] == []
        checkpoint("ready", source=source.name, target=target.name,
                   observer=observer.name, owned=OWNED, **baseline)

        for index, size in enumerate([196608, 16384]):
            descriptor = os.memfd_create(prefix + ("-current" if index == 0 else "-queued"), os.MFD_CLOEXEC)
            try:
                os.write(descriptor, RESOURCE if index == 0 else b"QUEUED-WRITER-EXPIRY")
                payload = bytes(range(256)) * (size // 256)
                body = wire.u32(0) + wire.u32(len(payload)) + payload
                source.send_fds(wire.signal(300 + index, OWNED, 1, body, "hay"), [descriptor])
            finally:
                os.close(descriptor)
        source.sock.sendall(wire.call("ListNames", 302))
        reply = source.receive()
        assert reply["type"] == 2 and reply["fields"].get(5) == 302, reply
        assert reply["fields"].get(7) == BUS and not reply["fds"], reply
        checkpoint("queued", messages=2)

        actual_id, latency = probe(observer, 900001)
        assert actual_id == identifier, "blocked writer restarted the core"
        snapshot = daemon_fds(daemon_pid, prefix)
        assert len(snapshot["daemon_memfds"]) == 2, snapshot
        assert any(prefix + "-current" in resource for resource in snapshot["daemon_memfds"]), snapshot
        assert any(prefix + "-queued" in resource for resource in snapshot["daemon_memfds"]), snapshot
        checkpoint("blocked_healthy", latency_ms=latency, **snapshot)

        # Until this checkpoint the recipient has never read or closed its
        # socket. Natural Peer timeout leaves one incomplete frame and one FD.
        partial = drain_expired(target)
        snapshot = reclaimed(daemon_pid, prefix, baseline["daemon_fds"] - 2)
        checkpoint("target_closed", **partial, **snapshot)
        actual_id, latency = probe(observer, 900002)
        assert actual_id == identifier, "writer expiry restarted the core"
        checkpoint("expired_healthy", latency_ms=latency)

        for client in clients:
            client.close()
        snapshot = reclaimed(daemon_pid, prefix, baseline["daemon_fds"] - 6)
        emit("closed", **snapshot)
    finally:
        for client in clients:
            client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 3 and os.path.isabs(sys.argv[1])
    run(sys.argv[1], sys.argv[2])
