"""Two fixed FD-free missing-body-signature cases on an explicit private socket."""
import os
import signal
import stat
import sys

from peer_hello_split_boundaries_actor import (
    GET_ID, HELLO, NormalClient, acquired, command, emit, health, registration, reply,
)
from transport_actor import call, frame, string, u32


OWNED = "org.foundation.BodySignatureObserver"
TARGET = "org.foundation.BodySignatureTarget"


def registered(path, bus_id=None):
    client = NormalClient(path)
    client.send(b"BEGIN\r\n" + HELLO + GET_ID)
    rows, observed_id = registration(client, bus_id)
    return client, rows, observed_id


def run(path, case, expected_uid, expected_gid):
    assert os.path.isabs(path) and len(os.fsencode(path)) < 108
    assert case in ("absent", "empty") and not sys.flags.optimize
    assert 0 < expected_uid < 0xFFFFFFFF and 0 < expected_gid < 0xFFFFFFFF
    assert os.getuid() == os.geteuid() == expected_uid
    assert os.getgid() == os.getegid() == expected_gid
    directory = os.stat(os.path.dirname(path))
    endpoint = os.stat(path)
    assert stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
    assert stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o600
    assert directory.st_uid == endpoint.st_uid == expected_uid
    assert directory.st_gid == endpoint.st_gid == expected_gid
    signal.alarm(30)
    request = string(TARGET)
    body = request + b"\0" * (-len(request) % 4) + u32(0)
    fields = [(1, "o", "/org/freedesktop/DBus"),
              (2, "s", "org.freedesktop.DBus"), (3, "s", "RequestName"),
              (6, "s", "org.freedesktop.DBus")]
    if case == "empty":
        fields.append((8, "g", ""))
    packet = frame(1, 3, fields, body)
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
        emit("ready", case=case, observer=observer.name, owned=OWNED, target=TARGET,
             actor_pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             auth=observer.writes[0], ok=observer.auth.hex(), hello=HELLO.hex(),
             get_id=GET_ID.hex(), bus_id=bus_id.hex(), control=control,
             ownership=ownership, writes=observer.writes, frame=packet.hex(),
             body=body.hex(), pending_fds=0)
        command("open")
        source, rows, _ = registered(path, bus_id)
        assert source.name != observer.name
        emit("opened", case=case, source=source.name, auth=source.writes[0],
             ok=source.auth.hex(), receipts=rows, writes=source.writes, pending_fds=0)
        command("send")
        source.send(packet)
        emit("sent", case=case, frame=packet.hex(), body=body.hex(),
             writes=source.writes, pending_fds=0)
        # The source socket stays open until ExUnit proves automatic normal Peer DOWN.
        command("observe-close")
        assert source.sock.recv(1) == b"", "missing signature produced output instead of EOF"
        emit("closed", case=case, disposition="automatic-eof", terminal_hex="",
             source_socket_open=True, pending_fds=0)
        source.close()
        source = None
        command("settled")
        probe = health(observer, OWNED, bus_id, 10)
        emit("settled", case=case, observer=observer.name, owned=OWNED,
             bus_id=bus_id.hex(), health=probe, buffered_hex="", socket_pending=False,
             pending_fds=0)
        command("stop")
        observer.empty()
        emit("result", result="PASS", case=case, cases=1, observer=observer.name,
             owned=OWNED, target=TARGET, bus_id=bus_id.hex(), frame=packet.hex(),
             body=body.hex(), health=probe, disposition="automatic-eof", pending_fds=0)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 5
    run(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
