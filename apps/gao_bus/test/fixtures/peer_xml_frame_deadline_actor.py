"""One ordinary incomplete call held for the compiled XML frame deadline."""
import os
import signal
import stat
import sys

from peer_hello_split_boundaries_actor import (
    GET_ID, HELLO, NormalClient, acquired, command, emit, health, registration, reply,
)
from transport_actor import call, string, u32


def registered(path, bus_id=None):
    client = NormalClient(path)
    client.send(b"BEGIN\r\n" + HELLO + GET_ID)
    rows, observed_id = registration(client, bus_id)
    return client, rows, observed_id


def run(path, uid, gid):
    assert os.path.isabs(path) and not sys.flags.optimize
    directory = os.stat(os.path.dirname(path))
    endpoint = os.stat(path)
    assert directory.st_uid == endpoint.st_uid == uid
    assert stat.S_IMODE(directory.st_mode) == 0o700
    assert stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o600
    assert 0 < uid < 0xFFFFFFFF and 0 < gid < 0xFFFFFFFF
    assert os.getuid() == os.geteuid() == uid
    assert os.getgid() == os.getegid() == gid
    signal.alarm(30)
    observer = source = None
    try:
        observer, control, bus_id = registered(path)
        owned = "org.foundation.XmlDeadlineObserver"
        request = string(owned)
        observer.send(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        ownership = observer.messages(2)
        returns = [row for row in ownership if row["type"] == 2]
        signals = [row for row in ownership if row["type"] == 4]
        assert len(returns) == len(signals) == 1
        assert reply(returns[0], 3) == u32(1)
        acquired(signals[0], owned, observer.name)
        observer.empty()
        emit("ready", observer=observer.name, owned=owned, actor_pid=os.getpid(),
             uid=uid, gid=gid, auth=observer.writes[0], ok=observer.auth.hex(),
             hello=HELLO.hex(), get_id=GET_ID.hex(), bus_id=bus_id.hex(),
             control=control, ownership=ownership, writes=observer.writes)

        command("open")
        source, rows, _ = registered(path, bus_id)
        assert source.name != observer.name
        emit("opened", source=source.name, auth=source.writes[0], ok=source.auth.hex(),
             receipts=rows, writes=source.writes)

        # This is a valid ordinary GetId with a new serial; its tail is never sent.
        packet = GET_ID[:8] + u32(3) + GET_ID[12:]
        assert len(packet) > 16
        command("first-byte")
        source.send(packet[:1])
        emit("partial", prefix=packet[:1].hex(), target=packet.hex(), writes=source.writes)

        command("grow")
        source.send(packet[1:16])
        emit("grown", prefix=packet[:16].hex(), writes=source.writes)

        command("held")
        source.empty()
        probe = health(observer, owned, bus_id, 10)
        emit("held", source=source.name, prefix=packet[:16].hex(), health=probe,
             buffered_hex="", socket_pending=False)

        # ExUnit observes automatic normal Peer DOWN before permitting this read.
        command("observe-close")
        assert source.sock.recv(1) == b"", "incomplete call produced output instead of EOF"
        emit("closed", disposition="automatic-eof", terminal_hex="")
        source.close()
        source = None

        command("settled")
        probe = health(observer, owned, bus_id, 20)
        emit("settled", observer=observer.name, owned=owned, bus_id=bus_id.hex(), health=probe)
        command("stop")
        observer.empty()
        emit("result", result="PASS", cases=1, observer=observer.name,
             owned=owned, bus_id=bus_id.hex())
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 4
    run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
