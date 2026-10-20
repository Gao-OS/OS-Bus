"""One FD-free native typed arg0path nonmatch with a positive control."""
import os
import signal
import stat
import sys
import time

from peer_hello_split_boundaries_actor import (
    GET_ID, HELLO, NormalClient, acquired, command, emit,
    registration, reply,
)
from transport_actor import call, frame, string, u32


OWNED = "org.foundation.MatchArgumentObserver"
RULE = "type='signal',arg0path='/probe'"
POSITIVE_BODY = string("/probe")
UINT32_BODY = u32(42)


def target(serial, signature, body):
    return frame(4, serial, [(1, "o", "/probe"),
                            (2, "s", "org.foundation.Probe"),
                            (3, "s", "Changed"), (8, "g", signature)], body)


POSITIVE = target(3, "s", POSITIVE_BODY)
UINT32 = target(6, "u", UINT32_BODY)


def registered(path, bus_id=None):
    client = NormalClient(path)
    client.send(b"BEGIN\r\n" + HELLO + GET_ID)
    rows, observed_id = registration(client, bus_id)
    return client, rows, observed_id


def send_health(client, owned, serial):
    client.send(call("GetNameOwner", serial, "s", string(owned)))
    client.send(call("GetId", serial + 1))


def check_health(client, rows, bus_id, serial):
    assert len(rows) == 2, rows
    assert reply(rows[0], serial) == string(client.name)
    assert reply(rows[1], serial + 1) == bus_id
    assert all(row["fields"][6] == client.name and row["fields"][8] == "s"
               and 9 not in row["fields"] for row in rows)
    client.empty()
    return rows


def source_health(client, bus_id, serial):
    send_health(client, client.name, serial)
    return check_health(client, client.messages(2), bus_id, serial)


def observer_health(client, bus_id, serial, source_name=None):
    started = time.monotonic_ns()
    send_health(client, OWNED, serial)
    # Exact counts and order: never skip a signal while searching for a reply.
    rows = client.messages(3 if source_name is not None else 2)
    positive = None
    if source_name is not None:
        positive, *rows = rows
        assert positive["type"] == 4 and positive["serial"] == 3, positive
        assert positive["fields"] == {
            1: "/probe", 2: "org.foundation.Probe", 3: "Changed",
            7: source_name, 8: "s",
        }, positive
        assert positive["body"] == POSITIVE_BODY.hex(), positive
    checked = check_health(client, rows, bus_id, serial)
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    assert elapsed_ms <= 1000, elapsed_ms
    return positive, checked, elapsed_ms


def run(path, expected_uid, expected_gid):
    assert os.path.isabs(path) and len(os.fsencode(path)) < 108
    assert not sys.flags.optimize
    assert 0 < expected_uid < 0xFFFFFFFF and 0 < expected_gid < 0xFFFFFFFF
    assert os.getuid() == os.geteuid() == expected_uid
    assert os.getgid() == os.getegid() == expected_gid
    directory = os.stat(os.path.dirname(path))
    endpoint = os.stat(path)
    assert stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
    assert stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o600
    assert directory.st_uid == endpoint.st_uid == expected_uid
    assert directory.st_gid == endpoint.st_gid == expected_gid
    assert len(POSITIVE_BODY) == 11 and len(UINT32_BODY) == 4
    assert len(POSITIVE) == 99 and len(UINT32) == 92
    assert POSITIVE[:16] == b"l\x04\0\x01" + u32(11) + u32(3) + u32(71)
    assert UINT32[:16] == b"l\x04\0\x01" + u32(4) + u32(6) + u32(71)
    assert POSITIVE[87:] == b"\0" + POSITIVE_BODY
    assert UINT32[87:] == b"\0" + UINT32_BODY
    signal.alarm(30)
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
        observer.send(call("AddMatch", 4, "s", string(RULE)))
        installed, = observer.messages(1)
        assert reply(installed, 4) == b"", installed
        assert installed["fields"][6] == observer.name
        assert installed["fields"].get(8, "") == ""
        assert 9 not in installed["fields"]
        observer.empty()
        emit("ready", observer=observer.name, owned=OWNED, rule=RULE,
             actor_pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             auth=observer.writes[0], ok=observer.auth.hex(), hello=HELLO.hex(),
             get_id=GET_ID.hex(), bus_id=bus_id.hex(), control=control,
             ownership=ownership, installed=installed, writes=observer.writes,
             positive_frame=POSITIVE.hex(), uint32_frame=UINT32.hex(),
             positive_body=POSITIVE_BODY.hex(), uint32_body=UINT32_BODY.hex(),
             pending_fds=0)
        command("open")
        source, rows, _ = registered(path, bus_id)
        assert source.name != observer.name
        emit("opened", source=source.name, auth=source.writes[0],
             ok=source.auth.hex(), receipts=rows, writes=source.writes, pending_fds=0)
        command("positive")
        source.send(POSITIVE)
        positive_source = source_health(source, bus_id, 4)
        # Router completes source routing before these replies. Only now may
        # observer probes follow the already enqueued matching delivery.
        received, positive_observer, positive_ms = observer_health(
            observer, bus_id, 10, source.name)
        emit("positive", source=source.name, frame=POSITIVE.hex(), body=POSITIVE_BODY.hex(),
             received=received, source_health=positive_source,
             observer_health=positive_observer, observer_health_ms=positive_ms,
             writes=source.writes, observer_writes=observer.writes,
             buffered_hex="", socket_pending=False, pending_fds=0)
        command("uint32")
        source.send(UINT32)
        typed_source = source_health(source, bus_id, 7)
        emit("typed-source", source=source.name, frame=UINT32.hex(), body=UINT32_BODY.hex(),
             source_health=typed_source, writes=source.writes,
             observer_writes=observer.writes,
             buffered_hex="", socket_pending=False, pending_fds=0)
        # ExUnit observes the settled source/authority and records its endpoint
        # before authorizing observer probes. A wrong signal precedes replies.
        command("observe")
        _, typed_observer, typed_ms = observer_health(observer, bus_id, 12)
        emit("observed", observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             health=typed_observer, observer_health_ms=typed_ms,
             writes=observer.writes, buffered_hex="", socket_pending=False, pending_fds=0)
        command("close-source")
        source.empty()
        source.close()
        source = None
        emit("closed", disposition="controller-close", pending_fds=0)
        command("settled")
        _, final_health, final_ms = observer_health(observer, bus_id, 14)
        emit("settled", observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             health=final_health, observer_health_ms=final_ms, writes=observer.writes,
             buffered_hex="", socket_pending=False, pending_fds=0)
        command("stop")
        observer.empty()
        emit("result", result="PASS", cases=1, rule=RULE,
             observer=observer.name, owned=OWNED, bus_id=bus_id.hex(),
             positive_frame=POSITIVE.hex(), uint32_frame=UINT32.hex(),
             positive_body=POSITIVE_BODY.hex(), uint32_body=UINT32_BODY.hex(),
             received=received, source_health=[positive_source, typed_source],
             observer_health=[positive_observer, typed_observer, final_health],
             observer_health_ms=[positive_ms, typed_ms, final_ms],
             disposition="controller-close", pending_fds=0)
    finally:
        if source is not None:
            source.close()
        if observer is not None:
            observer.close()


if __name__ == "__main__":
    assert len(sys.argv) == 4
    run(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
