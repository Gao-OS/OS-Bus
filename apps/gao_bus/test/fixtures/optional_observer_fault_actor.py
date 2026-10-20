"""Two persistent independent clients across an owned optional-observer outage."""
import json
import os
import sys
import time

import transport_actor as wire

BUS = "org.freedesktop.DBus"
SOURCE = "org.foundation.OptionalSource"
HEALTHY = "org.foundation.OptionalHealthy"
TRANSIENT = "org.foundation.OptionalTransient"


def checkpoint(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)
    assert sys.stdin.readline().strip() == "continue", "controller checkpoint"


class Client(wire.Client):
    def line(self):
        result = super().line()
        if result.startswith(b"OK "):
            self.guid = result[3:-2].decode()
        return result


def reply(client, serial, body, deadline=None):
    if deadline is not None:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "original health1000ms deadline"
        client.sock.settimeout(remaining)
    result = client.reply(serial)
    assert result["type"] == 2 and result["fields"].get(5) == serial, result
    assert result["fields"].get(7) == BUS, result
    assert result["fields"].get(6) == client.name, result
    assert result["body"] == body and result["fds"] == [], result
    if deadline is not None:
        assert time.monotonic() <= deadline, "original health1000ms deadline"
    return result


def request_name(client, name, serial):
    body = wire.string(name)
    client.sock.sendall(wire.call("RequestName", serial, "su",
                                body + wire.padding(len(body), 4) + wire.u32(0)))


def health(client, serial):
    started = time.monotonic()
    client.sock.sendall(wire.call("GetNameOwner", serial, "s", wire.string(HEALTHY)))
    reply(client, serial, wire.string(client.name), started + 1)
    return (time.monotonic() - started) * 1000


def run(path):
    clients = []
    try:
        source = Client(path, negotiate=False)
        clients.append(source)
        healthy = Client(path, negotiate=False)
        clients.append(healthy)
        assert source.guid == healthy.guid
        for client, name in [(source, SOURCE), (healthy, HEALTHY)]:
            request_name(client, name, 10)
            reply(client, 10, wire.u32(1))
            client.barrier(11)
        healthy.sock.sendall(wire.call("AddMatch", 12, "s",
                                     wire.string("type='signal',member='NeverOptionalFault'")))
        reply(healthy, 12, b"")
        healthy.sock.sendall(wire.call("GetId", 13))
        result = healthy.reply(13)
        bus_id = wire.read_string(result["body"])
        reply_check = result["type"] == 2 and result["fields"].get(5) == 13
        assert reply_check and result["fields"].get(7) == BUS
        assert result["fields"].get(6) == healthy.name and result["fds"] == []
        latencies = [health(healthy, 14)]
        source.barrier(15)
        healthy.barrier(15)
        checkpoint("ready", source=source.name, healthy=healthy.name, guid=source.guid,
                   bus_id=bus_id, pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
                   health_ms=latencies)

        started = time.monotonic()
        healthy.sock.sendall(wire.call("GetNameOwner", 20, "s", wire.string(HEALTHY)))
        request_name(source, TRANSIENT, 20)
        checkpoint("submitted", health_serial=20, source_serial=20,
                   started_monotonic_ns=int(started * 1_000_000_000))
        reply(healthy, 20, wire.string(healthy.name), started + 1)
        latencies.append((time.monotonic() - started) * 1000)
        reply(source, 20, wire.u32(1))

        # Both sockets have genuine outstanding requests during the permanent outage.
        started = time.monotonic()
        healthy.sock.sendall(wire.call("GetNameOwner", 21, "s", wire.string(HEALTHY)))
        source.sock.sendall(wire.call("ReleaseName", 21, "s", wire.string(TRANSIENT)))
        reply(healthy, 21, wire.string(healthy.name), started + 1)
        latencies.append((time.monotonic() - started) * 1000)
        reply(source, 21, wire.u32(1))
        source.barrier(22)
        healthy.barrier(22)
        latencies.append(health(healthy, 23))
        healthy.sock.sendall(wire.call("GetId", 24))
        reply(healthy, 24, wire.string(bus_id))
        source.barrier(25)
        healthy.barrier(25)
        checkpoint("drained", source=source.name, healthy=healthy.name,
                   guid=source.guid, bus_id=bus_id, health_ms=latencies,
                   counts={"health": 4, "transient_acquired": 1, "transient_released": 1},
                   reconnects=0)
    finally:
        for client in clients:
            client.close()
    print(json.dumps({"event": "closed", "clients": len(clients)}), flush=True)


if __name__ == "__main__":
    assert len(sys.argv) == 2 and os.path.isabs(sys.argv[1])
    run(sys.argv[1])
