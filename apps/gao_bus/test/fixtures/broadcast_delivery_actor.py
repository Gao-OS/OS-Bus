"""Independent mixed-negotiation and receive-denial broadcast effect checks."""
import json
import os
import sys

sys.dont_write_bytecode = True
import transport_actor as wire

BUS = "org.freedesktop.DBus"
INTERFACE = "org.foundation.Broadcast"
CONTENTS = b"OS-BUS-BROADCAST-MEMFD"
PLAIN = "RIGHTS0-BROADCAST"


def emit(event, **details):
    print(json.dumps({"event": event, **details}), flush=True)


def checkpoint(event, **details):
    emit(event, **details)
    assert sys.stdin.readline().strip() == "continue", "controller checkpoint"


def healthy(client, serial):
    client.sock.sendall(wire.call("GetNameOwner", serial, "s", wire.string(client.name)))
    # Do not use Client.reply: skipping unexpected signals would hide a denied
    # delivery. Stream order puts any earlier broadcast before this exact reply.
    reply = client.receive()
    try:
        assert reply["type"] == 2 and reply["fields"].get(5) == serial, reply
        assert reply["fields"].get(7) == BUS and reply["fields"].get(6) == client.name
        assert reply["body"] == wire.string(client.name) and not reply["fds"]
    finally:
        wire.close_fds(reply["fds"])


def signal(serial, member, signature, body, count=None):
    fields = [(1, "o", "/broadcast"), (2, "s", INTERFACE),
              (3, "s", member), (8, "g", signature)]
    if count is not None:
        fields.append((9, "u", count))
    return wire.frame(4, serial, fields, body)


def received_signal(client, source, serial, member):
    message = client.receive()
    try:
        assert message["type"] == 4 and message["serial"] == serial
        assert message["fields"].get(1) == "/broadcast"
        assert message["fields"].get(2) == INTERFACE and message["fields"].get(3) == member
        assert message["fields"].get(7) == source.name and message["fields"].get(6) is None
    except BaseException:
        wire.close_fds(message["fds"])
        raise
    return message


def run(path, mode):
    assert mode in ("mixed", "denied", "missing", "send_denied", "receive_denied")
    clients = []
    resource_name = "foundation-broadcast-%d" % os.getpid()
    try:
        clients.append(wire.Client(path))
        clients.append(wire.Client(path))
        clients.append(wire.Client(path, negotiate=mode == "denied"))
        source, target, other = clients
        for recipient in (target, other):
            rule = "type='signal',interface='%s'" % INTERFACE
            recipient.sock.sendall(wire.call("AddMatch", 3, "s", wire.string(rule)))
            assert recipient.reply(3)["type"] == 2
        before_fds = len(os.listdir("/proc/self/fd"))
        checkpoint("ready", names=[client.name for client in clients], mode=mode,
                   resource_name=resource_name)

        fd = os.memfd_create(resource_name, os.MFD_CLOEXEC)
        try:
            assert os.write(fd, CONTENTS) == len(CONTENTS)
            if mode in ("missing", "send_denied", "receive_denied"):
                destination = "org.foundation.Absent" if mode == "missing" else target.name
                message = wire.frame(1, 100, [(1, "o", "/broadcast"),
                    (2, "s", INTERFACE), (3, "s", "Resource"), (6, "s", destination),
                    (8, "g", "h"), (9, "u", 1)], wire.u32(0), flags=2)
            else:
                message = signal(100, "Resource", "h", wire.u32(0), 1)
            source.send_fds(message, [fd])
        finally:
            os.close(fd)

        if mode in ("missing", "send_denied", "receive_denied"):
            error_name = "ServiceUnknown" if mode == "missing" else "AccessDenied"
            reply = source.receive()
            try:
                assert reply["type"] == 3 and reply["fields"].get(5) == 100, reply
                assert reply["fields"].get(4) == "org.freedesktop.DBus.Error." + error_name
                assert reply["fields"].get(7) == BUS and reply["fields"].get(6) == source.name
                assert not reply["fds"], "error response leaked descriptors"
            finally:
                wire.close_fds(reply["fds"])
        else:
            source.barrier(101)

        resource_deliveries = 0
        if mode == "mixed":
            message = received_signal(target, source, 100, "Resource")
            try:
                assert message["body"] == wire.u32(0) and message["fields"].get(9) == 1
                assert len(message["fds"]) == 1
                received = message["fds"][0]
                assert resource_name in os.readlink("/proc/self/fd/%d" % received)
                assert os.pread(received, len(CONTENTS) + 1, 0) == CONTENTS
                resource_deliveries = 1
            finally:
                wire.close_fds(message["fds"])
        for index, client in enumerate(clients):
            healthy(client, 110 + index)

        if mode in ("mixed", "denied"):
            source.sock.sendall(signal(200, "Plain", "s", wire.string(PLAIN)))
            source.barrier(201)
        plain_deliveries = 0
        if mode == "mixed":
            for recipient in (target, other):
                message = received_signal(recipient, source, 200, "Plain")
                try:
                    assert message["body"] == wire.string(PLAIN) and not message["fds"]
                    plain_deliveries += 1
                finally:
                    wire.close_fds(message["fds"])
        for index, client in enumerate(clients):
            healthy(client, 210 + index)
        assert len(os.listdir("/proc/self/fd")) == before_fds, "actor descriptor leak"
        checkpoint("checked", mode=mode, resource_deliveries=resource_deliveries,
                   rights0_deliveries=plain_deliveries, healthy_replies=6, actor_fd_growth=0)
    finally:
        for client in clients:
            client.close()
    emit("closed")


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2])
