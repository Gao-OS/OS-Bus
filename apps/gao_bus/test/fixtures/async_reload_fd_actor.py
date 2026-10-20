"""One FD-bearing reload on an explicitly supplied private Unix socket."""
import os
import select
import signal
import stat
import sys

from transport_actor import Client, close_fds, frame


def emit(*parts):
    print(" ".join(str(part) for part in parts), flush=True)


def command(expected):
    assert sys.stdin.readline().strip() == expected, expected


def no_pending_bytes(client):
    assert not select.select([client.sock], [], [], 0)[0], "unexpected caller bytes or EOF"


def receipt(client, serial, event):
    message = client.receive()
    try:
        assert message["type"] == 2, message
        assert message["fields"][5] == serial, message
        assert message["fields"][6] == client.name, message
        assert message["fields"].get(8, "") == "", message
        assert message["body"] == b"" and message["fds"] == [], message
        emit(event, message["serial"], client.name, len(message["fds"]))
    finally:
        close_fds(message["fds"])


def run(path):
    signal.alarm(20)
    assert os.path.isabs(path) and stat.S_ISSOCK(os.stat(path).st_mode)
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    client = Client.__new__(Client)
    reader = writer = None
    try:
        Client.__init__(client, path, negotiate=True)
        reader, writer = os.pipe()
        assert os.write(writer, b"U") == 1
        assert os.read(reader, 1) == b"U"
        fields = [(1, "o", "/org/freedesktop/DBus"),
                  (2, "s", "org.freedesktop.DBus"), (3, "s", "ReloadConfig"),
                  (6, "s", "org.freedesktop.DBus"), (8, "g", ""), (9, "u", 1)]
        reload = frame(1, 300, fields)
        emit("ready", os.getpid(), client.name, reload.hex())
        command("prefix")
        client.send_fds(reload[:16], [reader])
        emit("prefix", reload[:16].hex())
        command("finish")
        client.sock.sendall(reload[16:])
        os.close(reader)
        reader = None
        ping = frame(1, 301, [(1, "o", "/org/freedesktop/DBus"),
                              (2, "s", "org.freedesktop.DBus.Peer"),
                              (3, "s", "Ping"), (6, "s", "org.freedesktop.DBus")])
        client.sock.sendall(ping)
        emit("queued")
        command("probe")
        no_pending_bytes(client)
        try:
            os.write(writer, b"LEAK-PROBE")
        except BrokenPipeError:
            emit("retired", "no_early_bytes", "broken_pipe")
        else:
            raise AssertionError("a transferred pipe reader survived reload admission")
        command("replies")
        receipt(client, 300, "reload_reply")
        receipt(client, 301, "ping_reply")
        no_pending_bytes(client)
        emit("complete")
        command("stop")
        no_pending_bytes(client)
        emit("stopped")
    finally:
        for descriptor in (reader, writer):
            if descriptor is not None:
                os.close(descriptor)
        if hasattr(client, "sock"):
            client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2
    run(sys.argv[1])
