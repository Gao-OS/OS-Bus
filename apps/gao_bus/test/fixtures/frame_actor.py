import array, importlib.util, os, socket, struct, sys
from pathlib import Path
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("transport", Path(__file__).resolve().parent / "transport_actor.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
path, mode = sys.argv[1:]
client = t.Client(path)
rights = []
try:
    if mode in ("size", "large"):
        ceiling = 4096 if mode == "size" else 1049600
        empty = t.call("GetId", 10, "s", t.string(""))
        payload = t.call("GetId", 10, "s", t.string("x" * (ceiling - len(empty))))
        assert len(payload) == ceiling
        client.sock.sendall(payload)
        response = client.reply(10)
        assert response["type"] == 3 and response["fields"][4] == "org.freedesktop.DBus.Error.InvalidArgs", response
        client.barrier(11)
        if mode == "size":
            # Only the fixed prefix is sent: oversized length must close before
            # reading the claimed header/body or invoking the body decoder.
            payload = t.call("GetId", 12, "s", t.string("x" * (ceiling + 1 - len(empty))))
            client.sock.sendall(payload[:16])
            client.sock.settimeout(0.6)
            assert client.sock.recv(1) == b"", "oversized prefix was not rejected"
    elif mode in ("fds17", "fds253", "overfds", "unnegotiated", "malformed"):
        client.close()
        client = t.Client(path, negotiate=mode != "unnegotiated")
        target = t.Client(path)
        try:
            count = 253 if mode == "fds253" else 17
            if mode in ("unnegotiated", "malformed"):
                count = 1
            rights = [os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) for _ in range(count)]
            indices = list(range(count))
            if mode == "malformed": indices = [count]
            body = t.u32(4 * len(indices)) + b"".join(t.u32(index) for index in indices)
            payload = t.signal(10, destination=target.name, count=count, signature="ah", body=body)
            client.send_fds(payload, rights)
            if mode in ("overfds", "unnegotiated", "malformed"):
                client.sock.settimeout(0.6)
                try: assert client.sock.recv(1) == b""
                except ConnectionResetError: pass
                target.barrier(11)
            else:
                message = target.receive()
                assert message["type"] == 4 and len(message["fds"]) == count, message
                try:
                    for fd in message["fds"]:
                        assert os.read(fd, 1) == b""
                finally: t.close_fds(message["fds"])
                client.barrier(11)
                target.barrier(12)
        finally: target.close()
    elif mode in ("pending", "pending_zero", "complete"):
        rights = [os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) for _ in range(2)]
        payload = t.signal(10, destination="org.foundation.Missing", count=2, signature="ah", body=t.u32(8)+t.u32(0)+t.u32(1))
        client.send_fds(payload[:1], rights[:1])
        print("READY " + client.name, flush=True)
        if mode == "pending_zero":
            client.sock.settimeout(0.6)
            assert client.sock.recv(1) == b""
        else:
            assert sys.stdin.readline().strip() == "GROW"
            client.send_fds(payload[1:2], rights[1:])
            print("GROWN", flush=True)
            if mode == "complete":
                assert sys.stdin.readline().strip() == "FINISH"
                client.sock.sendall(payload[2:])
                client.barrier(11)
                print("CONSUMED", flush=True)
                assert sys.stdin.readline().strip() == "SECOND"
                client.send_fds(payload[:1], rights[:1])
                print("SECOND", flush=True)
                assert sys.stdin.readline().strip() == "FINISH2"
                client.send_fds(payload[1:], rights[1:])
                client.barrier(12)
            else:
                client.sock.settimeout(1)
                assert client.sock.recv(1) == b""
    elif mode == "output":
        print("READY " + client.name, flush=True)
        message = client.receive()
        assert message["type"] == 4 and message["body"] == t.string("x" * 1049600)
        client.barrier(13)
    else: raise AssertionError(mode)
    print("PASS " + mode, flush=True)
finally:
    client.close()
    t.close_fds(rights)
