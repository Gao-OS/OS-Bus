"""Independent private-socket API oracle; no OS-Bus codec or default bus."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "transport_actor", Path(__file__).resolve().parents[1] / "fixtures/transport_actor.py")
actor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(actor)
BUS = "org.freedesktop.DBus"
PEER = BUS + ".Peer"


def value(signature, body, offset=0):
    if signature == "u":
        offset += -offset % 4
        return struct.unpack_from("<I", body, offset)[0], offset + 4
    if signature == "s":
        offset += -offset % 4
        length = struct.unpack_from("<I", body, offset)[0]
        assert body[offset + 4 + length] == 0
        return body[offset + 4:offset + 4 + length].decode(), offset + 5 + length
    if signature == "v":
        length = body[offset]
        sig = body[offset + 1:offset + 1 + length].decode()
        assert body[offset + 1 + length] == 0
        decoded, end = value(sig, body, offset + 2 + length)
        return (sig, decoded), end
    if signature in ("as", "au", "a{sv}"):
        offset += -offset % 4
        length = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        offset += -offset % (8 if signature == "a{sv}" else 4)
        end = offset + length
        result = {} if signature == "a{sv}" else []
        while offset < end:
            if signature == "a{sv}":
                offset += -offset % 8
                key, offset = value("s", body, offset)
                item, offset = value("v", body, offset)
                assert key not in result
                result[key] = item
            else:
                item, offset = value("u" if signature == "au" else "s", body, offset)
                result.append(item)
        assert offset == end
        return result, offset
    raise AssertionError(signature)


def query(client, member, signature="", body=b"", interface=BUS, path="/org/freedesktop/DBus"):
    query.serial += 1
    client.sock.sendall(actor.frame(1, query.serial, [
        (1, "o", path), (2, "s", interface), (3, "s", member),
        (6, "s", BUS), (8, "g", signature)], body))
    reply = client.reply(query.serial)
    assert not reply["fds"]
    return reply


query.serial = 10


def result(reply, signature):
    assert reply["type"] == 2, reply
    assert reply["fields"].get(8, "") == signature, reply
    if not signature:
        assert reply["body"] == b""
        return None
    decoded, end = value(signature, reply["body"])
    assert end == len(reply["body"])
    return decoded


def error(reply, name):
    assert reply["type"] == 3 and reply["fields"].get(4) == BUS + ".Error." + name, reply


def strings(*items):
    body = b""
    for item in items:
        body += actor.padding(len(body), 4) + actor.string(item)
    return body


def request(client, name):
    body = actor.string(name)
    return result(query(client, "RequestName", "su",
                        body + actor.padding(len(body), 4) + actor.u32(0)), "u")


def process_groups():
    groups = os.getgroups()
    return sorted(groups + ([] if os.getegid() in groups else [os.getegid()]))


def credentials(client, name, pid, uid, groups=None):
    assert result(query(client, "GetConnectionUnixUser", "s", actor.string(name)), "u") == uid
    assert result(query(client, "GetConnectionUnixProcessID", "s", actor.string(name)), "u") == pid
    expected = {"UnixUserID": ("u", uid), "ProcessID": ("u", pid)}
    if groups is not None:
        expected["UnixGroupIDs"] = ("au", groups)
    assert result(query(client, "GetConnectionCredentials", "s", actor.string(name)), "a{sv}") == expected


def owner(path, name):
    client = actor.Client(path, negotiate=False)
    assert request(client, name) == 1
    print(json.dumps({"name": client.name, "pid": os.getpid(), "uid": os.getuid(), "groups": process_groups()}), flush=True)
    assert sys.stdin.readline().strip() == "exit"
    client.close()


def identities(client, path, daemon_pid):
    credentials(client, client.name, os.getpid(), os.getuid(), process_groups())
    daemon_uid = int(next(line.split()[1] for line in Path(f"/proc/{daemon_pid}/status").read_text().splitlines()
                          if line.startswith("Uid:")))
    credentials(client, BUS, daemon_pid, daemon_uid)
    alias = "org.foundation.IdentityOwner"
    child = subprocess.Popen([sys.executable, __file__, "owner", path, alias],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        metadata = json.loads(child.stdout.readline())
        assert metadata["pid"] == child.pid and metadata["uid"] == os.getuid()
        assert request(client, alias) == 2
        credentials(client, alias, child.pid, os.getuid(), metadata["groups"])
        credentials(client, metadata["name"], child.pid, os.getuid(), metadata["groups"])
        child.communicate("exit\n", timeout=5)
        assert child.returncode == 0
        deadline = time.monotonic() + 3
        while True:
            reply = query(client, "GetConnectionUnixProcessID", "s", actor.string(metadata["name"]))
            if reply["type"] == 3:
                error(reply, "NameHasNoOwner")
                break
            assert result(reply, "u") == metadata["pid"]
            assert time.monotonic() < deadline
        # Primary-owner promotion must select the observer, not the old PID.
        credentials(client, alias, os.getpid(), os.getuid(), process_groups())
        for method in ["GetConnectionUnixUser", "GetConnectionUnixProcessID", "GetConnectionCredentials"]:
            error(query(client, method, "s", actor.string(metadata["name"])), "NameHasNoOwner")
            error(query(client, method, "s", actor.string("org.foundation.Unknown")), "NameHasNoOwner")
        result(query(client, "ReleaseName", "s", actor.string(alias)), "u")
        error(query(client, "GetConnectionCredentials", "s", actor.string(alias)), "NameHasNoOwner")
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)


def peer_properties(client):
    bus_id = result(query(client, "GetId"), "s")
    machine_id = Path("/etc/machine-id").read_text().strip()
    for path in ["/", "/org/freedesktop/DBus", "/arbitrary/object"]:
        result(query(client, "Ping", interface=PEER, path=path), "")
        assert result(query(client, "GetMachineId", interface=PEER, path=path), "s") == machine_id
    assert machine_id != bus_id
    xml = result(query(client, "Introspect", interface=BUS + ".Introspectable"), "s")
    node = ET.fromstring(xml)
    bus = node.find("interface[@name='org.freedesktop.DBus']")
    for name in ["GetConnectionUnixUser", "GetConnectionUnixProcessID", "GetConnectionCredentials"]:
        assert bus.find(f"method[@name='{name}']") is not None
    for name in ["Features", "Interfaces"]:
        prop = bus.find(f"property[@name='{name}']")
        assert prop is not None and prop.attrib["type"] == "as" and prop.attrib["access"] == "read"
    assert node.find("interface[@name='org.freedesktop.DBus.Monitoring']") is None
    properties = BUS + ".Properties"
    assert result(query(client, "GetAll", "s", actor.string(BUS), properties), "a{sv}") == {
        "Features": ("as", []), "Interfaces": ("as", [])}
    for name in ["Features", "Interfaces"]:
        assert result(query(client, "Get", "ss", strings(BUS, name), properties), "v") == ("as", [])
    error(query(client, "Get", "ss", strings("org.foundation.Unknown", "Features"), properties), "UnknownInterface")
    error(query(client, "Get", "ss", strings(PEER, "Features"), properties), "UnknownProperty")
    assert result(query(client, "GetAll", "s", actor.string(PEER), properties), "a{sv}") == {}
    error(query(client, "NoSuchMethod"), "UnknownMethod")


def invalid_calls(client):
    for method in ["GetConnectionUnixUser", "GetConnectionUnixProcessID", "GetConnectionCredentials"]:
        error(query(client, method), "InvalidArgs")
        error(query(client, method, "u", actor.u32(1)), "InvalidArgs")
        error(query(client, method, "s", actor.string("invalid")), "InvalidArgs")
        signature = "a{sv}" if method == "GetConnectionCredentials" else "u"
        expected = result(query(client, method, "s", actor.string(client.name)), signature)
        assert result(query(client, method, "s", actor.string(client.name), path="/wrong"), signature) == expected
    for method in ["Ping", "GetMachineId"]:
        error(query(client, method, "s", actor.string("unexpected"), PEER), "InvalidArgs")


if __name__ == "__main__":
    mode, path = sys.argv[1:3]
    if mode == "owner":
        owner(path, sys.argv[3])
    else:
        client = actor.Client(path, negotiate=False)
        try:
            if mode == "identity":
                identities(client, path, int(sys.argv[3]))
            elif mode == "peer":
                peer_properties(client)
            elif mode == "invalid":
                invalid_calls(client)
            else:
                raise AssertionError(mode)
            result(query(client, "GetId"), "s")
            client.barrier(10000)
            print(json.dumps({"result": "PASS", "mode": mode, "pid": os.getpid(), "uid": os.getuid(),
                              "checked_queries": query.serial - 10}))
        finally:
            client.close()
