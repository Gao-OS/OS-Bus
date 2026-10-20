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


import array
import pwd
import socket


def identity():
    account = pwd.getpwuid(os.getuid())
    return {'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getegid(),
            'groups': sorted(os.getgroups() + ([] if os.getegid() in os.getgroups() else [os.getegid()])),
            'account_groups': sorted(os.getgrouplist(account.pw_name, account.pw_gid))}


def check(client, name, metadata):
    assert result(query(client, 'GetConnectionUnixProcessID', 's', actor.string(name)), 'u') == metadata['pid']
    assert result(query(client, 'GetConnectionUnixUser', 's', actor.string(name)), 'u') == metadata['uid']
    observed = result(query(client, 'GetConnectionCredentials', 's', actor.string(name)), 'a{sv}')
    assert observed['UnixUserID'] == ('u', metadata['uid']), observed
    assert observed['ProcessID'] == ('u', metadata['pid']), observed
    assert observed['UnixGroupIDs'] == ('au', metadata['groups']), (observed, metadata)
    return {key: observed[key] for key in ['UnixUserID', 'ProcessID', 'UnixGroupIDs']}


def own(client):
    body = actor.string('org.foundation.ProcessOnly')
    return result(query(client, 'RequestName', 'su', body + actor.padding(len(body), 4) + actor.u32(0)), 'u')


def denial(client, path):
    forbidden = 'org.foundation.Forbidden'
    body = actor.string(forbidden)
    error(query(client, 'RequestName', 'su', body + actor.padding(len(body), 4) + actor.u32(0)), 'AccessDenied')
    for method in ['GetNameOwner', 'GetConnectionCredentials']:
        error(query(client, method, 's', actor.string(forbidden)), 'NameHasNoOwner')
    target = actor.Client(path, negotiate=False)
    try:
        query.serial += 1
        client.sock.sendall(actor.frame(1, query.serial, [(1, 'o', '/probe'),
            (2, 's', 'org.foundation.GroupDenied'), (3, 's', 'Probe'), (6, 's', target.name)]))
        error(client.reply(query.serial), 'AccessDenied')
        query.serial += 1
        target.sock.sendall(actor.call('GetId', query.serial))
        while True:
            message = target.receive()
            assert message['type'] != 1, 'denied call was delivered'
            if message['fields'].get(5) == query.serial:
                result(message, 's'); break
            assert message['type'] == 4 and message['fields'].get(2) == BUS, message
    finally:
        target.close()
    result(query(client, 'GetId'), 's')


def transferred(path, before_auth):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(3)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if before_auth:
                connected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connected.connect(path)
                name = None
            else:
                client = actor.Client(path, negotiate=False)
                connected, name = client.sock, client.name
            metadata = identity()
            metadata['name'] = name
            child.sendmsg([json.dumps(metadata).encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [connected.fileno()]))])
            connected.close()
            child.close()
            os._exit(0)
        except BaseException:
            os._exit(91)
    child.close()
    try:
        payload, controls, flags, _ = parent.recvmsg(4096, socket.CMSG_SPACE(4))
        assert not flags & socket.MSG_CTRUNC
        assert len(controls) == 1 and controls[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        rights = array.array('i'); rights.frombytes(controls[0][2]); assert len(rights) == 1
        metadata = json.loads(payload)
        reaped, status = os.waitpid(pid, 0)
        assert reaped == pid and os.waitstatus_to_exitcode(status) == 0
        assert metadata['pid'] == pid and pid != os.getpid()
        survivor = actor.Client.__new__(actor.Client)
        survivor.sock = socket.socket(fileno=rights[0]); survivor.sock.settimeout(3)
        if before_auth:
            survivor.sock.sendall(b'\0AUTH EXTERNAL ' + str(metadata['uid']).encode().hex().encode() + b'\r\n')
            assert survivor.line().startswith(b'OK ')
            survivor.sock.sendall(b'BEGIN\r\n' + actor.call('Hello', 1))
            survivor.name = result(survivor.reply(1), 's')
            survivor.barrier(2)
        else:
            survivor.name = metadata['name']
        return survivor, metadata, {'pid': pid, 'reaped': True, 'exit_code': 0}
    finally:
        parent.close()


def exercise(path, mode):
    observer = actor.Client(path, negotiate=False)
    surviving = None
    try:
        own_metadata = identity()
        if os.environ.get('OSBUS_API04_REQUIRE_DIFFERENT_GROUPS') == '1':
            assert own_metadata['account_groups'] == [0] and 65534 in own_metadata['groups'], own_metadata
        if mode == 'groups':
            observed = check(observer, observer.name, own_metadata)
            denial(observer, path)
            assert own(observer) == 1
            result(query(observer, 'ReleaseName', 's', actor.string('org.foundation.ProcessOnly')), 'u')
            reaped = None
        else:
            surviving, metadata, reaped = transferred(path, mode == 'exited-before-auth')
            observed = check(observer, surviving.name, metadata)
            assert own(surviving) == 1
            check(observer, 'org.foundation.ProcessOnly', metadata)
            result(query(surviving, 'ReleaseName', 's', actor.string('org.foundation.ProcessOnly')), 'u')
            # The surviving process can send; its PID must never replace connector PID.
            result(query(surviving, 'GetId'), 's')
            name = surviving.name
            surviving.close(); surviving = None
            deadline = time.monotonic() + 3
            while True:
                reply = query(observer, 'GetConnectionCredentials', 's', actor.string(name))
                if reply['type'] == 3:
                    error(reply, 'NameHasNoOwner'); break
                observed_after_close = result(reply, "a{sv}")
                assert observed_after_close["ProcessID"] == ("u", metadata["pid"])
                assert observed_after_close["UnixGroupIDs"] == ("au", metadata["groups"])
                assert time.monotonic() < deadline
        result(query(observer, 'GetId'), 's')
        print(json.dumps({'mode': mode, 'result': 'PASS', 'credentials': observed,
                          'actor': own_metadata, 'original_peer': reaped}), flush=True)
    finally:
        observer.close()
        if surviving is not None:
            surviving.close()


if __name__ == '__main__':
    exercise(sys.argv[2], sys.argv[1])
