"""Ordinary independent SEC01 raw client held for H04 fixture ownership checks."""
import json
import os
from pathlib import Path
import sys

original, endpoint = sys.argv[1:]
assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
assert os.getuid() == os.geteuid() == 1101
assert os.getgid() == os.getegid() == 1101
assert endpoint in ('/run/osbus-security/sec01-complete/reference/bus',
                    '/run/osbus-security/sec01-complete/gao_bus/bus')
sys.path.insert(0, original)
from actor import Client  # Exact pinned SEC01 independent packet/parser helper.

client = Client(endpoint)
try:
    hello = client.register('pipeline')
    bus_id = client.command(dict(op='call', member='GetId'))
    assert hello['type'] == bus_id['type'] == 2
    assert hello['reply_serial'] == 1 and bus_id['reply_serial'] == 2
    assert hello['sender'] == bus_id['sender'] == 'org.freedesktop.DBus'
    assert len(hello['body']) == len(bus_id['body']) == 1
    assert hello['body'][0].startswith(':')
    assert len(bus_id['body'][0]) == 32
    int(bus_id['body'][0], 16)
    fd = client.socket.fileno()
    print(json.dumps(dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
                          endpoint=endpoint, fd=fd, inode=os.fstat(fd).st_ino,
                          hello=hello, get_id=bus_id)), flush=True)
    client.socket.settimeout(None)
    while client.socket.recv(4096):
        pass
finally:
    if client.socket is not None:
        client.socket.close()
