"""Independent SCM_RIGHTS actor on the fixed canonical disposable guest bus."""
import json
import os
from pathlib import Path
import sys
from protocol import fd_reply

sys.path.insert(0,sys.argv[1])
from transport import Client, call, close_fds, frame, read_string, string, u32

assert Path('/etc/osbus-p10-guest').read_text()=='isolated-vm\n'
mode,name=sys.argv[2:]
client=Client('/run/dbus/system_bus_socket')
try:
    if mode=='id':
        client.sock.sendall(call('GetId',10,flags=2))
        reply=client.reply(10);assert reply['type']==2 and not reply['fds']
        print(json.dumps({'bus_id':read_string(reply['body']),'unique':client.name,'uid':os.getuid()}))
    else:
        fields=[(1,'o','/org/foundation/Activation'),(2,'s','org.foundation.Activation'),
                (3,'s','ReadAndReturnFD' if mode=='fd' else 'Echo'),(6,'s',name),
                (8,'g','h' if mode=='fd' else 's')]
        if mode=='fd':
            resource=b'installed-helper-raw-FD';fd=os.memfd_create('p10-raw-readback',os.MFD_CLOEXEC)
            try:
                os.write(fd,resource);identity=os.fstat(fd);fields.append((9,'u',1))
                client.send_fds(frame(1,10,fields,u32(0),flags=2),[fd])
            finally:os.close(fd)
        else:client.sock.sendall(frame(1,10,fields,string('installed-helper'),flags=2))
        reply=client.reply(10)
        try:
            if mode=='denied':assert reply['type']==3 and reply['fields'][4]=='org.freedesktop.DBus.Error.AccessDenied' and not reply['fds']
            else:
                fd_reply(reply,identity,resource)
            print(json.dumps({'ok':True,'mode':mode,'uid':os.getuid(),'flags':2,'fds':len(reply['fds']),'sender':reply['fields'].get(7)}))
        finally:close_fds(reply['fds'])
finally:client.close()
