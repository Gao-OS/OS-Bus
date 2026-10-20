"""Exact Stage A fact validation; startup observations are not ACT acceptance."""
import struct
import os

SELECTED = ['A%d'%i for i in range(8)]
ADDRESS = 'unix:path=/run/dbus/system_bus_socket'


def decode(raw):
    assert len(raw)==16, 'incomplete/extra GHB bytes'
    magic,kind,stage,reserved,value,tail=struct.unpack('>4sBBHII',raw)
    assert magic==b'GHB\1' and reserved==tail==0
    assert (kind==3 and stage==0 and value<=255) or (kind==4 and stage==0 and 1<=value<=64) or (kind==2 and stage in (4,5,8,9) and value>0) or (kind==1 and 1<=stage<=8 and value>0), 'unproved bridge result'
    return {'kind':kind,'stage':stage,'value':value}


def witness(row,uid,gid,groups):
    assert row['pid'] > 0 and row['uids']==[uid]*3 and row['gids']==[gid]*3, 'service identity mismatch'
    assert sorted(row['groups'])==sorted(groups), 'supplementary group mismatch'
    assert sorted(row['environment'])==sorted(['DBUS_STARTER_ADDRESS='+ADDRESS,'DBUS_STARTER_BUS_TYPE=system']), 'helper environment leak/override'
    assert row['fds']==[{'fd':i,'target':'/dev/null'} for i in range(3)], 'inherited FD or standard-I/O leak'
    return row


def accounting(rows):
    results=('passed','failed','blocked')
    return {'selected':8,'executed':sum(r['executed'] is True for r in rows),
            **{k:sum(r['result']==k for r in rows) for k in results},'skipped':0,
            'accepted':[r['id'] for r in rows]==SELECTED and all(r['executed'] is True and r['result']=='passed' for r in rows)}


def fd_reply(reply,identity,resource):
    assert reply['type']==2 and reply['fields'][8]=='hs' and len(reply['fds'])==1
    assert reply['body']==struct.pack('<II',0,len(resource))+resource+b'\0', 'FD reply payload/index mismatch'
    got=os.fstat(reply['fds'][0])
    assert (got.st_dev,got.st_ino)==(identity.st_dev,identity.st_ino), 'FD object changed'
    assert os.pread(reply['fds'][0],len(resource)+1,0)==resource, 'FD contents changed'
