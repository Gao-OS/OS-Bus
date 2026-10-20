"""Pure mutation tests: no VM, bus, privilege transition or child launch."""
import copy
import struct
import unittest
from protocol import decode, witness, accounting


class ProtocolTest(unittest.TestCase):
    def sample(self):
        return {'pid': 123, 'uids': [1102]*3, 'gids': [1102]*3,
                'groups': [1102,1103], 'stat': '123 (actor) S '+'0 '*18+'42 0',
                'environment': ['DBUS_STARTER_ADDRESS=unix:path=/run/dbus/system_bus_socket',
                                'DBUS_STARTER_BUS_TYPE=system'],
                'fds': [{'fd': i, 'target': '/dev/null'} for i in range(3)]}

    def test_real_numeric_helper_errors(self):
        for value in (0,6,7,9):
            self.assertEqual(decode(struct.pack('>4sBBHII', b'GHB\1',3,0,0,value,0)), {'kind':3,'stage':0,'value':value})

    def test_invalid_records_are_never_child_exit(self):
        good = struct.pack('>4sBBHII',b'GHB\1',3,0,0,7,0)
        for raw in (good[:-1],good+b'x',b'BAD\1'+good[4:],good[:6]+b'\1\0'+good[8:],
                    struct.pack('>4sBBHII',b'GHB\1',3,1,0,7,0),
                    struct.pack('>4sBBHII',b'GHB\1',3,0,0,256,0)):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):decode(raw)

    def test_pre_glib_witness(self):
        self.assertEqual(witness(self.sample(),1102,1102,[1102,1103])['pid'],123)

    def test_identity_environment_and_fd_leaks_are_rejected(self):
        for mutate in (lambda r:r['uids'].__setitem__(0,0),lambda r:r['gids'].__setitem__(1,4),
                       lambda r:r.update(groups=[1102]),lambda r:r['environment'].append('NOTIFY_SOCKET=/run/lure'),
                       lambda r:r['environment'].__setitem__(0,'DBUS_STARTER_ADDRESS=unix:path=/run/private'),
                       lambda r:r['fds'].append({'fd':4,'target':'socket:[42]'}),
                       lambda r:r['fds'][1].update(target='pipe:[1]')):
            r=self.sample();mutate(r)
            with self.subTest(row=r), self.assertRaises(AssertionError):witness(r,1102,1102,[1102,1103])

    def test_strict_complete_disposition(self):
        rows=[{'id':'A%d'%i,'executed':True,'result':'passed'} for i in range(8)]
        self.assertEqual(accounting(rows)['passed'],8)
        for broken in (rows[:-1],rows+[rows[0]],[],[dict(x,result='blocked',executed=False) for x in rows]):
            self.assertFalse(accounting(broken)['accepted'])
        bad=copy.deepcopy(rows);bad[3]['result']='failed'
        self.assertEqual(accounting(bad)['failed'],1)
        self.assertFalse(accounting(bad)['accepted'])

if __name__=='__main__':unittest.main()
