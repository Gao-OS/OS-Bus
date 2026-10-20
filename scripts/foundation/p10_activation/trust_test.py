"""Offline trust-boundary mutations; no helper, bus or actor execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import guest
from protocol import SELECTED

class TrustTest(unittest.TestCase):
    def helper(self,name):
        value=getattr(guest,name,None)
        self.assertTrue(callable(value),'missing trust boundary '+name)
        return value

    def test_wrapper_bytes_source_and_safe_symlink_chain(self):
        check=self.helper('verify_wrapper')
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);base=parent/'wrappers';base.mkdir()
            actual=base/'wrappers.test';actual.mkdir();(base/'bin').symlink_to(actual)
            wrapper=actual/'dbus-daemon-launch-helper';wrapper.write_bytes(b'pinned wrapper');wrapper.chmod(0o4550)
            expected=parent/'generated-wrapper';expected.write_bytes(wrapper.read_bytes())
            source=parent/'helper';source.write_bytes(b'pinned underlying helper')
            digest=hashlib.sha256(source.read_bytes()).hexdigest()
            invoke=lambda:check(base/'bin/dbus-daemon-launch-helper',expected,source,digest,base,os.getuid())
            self.assertTrue(invoke()['matched'])
            wrapper.chmod(0o750);wrapper.write_bytes(b'replacement same mode');wrapper.chmod(0o4550)
            self.assertEqual(wrapper.stat().st_mode&0o7777,0o4550)
            with self.assertRaises(AssertionError):invoke()
            wrapper.chmod(0o750);wrapper.write_bytes(expected.read_bytes());wrapper.chmod(0o4550)
            source.write_bytes(b'changed underlying helper')
            with self.assertRaises(AssertionError):invoke()
            source.write_bytes(b'pinned underlying helper');actual.chmod(0o777)
            with self.assertRaises(AssertionError):invoke()
            actual.chmod(0o755);outside=parent/'outside';outside.mkdir();(outside/wrapper.name).write_bytes(expected.read_bytes())
            (base/'bin').unlink();(base/'bin').symlink_to(outside)
            with self.assertRaises(AssertionError):invoke()

    def test_generated_wrapper_is_single_exact_helper_copy(self):
        check=self.helper('generated_wrapper')
        path='/nix/store/pinned-wrapper/bin/security-wrapper'
        line='cp '+path+' "$wrapperDir/dbus-daemon-launch-helper"\n'
        self.assertEqual(check(line),Path(path))
        for text in ('',line+line,line.replace('dbus-daemon-launch-helper','other')):
            with self.assertRaises(AssertionError):check(text)

    def test_unit_primary_dropins_and_loaded_argv_are_exact(self):
        files=self.helper('verify_unit_files');loaded=self.helper('verify_loaded')
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);primary=base/'dbus.service';primary.write_text('pinned primary\n')
            drop=base/'dbus.service.d';drop.mkdir();override=drop/'overrides.conf';override.write_text('exact new trigger\n')
            digest=hashlib.sha256(primary.read_bytes()).hexdigest()
            rows=files(base,'dbus.service',digest,override.read_text())
            argv=['/nix/store/pinned/bin/dbus-daemon','--system','--address=systemd:','--nofork']
            props={'FragmentPath':str(primary),'DropInPaths':str(override),'ExecStart':'{ path='+argv[0]+' ; argv[]='+' '.join(argv)+' ; ignore_errors=no ; }','Type':'notify'}
            self.assertTrue(loaded(props,rows,argv,{'Type':'notify'}))
            changed=dict(props,ExecStart=props['ExecStart'].replace('--system','--config-file=/tmp/lure'))
            with self.assertRaises(AssertionError):loaded(changed,rows,argv,{'Type':'notify'})
            with self.assertRaises(AssertionError):loaded(dict(props,DropInPaths=''),rows,argv,{'Type':'notify'})
            override.write_text('changed runtime dropin\n')
            with self.assertRaises(AssertionError):files(base,'dbus.service',digest,'exact new trigger\n')
            override.write_text('exact new trigger\n');extra=drop/'extra.conf';extra.write_text('unexpected override\n')
            with self.assertRaises(AssertionError):files(base,'dbus.service',digest,override.read_text())
            extra.unlink();primary.write_text('changed primary\n')
            with self.assertRaises(AssertionError):files(base,'dbus.service',digest,override.read_text())

    def test_absent_alias_rejects_dangling_symlink(self):
        check=self.helper('alias_state')
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'absent.service'
            self.assertFalse(check(path,False,None)['present'])
            path.symlink_to('missing.service')
            with self.assertRaises(AssertionError):check(path,False,None)

    def test_account_maps_allow_only_declared_additions_and_bind_real_records(self):
        check=self.helper('verify_accounts')
        baseline={'users':{'root':{'uid':0,'group':'root','isSystemUser':False}},'groups':{'root':{'gid':0}}}
        profile=copy.deepcopy(baseline)
        profile['users']['foundationSvc']={'uid':1102,'group':'foundationSvc','isSystemUser':True}
        profile['groups'].update(foundationSvc={'gid':1102},foundationExtra={'gid':1103})
        passwd=[{'name':'root','uid':0,'gid':0},{'name':'foundationSvc','uid':1102,'gid':1102}]
        groups=[{'name':'root','gid':0,'members':[]},{'name':'foundationSvc','gid':1102,'members':[]},{'name':'foundationExtra','gid':1103,'members':['foundationSvc']}]
        self.assertTrue(check(profile,baseline,passwd,groups)['matched'])
        for target in ('uid','group'):
            changed=copy.deepcopy(profile);changed['users']['root'][target]=1 if target=='uid' else 'foundationSvc'
            with self.assertRaises(AssertionError):check(changed,baseline,passwd,groups)
        with self.assertRaises(AssertionError):check(profile,baseline,passwd+[{'name':'extra','uid':9,'gid':0}],groups)
        changed=copy.deepcopy(passwd);changed[0]['uid']=1
        with self.assertRaises(AssertionError):check(profile,baseline,changed,groups)
        changed=copy.deepcopy(groups);changed[-1]['members']=[]
        with self.assertRaises(AssertionError):check(profile,baseline,passwd,changed)

    def test_required_missing_file_is_blocked_before_execution(self):
        required=self.helper('required');blocked=self.helper('RequiredFacility')
        with tempfile.TemporaryDirectory() as temporary:
            box=Path(temporary);(box/'evidence').mkdir();(box/'witness').mkdir()
            missing=box/'missing-helper'
            with self.assertRaises(blocked):required(missing)
            runner=guest.Runner.__new__(guest.Runner);runner.active={};runner.release=box;runner.package=box
            runner.manifest={'inventory':{}};runner.fixture_package_before={}
            runner.before_fixture={p.name:guest.sha(p) for p in guest.FIXTURE.iterdir() if p.is_file()}
            runner.report={'selected':SELECTED,'rows':[],'cleanup':[],'cleanup_errors':[]}
            runner.preflight=lambda key:required(missing)
            runner.case=lambda key:self.fail('missing required facility must never execute a row')
            with patch('guest.BASE',box),patch('guest.verify_capture',return_value=True),patch('guest.package_inventory',return_value={}):
                with self.assertRaises(AssertionError):runner.run()
            self.assertEqual(runner.report['counts']['executed'],0)
            self.assertEqual(runner.report['counts']['blocked'],8)
            self.assertEqual(runner.report['counts']['failed'],0)
            self.assertFalse(runner.report['counts']['accepted'])

if __name__=='__main__':unittest.main()
