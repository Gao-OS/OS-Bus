"""Installed-helper prerequisite; all effectful entrypoints require a VM marker."""
from collections import Counter
import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import runpy
import select
import shlex
import signal
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from protocol import SELECTED, ADDRESS, accounting, witness
from trust import (RequiredFacility, required, generated_wrapper, verify_wrapper,
                   verify_unit_files, verify_loaded, exec_argv, alias_state, verify_accounts)

BASE=Path('/run/osbus-p10')
FIXTURE=Path(__file__).resolve().parent
WORKLOAD=json.loads((FIXTURE/'workload.json').read_text())
PREFIX='org.foundation.Activation.'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def starttime(text):return int(text[text.rfind(')')+2:].split()[19])

def proc(pid):
    p=Path('/proc')/str(pid)
    values=dict(line.split(':',1) for line in (p/'status').read_text().splitlines() if ':' in line)
    return {'pid':pid,'starttime':starttime((p/'stat').read_text()),'uids':list(map(int,values['Uid'].split())),
            'gids':list(map(int,values['Gid'].split())),'groups':list(map(int,values['Groups'].split())),
            'exe':os.readlink(p/'exe'),'cgroup':(p/'cgroup').read_text(),
            'argv':(p/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')}


def process_gone(row):
    try:return starttime((Path('/proc')/str(row['pid'])/'stat').read_text())!=starttime(row['stat'])
    except FileNotFoundError:return True


def owned_group(unit,value=None):
    assert unit.startswith('osbus-p10-') and unit.endswith('.service') and '/' not in unit
    expected='/system.slice/'+unit
    assert value in (None,'',expected), 'unexpected controller unit cgroup'
    return Path('/sys/fs/cgroup'+expected)


def terminate_witness(row):
    handle=os.pidfd_open(row['pid'],0)
    try:
        assert starttime((Path('/proc')/str(row['pid'])/'stat').read_text())==starttime(row['stat']), 'witness PID changed before termination'
        signal.pidfd_send_signal(handle,signal.SIGTERM,None,0)
    finally:os.close(handle)


def group_path(text):return Path('/sys/fs/cgroup')/next(x[3:] for x in text.splitlines() if x.startswith('0::')).lstrip('/')


def group_empty(snapshot):
    return not snapshot['pids'] and (snapshot['events']=='removed' or 'populated 0' in snapshot['events'].splitlines())


def occurrences(rows,roots):
    result=[]
    for row in rows:
        matches=[(i,str(Path(row['path']).relative_to(root))) for i,root in enumerate(roots) if Path(row['path']).is_relative_to(root)]
        assert len(matches)==1, 'unknown original directory occurrence'
        result.append((*matches[0],row['sha256']))
    return Counter(result)


def fixture_files(package):
    result={}
    template=(FIXTURE/'service.template').read_text()
    for mode in ('Echo','Flood','Exit0','Live','BadExec'):
        command='/nonexistent/osbus-p10-executable' if mode=='BadExec' else str(package/'bin/p10-actor')+' '+mode
        result['share/dbus-1/system-services/'+PREFIX+mode+'.service']=template.replace('@NAME@',PREFIX+mode).replace('@EXEC@',command).encode()
    result['share/dbus-1/system.d/'+PREFIX[:-1]+'.conf']=(FIXTURE/'policy.conf').read_bytes()
    return result


def group_snapshot(path):
    if not path.exists():return {'path':str(path),'pids':[],'events':'removed'}
    try:return {'path':str(path),'pids':list(map(int,(path/'cgroup.procs').read_text().split())),'events':(path/'cgroup.events').read_text()}
    except FileNotFoundError:
        assert not path.exists();return {'path':str(path),'pids':[],'events':'removed'}


def package_inventory(release):
    rows={}
    for p in sorted(release.rglob('*')):
        mode=stat.S_IMODE(p.lstat().st_mode);assert not mode&0o6000
        row={'mode':mode}
        if p.is_symlink():row.update(type='symlink',target=os.readlink(p))
        elif p.is_dir():row.update(type='directory')
        elif p.is_file():row.update(type='file',size=p.stat().st_size,sha256=sha(p))
        else:raise AssertionError('special packaged file')
        rows[str(p.relative_to(release))]=row
    return rows


def verify_capture(root,expected):
    # Same immutable builtins.path mode rule used by P11 verify_inventory.
    normalized={}
    for name,row in expected.items():
        assert not row['mode']&0o6000, 'privileged captured package mode'
        mode=row['mode'] if row['type']=='symlink' else (0o555 if row['type']=='directory' or row['mode']&0o111 else 0o444)
        normalized[name]=dict(row,mode=mode)
    assert package_inventory(root)==normalized, 'imported package bytes/links/paths/modes mismatch'
    return True


class Runner:
    def __init__(self,frozen,package,recorded,manifest_hash,transport,capture):
        assert os.geteuid()==0 and Path('/etc/osbus-p10-guest').read_text()=='isolated-vm\n'
        assert WORKLOAD['selected']==SELECTED and WORKLOAD['max_live_units']==1
        self.frozen,self.package,self.recorded=frozen,package,recorded
        self.transport,self.capture=transport,capture
        self.release=frozen/'release';self.manifest=json.loads((frozen/'release.json').read_text())
        self.expected_manifest=manifest_hash;self.active={};self.row=None
        (BASE/'evidence').mkdir(mode=0o755)
        self.report={'selected':SELECTED,'rows':[],'commands':[],'launches':[],'cgroups':[],
                     'scope':'reference canonical installed-helper ABI only; NOT ACT acceptance',
                     'manifest_sha256':sha(frozen/'release.json'),'limits':WORKLOAD,'cleanup':[],'cleanup_errors':[]}
        self.report['fixture_hashes']={p.name:sha(p) for p in FIXTURE.iterdir() if p.is_file()}
        self.before_fixture=dict(self.report['fixture_hashes'])

    def save(self):
        self.report['counts']=accounting(self.report['rows'])
        (BASE/'evidence/report.json').write_text(json.dumps(self.report,indent=2,sort_keys=True)+'\n')

    def command(self,args,check=True,timeout=8,uid=None):
        if uid:args=['runuser','-u',uid,'--',*args]
        result=subprocess.run(args,text=True,capture_output=True,timeout=timeout,
                              env={'PATH':'/run/current-system/sw/bin'})
        self.report['commands'].append({'argv':args,'code':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        if check:assert result.returncode==0,(args,result.returncode,result.stdout,result.stderr)
        return result

    def glib(self,mode,name,uid=None):
        r=self.command([str(self.package/'bin/p10-actor'),'client',mode,name],check=False,uid=uid)
        return r.returncode,json.loads(r.stdout)

    def owner(self,name):
        code,row=self.glib('owner',name)
        if code:assert row=={'error':'org.freedesktop.DBus.Error.NameHasNoOwner'};return None
        return row

    def raw(self,mode,name,uid=None):
        r=self.command(['python3','-B',str(FIXTURE/'raw.py'),str(self.transport),mode,name],uid=uid)
        return json.loads(r.stdout)

    def poll(self,callback,seconds):
        deadline=time.monotonic()+seconds
        while True:
            value=callback()
            if value:return value
            assert time.monotonic()<deadline,'bounded observation deadline'
            select.select([],[],[],min(.02,max(0,deadline-time.monotonic())))

    def preflight(self,key):
        if key!='A0':return
        for path in (self.frozen/'release.json',self.release,self.package/'bin/p10-actor',
                     '/etc/osbus-p10-profile.json','/etc/dbus-1/system.conf',WORKLOAD['helper'],
                     '/proc/net/unix','/sys/fs/cgroup/cgroup.controllers'):
            required(path)
        for name in ('systemctl','systemd-run','runuser','findmnt','python3'):
            if not shutil.which(name,path='/run/current-system/sw/bin'):
                raise RequiredFacility('missing required command: '+name)
        if not callable(getattr(os,'pidfd_open',None)) or not callable(getattr(signal,'pidfd_send_signal',None)):
            raise RequiredFacility('PIDFD observation/termination unavailable')
        bridge=next(self.release.glob('lib/gao_bus-*/priv/gao_helper_bridge'),None)
        if bridge is None:raise RequiredFacility('missing packaged helper bridge')
        required(bridge)
        required(self.manifest['inspection_elixir']['path'])
        profile=json.loads(Path('/etc/osbus-p10-profile.json').read_text())
        required(generated_wrapper(profile['wrapperScript']));required(profile['helperSource'])
        for name in ('dbus.service','dbus.socket','polkit.service','systemd-logind.service'):
            required(Path('/etc/systemd/system')/name)

    def inventory(self):
        assert sha(self.frozen/'release.json')==self.expected_manifest
        assert verify_capture(self.release,self.manifest['inventory'])
        profile=json.loads(Path('/etc/osbus-p10-profile.json').read_text())
        meta=json.loads((self.recorded/'metadata.json').read_text())
        for key in ('owner','repo','rev','narHash'):assert profile['pinned'][key]==meta[key]
        for key in ('apparmorEnabled','networkManagerEnabled','stateVersion','kernelVersion'):assert profile[key]==meta[key]
        assert profile['systemdVersion']==meta['systemd']['version'] and profile['polkitVersion']==meta['polkit']['version']
        assert profile['implementation']==meta['dbus']['implementation'] and profile['apparmor']==meta['dbus']['apparmor']
        assert profile['wrapper']==meta['dbus']['launchHelper']
        self.account_inventory=verify_accounts(profile,meta,
            [{'name':x.pw_name,'uid':x.pw_uid,'gid':x.pw_gid} for x in pwd.getpwall()],
            [{'name':x.gr_name,'gid':x.gr_gid,'members':x.gr_mem} for x in grp.getgrall()])
        for name,unit in meta['units'].items():
            assert profile['units'][name]['overrideStrategy']==unit['overrideStrategy']
            # Only config-content triggers change when adding the fixture package.
            keep=lambda text:[line for line in text.splitlines() if not line.startswith(('X-Restart-Triggers=','X-Reload-Triggers='))]
            assert keep(profile['units'][name]['text'])==keep(unit['text']), 'installed unit settings changed'
        assert profile['dbus']==meta['dbus']['package'] and profile['helperSource']==meta['dbus']['launchHelper']['source']
        assert Path('/etc/dbus-1').resolve()==Path(profile['config'])
        xml=ET.fromstring(Path('/etc/dbus-1/system.conf').read_bytes())
        assert xml.findtext('user')=='messagebus' and xml.findtext('type')=='system'
        assert xml.findtext('servicehelper')==WORKLOAD['helper']
        assert [x.text for x in xml.findall('listen')]==[ADDRESS]
        directories=[x.text for x in xml.findall('servicedir')]
        assert directories==[x+'/share/dbus-1/system-services' for x in profile['directories']]
        originals=[x for x in profile['directories'] if x!=str(self.package)]
        assert len(originals)==3 and originals[0]==meta['dbus']['directories'][0] and originals[2]==meta['dbus']['directories'][2]
        assert originals[1].endswith('-system-path'), 'installed directory precedence changed'
        recorded=json.loads((self.recorded/'inventory.json').read_text())
        previous=next(x for x in recorded['files'] if x['path'].endswith('/system.conf'))
        elements=[]
        for element in xml.iter():
            text=(element.text or '').strip()
            if element.tag in ('servicedir','includedir') and Path(text).is_relative_to(self.package):continue
            text=text.replace(originals[1],meta['dbus']['directories'][1])
            elements.append({'tag':element.tag,'attributes':dict(element.attrib),'text':text})
        assert elements==previous['elements'], 'base system.conf changed beyond fixture directories'
        expected_fixture=fixture_files(self.package)
        actual_fixture={str(p.relative_to(self.package)):p.read_bytes() for p in (self.package/'share/dbus-1').rglob('*') if p.is_file()}
        assert actual_fixture==expected_fixture, 'fixture service/policy bytes differ'
        self.fixture_package_before=package_inventory(self.package)
        original_services=[];fixture_services=[]
        for directory in directories:
            for p in sorted(Path(directory).glob('*.service')):
                row={'path':str(p),'realpath':str(p.resolve()),'sha256':sha(p),'size':p.stat().st_size}
                (fixture_services if Path(directory).is_relative_to(self.package) else original_services).append(row)
        assert occurrences(original_services,originals)==occurrences(recorded['services'],meta['dbus']['directories'])
        assert len(original_services)==16 and len({Path(x['path']).name for x in original_services})==15 and len(fixture_services)==5
        assert {Path(x['path']).name for x in fixture_services}=={PREFIX+x+'.service' for x in ('Echo','Flood','Exit0','Live','BadExec')}
        policies=[]
        for directory in [x.text for x in xml.findall('includedir')]:
            for p in sorted(Path(directory).glob('*.conf')):policies.append({'path':str(p),'sha256':sha(p)})
        old=[x for x in recorded['files'] if x['kind']=='xml' and not x['path'].endswith('/system.conf')]
        assert occurrences([x for x in policies if not Path(x['path']).is_relative_to(self.package)],originals)==occurrences(old,meta['dbus']['directories'])
        assert len([x for x in policies if Path(x['path']).is_relative_to(self.package)])==1
        units=json.loads((self.recorded/'units-inventory.json').read_text())
        unit_evidence=[]
        for activation in units['activation']:
            if activation['target']:
                p=Path('/etc/systemd/system')/activation['target']
                alias_state(p,activation['present'],activation['symlink'])
                if activation['present']:
                    assert p.is_symlink() and os.readlink(p)==activation['symlink'] and not activation['masked']
                unit_evidence.append({'name':activation['name'],'target':activation['target'],'present':p.exists(),'symlink':os.readlink(p) if p.is_symlink() else None})
        helper=Path(WORKLOAD['helper']); info=helper.stat()
        assert info.st_uid==0 and info.st_gid==4 and stat.S_IMODE(info.st_mode)==0o4550
        mount=json.loads(self.command(['findmnt','-J','-T',str(helper),'--output','TARGET,OPTIONS']).stdout)
        assert 'nosuid' not in mount['filesystems'][0]['options'].split(',')
        wrapper_trust=verify_wrapper(helper,generated_wrapper(profile['wrapperScript']),
            profile['helperSource'],'0aea27579b4b000197f4a817e80562684d4e35d6f50336529ee08c68484504a9')
        self.interpreter=self.manifest['inspection_elixir']['path']
        assert self.interpreter.startswith('/nix/store/') and Path(self.interpreter).name=='elixir'
        assert sha(required(self.interpreter))==self.manifest['inspection_elixir']['sha256'],'inspection Elixir executable changed'
        self.bridge=next(self.release.glob('lib/gao_bus-*/priv/gao_helper_bridge'))
        binding=runpy.run_path(str(self.capture/'capture.py'))['helper_binding'](self.bridge)
        assert binding==self.manifest['helper_binding'] and binding['configured'] and binding['path']==str(helper)
        assert not binding['runtime_overrides'] and not binding['installed_entrypoint_qualified']
        self.unit_pid=int(self.command(['systemctl','show','dbus.service','--property=MainPID','--value']).stdout)
        self.bus_identity=proc(self.unit_pid);assert self.bus_identity['uids']==[4]*4 and self.bus_identity['gids']==[4]*4
        assert self.bus_identity['exe']==str(Path(profile['dbus'])/'bin/dbus-daemon')
        bus=self.owner('org.freedesktop.DBus');assert bus['pid']==self.unit_pid and bus['uid']==4
        self.socket=Path('/run/dbus/system_bus_socket').stat();assert stat.S_ISSOCK(self.socket.st_mode)
        assert (self.socket.st_uid,self.socket.st_gid,stat.S_IMODE(self.socket.st_mode))==(0,0,0o666)
        listeners=[line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:] if line.split()[-1]=='/run/dbus/system_bus_socket' and line.split()[3]=='00010000']
        assert len(listeners)==1 and listeners[0][4:6]==['0001','01']
        kernel_inode=int(listeners[0][6])
        assert 'socket:[%d]'%kernel_inode in [os.readlink(p) for p in (Path('/proc')/str(self.unit_pid)/'fd').iterdir()]
        loaded_units={}
        for name in ('dbus.service','dbus.socket','polkit.service','systemd-logind.service'):
            saved=next(x for x in units['units'] if x['name']==name)
            primary=next(x for x in saved['files'] if x['kind']=='unit')
            files=verify_unit_files('/etc/systemd/system',name,primary['sha256'],
                profile['units'].get(name,{}).get('text'))
            props=dict(line.split('=',1) for line in self.command(['systemctl','show',name,
                '--property=FragmentPath,DropInPaths,ExecStart,ExecReload,Type,NotifyAccess,User,Group,NoNewPrivileges,KillMode,Listen,BusName']).stdout.splitlines() if '=' in line)
            argv=shlex.split(saved['selected_effective_fields']['Service.ExecStart']) if name.endswith('.service') else None
            fields={key.split('.')[1]:value for key,value in saved['selected_effective_fields'].items()
                    if key in ('Service.Type','Service.User','Service.Group','Service.BusName')}
            if name=='dbus.service':fields.update(NotifyAccess='main',User='',Group='',NoNewPrivileges='no',KillMode='control-group')
            if name=='dbus.socket':fields['Listen']='/run/dbus/system_bus_socket (Stream)'
            assert verify_loaded(props,files,argv,fields)
            if name=='dbus.service':
                assert self.bus_identity['argv']==argv,'running canonical daemon argv/config selection changed'
                assert exec_argv(props['ExecReload'])==shlex.split(saved['selected_effective_fields']['Service.ExecReload'])
            loaded_units[name]={'files':files,'loaded':props}
        self.bus_id=self.raw('id','unused')['bus_id'];assert len(self.bus_id)==32
        svc=pwd.getpwnam('foundationSvc');assert (svc.pw_uid,svc.pw_gid)==(1102,1102)
        self.report['inventory']={'profile':profile,'helper':{'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode)),'realpath':str(helper.resolve()),'source_sha256':sha(Path(profile['helperSource']))},
            'mount':mount,'binding':binding,'wrapper_trust':wrapper_trust,'loaded_units':loaded_units,'accounts':self.account_inventory,'system_conf_sha256':sha(Path('/etc/dbus-1/system.conf')),
            'original_services':original_services,'fixture_services':fixture_services,'policies':policies,'units':unit_evidence,
            'bus':bus,'kernel_bus_identity':self.bus_identity,'bus_id':self.bus_id,'socket_inode':self.socket.st_ino,'kernel_listener_inode':kernel_inode,'socket_uid':self.socket.st_uid,'socket_gid':self.socket.st_gid,'actor_sha256':sha(self.package/'bin/p10-actor')}

    def launch(self,label,mode,user='messagebus',worker=False):
        assert not self.active,'unretired live launch charge'
        name=PREFIX+mode;unit='osbus-p10-'+label+'.service'
        caller=pwd.getpwnam(user);group=grp.getgrgid(caller.pw_gid).gr_name
        directory=BASE/label;directory.mkdir(mode=0o770);os.chown(directory,0,caller.pw_gid)
        file=directory/'result.json'
        if worker:
            elixir=self.interpreter
            args=[elixir,'--erl','+S 2:2']
            for p in sorted(self.release.glob('lib/*/ebin')):args+=['-pa',str(p)]
            args += [str(FIXTURE/'worker.exs'),name,str(file)]
        else:args=['python3','-B',str(FIXTURE/'bridge_probe.py'),str(self.bridge),name,str(file)]
        env_lures=['NOTIFY_SOCKET=/run/osbus-p10/lure','LISTEN_PID=1','LISTEN_FDS=5','LISTEN_FDNAMES=lure',
                   'DBUS_STARTER_ADDRESS=unix:path=/run/osbus-p10/lure','DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/osbus-p10/lure',
                   'TEST_LAUNCH_HELPER_CONFIG=/run/osbus-p10/lure','OSBUS_P10_LURE=present']
        command=['systemd-run','--unit='+unit,'--property=Type=exec','--property=User='+user,
            '--property=Group='+group,'--property=RemainAfterExit=yes',
            '--property=KillMode=control-group','--property=TimeoutStopSec=5s','--property=RuntimeMaxSec=20s','--property=NoNewPrivileges=no']
        for value in env_lures:command+=['--setenv='+value]
        self.active[unit]={'unit':unit,'result':file,'mode':mode,'worker':worker,'charged':1,'observed':None,'caller_uid':caller.pw_uid,'caller_gid':caller.pw_gid,'cgroup':owned_group(unit)}
        self.command(command+args)
        props=self.properties(unit)
        assert props['KillMode']=='control-group' and props['NoNewPrivileges']=='no'
        assert props['User']==user and props['Group']==group
        assert props['RemainAfterExit']=='yes'
        owned_group(unit,props['ControlGroup'])
        self.report['launches'].append({'unit':unit,'mode':mode,'backend':'worker' if worker else 'bridge','initial':props,'charge':1})
        return unit

    def properties(self,unit):
        fields='MainPID,ControlGroup,ActiveState,SubState,KillMode,NoNewPrivileges,User,Group,ExecMainCode,ExecMainStatus,RemainAfterExit'
        return dict(line.split('=',1) for line in self.command(['systemctl','show',unit,'--property='+fields]).stdout.splitlines() if '=' in line)

    def observe(self,unit):
        item=self.active[unit];p=item['result'];self.poll(lambda:p.exists(),WORKLOAD['launch_seconds'])
        row=json.loads(p.read_text());item['observed']=row
        if row['result']['kind']==3:assert row['result']=={'kind':3,'stage':0,'value':row['result']['value']}
        else:assert not item['worker'] and row['result']=={'kind':2,'stage':9,'value':13}
        if item['worker']:
            assert row['worker_down']=='normal' and row['caller_identity']['uid']==row['caller_identity']['real_uid']==4
            assert row['caller_identity']['gid']==row['caller_identity']['real_gid']==4
        else:
            expected=item['caller_uid']
            assert row['bridge_exit']==0 and row['caller_uids']==[expected]*3
            assert row['caller_gids']==[item['caller_gid']]*3
            from protocol import decode
            assert decode(bytes.fromhex(row['record_hex']))==row['result']
        self.report['launches'][-1]['observation']=row
        return row['result']

    def retire(self,unit,expected=None,stop=False):
        item=self.active[unit];group=item['cgroup']
        before=group_snapshot(group);self.report['cgroups'].append({'unit':unit,'phase':'before_retirement','charge':1,**before})
        if stop:self.command(['systemctl','stop',unit],timeout=8)
        if expected is not None:
            expected={'kind':3,'stage':0,'value':expected} if isinstance(expected,int) else expected
            assert self.observe(unit)==expected
        self.poll(lambda:group_empty(group_snapshot(group)),5)
        props=self.properties(unit)
        assert props['MainPID']=='0'
        if not stop:assert props['ExecMainStatus']=='0' and props['ExecMainCode']=='1',props
        if not stop:self.command(['systemctl','stop',unit],timeout=8)
        self.poll(lambda:group_empty(group_snapshot(group)),5)
        self.report['cgroups'].append({'unit':unit,'phase':'retired','charge':0,**group_snapshot(group)})
        self.report['cleanup'].append({'unit':unit,'empty':True,'properties':props,'observed':item['observed']})
        del self.active[unit]

    def service_witness(self,mode,unit,owns):
        p=BASE/'witness'/(mode+'.json')
        def read_witness():
            try:return json.loads(p.read_text())
            except (FileNotFoundError,json.JSONDecodeError):return None
        row=witness(self.poll(read_witness,3),1102,1102,[1102,1103]);kernel=proc(row['pid'])
        assert kernel['starttime']==starttime(row['stat']) and kernel['uids']==[1102]*4 and kernel['gids']==[1102]*4
        assert sorted(kernel['groups'])==[1102,1103] and kernel['exe']==str(self.package/'bin/p10-actor')
        assert group_path(kernel['cgroup'])==self.active[unit]['cgroup']
        assert row['pid'] in group_snapshot(self.active[unit]['cgroup'])['pids']
        if owns:
            owner=self.poll(lambda:self.owner(PREFIX+mode),3)
            assert owner['uid']==1102 and owner['pid']==row['pid']
        else:assert self.owner(PREFIX+mode) is None
        self.row.setdefault('witnesses',[]).append({'pre_glib':row,'kernel':kernel,'unit':unit})
        (BASE/'evidence'/(unit+'.witness.json')).write_text(p.read_text())
        return row

    def success(self,label,mode,worker=False):
        unit=self.launch(label,mode,worker=worker)
        row=self.service_witness(mode,unit,True)
        assert not self.active[unit]['result'].exists(),'service lifetime mistaken for helper completion'
        assert self.active[unit]['charged']==1
        for op in ('echo','fd'):
            code,result=self.glib(op,PREFIX+mode,'foundationA');assert code==0
            self.row.setdefault('glib_allowed',[]).append(result)
        code,denied=self.glib('echo',PREFIX+mode,'foundationB')
        assert code==1 and denied=={'error':'org.freedesktop.DBus.Error.AccessDenied'}
        self.row.setdefault('glib_denied',[]).append(denied)
        self.row.setdefault('raw_allowed',[]).append(self.raw('fd',PREFIX+mode,'foundationA'))
        self.row.setdefault('raw_denied',[]).append(self.raw('denied',PREFIX+mode,'foundationB'))
        code,_=self.glib('quit',PREFIX+mode,'foundationA');assert code==0
        self.retire(unit,expected=0)
        assert self.owner(PREFIX+mode) is None and process_gone(row)
        (BASE/'witness'/(mode+'.json')).unlink()

    def numeric(self,label,mode,expected,user='messagebus'):
        assert self.owner(PREFIX+mode) is None
        unit=self.launch(label,mode,user=user)
        self.retire(unit,expected=expected)
        assert self.owner(PREFIX+mode) is None
        assert not (BASE/'witness'/(mode+'.json')).exists(),'unexpected service exec'

    def case(self,key):
        if key=='A0':self.inventory()
        elif key=='A1':self.success('A1-direct','Echo');self.success('A1-worker','Echo',worker=True)
        elif key=='A2':self.success('A2-flood','Flood')
        elif key=='A3':
            self.numeric('A3-caller','Echo',7,user='root')
            unit=self.launch('A3-dac','Echo',user='foundationB')
            self.retire(unit,expected={'kind':2,'stage':9,'value':13})
            assert self.owner(PREFIX+'Echo') is None and not (BASE/'witness/Echo.json').exists()
        elif key=='A4':self.numeric('A4-missing','Missing',6)
        elif key=='A5':self.numeric('A5-exec','BadExec',9)
        elif key=='A6':
            unit=self.launch('A6-zero','Exit0');self.retire(unit,expected=0)
            row=witness(json.loads((BASE/'witness/Exit0.json').read_text()),1102,1102,[1102,1103])
            assert process_gone(row) and self.owner(PREFIX+'Exit0') is None
            self.row['zero_without_name']=row
            (BASE/'evidence/Exit0.witness.json').write_text((BASE/'witness/Exit0.json').read_text())
        elif key=='A7':
            unit=self.launch('A7-live','Live');row=self.service_witness('Live',unit,False)
            ready=BASE/'witness/Live.ready'
            self.poll(lambda:ready.exists() and ready.read_text()==str(row['pid'])+'\n',3)
            self.row['live_ready_pid']=row['pid']
            assert not self.active[unit]['result'].exists() and self.active[unit]['charged']==1
            self.row['live_charge']={'before':1,'pid':row['pid'],'cgroup':group_snapshot(self.active[unit]['cgroup'])}
            # Signal only our verified live cgroup member; graceful service exit lets
            # bridge waitpid and Worker-style observation prove the numeric result.
            terminate_witness(row);self.retire(unit,expected=0)
            assert process_gone(row) and self.owner(PREFIX+'Live') is None
            self.row['live_charge']['after']=0

    def cleanup(self):
        errors=[]
        for unit,item in list(self.active.items()):
            try:
                self.command(['systemctl','stop',unit],timeout=8)
                group=item.get('cgroup')
                if group:self.poll(lambda:group_empty(group_snapshot(group)),5)
                props=self.properties(unit);assert props['MainPID']=='0'
                self.report['cleanup'].append({'unit':unit,'emergency':True,'empty':bool(group and group_empty(group_snapshot(group))),'properties':props})
                del self.active[unit]
            except Exception as error:errors.append({'unit':unit,'error':repr(error)})
        self.report['cleanup_errors'].extend(errors)
        return errors

    def run(self):
        prerequisite=True
        try:
            for key in SELECTED:
                self.row={'id':key,'executed':False,'result':'blocked','start_monotonic':time.monotonic()}
                self.report['rows'].append(self.row)
                if not prerequisite:
                    self.row['error']='prerequisite or containment cleanup failed'
                    self.row['end_monotonic']=time.monotonic();self.save();continue
                try:
                    self.preflight(key)
                    self.row['executed']=True
                    self.case(key);self.row['result']='passed'
                except RequiredFacility as error:
                    self.row['executed']=False;self.row['result']='blocked';self.row['error']=str(error);prerequisite=False
                except Exception as error:
                    self.row['result']='failed';self.row['error']=repr(error)
                    if key=='A0':prerequisite=False
                    if self.cleanup():prerequisite=False
                finally:
                    # A failed witness is preserved before any later same-name row.
                    for path in (BASE/'witness').iterdir():
                        if path.is_file():
                            shutil.copyfile(path,BASE/'evidence'/(key+'.'+path.name))
                            if not self.active:path.unlink()
                    self.row['end_monotonic']=time.monotonic();self.save()
        finally:
            self.cleanup()
            self.report['final_validation_errors']=[]
            try:
                self.report['package_hashes_after']=verify_capture(self.release,self.manifest['inventory'])
                self.report['fixture_hashes_after']={p.name:sha(p) for p in FIXTURE.iterdir() if p.is_file()}==self.before_fixture
                self.report['fixture_package_hashes_after']=hasattr(self,'fixture_package_before') and package_inventory(self.package)==self.fixture_package_before
                if hasattr(self,'bus_identity'):
                    self.report['reference_after']=proc(self.unit_pid)
                    self.report['canonical_preserved']=self.report['reference_after']==self.bus_identity and all(getattr(Path('/run/dbus/system_bus_socket').stat(),field)==getattr(self.socket,field) for field in ('st_ino','st_uid','st_gid','st_mode')) and self.raw('id','unused')['bus_id']==self.bus_id
            except Exception as error:self.report['final_validation_errors'].append(repr(error))
            finally:
                # Preserve startup witnesses and observer outputs even after a row fails.
                archive=BASE/'evidence/raw';archive.mkdir()
                for directory in BASE.iterdir():
                    if not directory.is_dir() or directory.name=='evidence':continue
                    target=archive/directory.name;target.mkdir()
                    for path in directory.iterdir():
                        if path.is_file():shutil.copyfile(path,target/path.name)
                self.save()
        assert self.report['counts']['accepted'] and not self.report['cleanup_errors'] and not self.active
        assert not self.report['final_validation_errors']
        assert all(self.report.get(key,False) for key in ('package_hashes_after','fixture_hashes_after','fixture_package_hashes_after','canonical_preserved'))
        print(json.dumps({'counts':self.report['counts'],'scope':self.report['scope']}))

if __name__=='__main__':
    frozen,package,recorded,manifest,transport,capture=sys.argv[1:]
    Runner(Path(frozen),Path(package),Path(recorded),manifest,Path(transport),Path(capture)).run()
