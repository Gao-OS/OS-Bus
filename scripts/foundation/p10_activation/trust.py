"""Pure installed-profile trust checks. No subprocess, helper or bus operations."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import stat

class RequiredFacility(Exception):
    """A required facility is absent; the dependent row must not execute."""


def required(path):
    path=Path(path)
    if not path.exists():raise RequiredFacility('missing required facility: '+str(path))
    return path


def generated_wrapper(script):
    matches=re.findall(r'^\s*cp (/nix/store/[^\s]+/bin/security-wrapper) "\$wrapperDir/dbus-daemon-launch-helper"\s*$',script,re.M)
    assert len(matches)==1,'missing/ambiguous generated installed-helper wrapper'
    return Path(matches[0])


def verify_wrapper(path,expected,source,source_hash,base=Path('/run/wrappers'),owner=0):
    path,expected,source,base=map(Path,(path,expected,source,base))
    for p in (path,expected,source):required(p)
    for directory in (base.parent,base):
        info=directory.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022,'unsafe wrapper parent'
    link=base/'bin';info=link.lstat()
    assert stat.S_ISLNK(info.st_mode) and info.st_uid==owner,'untrusted wrapper symlink'
    target=link.resolve(strict=True)
    assert target.parent==base and target.name.startswith('wrappers.'),'wrapper chain escaped installed directory'
    info=target.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022,'unsafe wrapper target directory'
    info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022,'unsafe installed wrapper'
    assert not expected.is_symlink() and expected.is_file() and not source.is_symlink() and source.is_file()
    assert path.read_bytes()==expected.read_bytes(),'installed wrapper differs from pinned generated wrapper'
    actual_hash=hashlib.sha256(source.read_bytes()).hexdigest()
    assert actual_hash==source_hash,'source helper bytes changed'
    return {'matched':True,'realpath':str(path.resolve()),'expected':str(expected),
            'wrapper_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'source_sha256':actual_hash,
            'chain':[str(base.parent),str(base),str(link),str(target)]}


def verify_unit_files(base,name,primary_hash,dropin_text=None):
    base=Path(base);fragment=required(base/name)
    assert hashlib.sha256(fragment.read_bytes()).hexdigest()==primary_hash,'canonical unit source changed'
    directory=base/(name+'.d')
    drops=sorted(directory.glob('*.conf'))
    assert [p.name for p in drops]==([] if dropin_text is None else ['overrides.conf']),'unexpected/missing installed unit dropins'
    if dropin_text is not None:assert drops[0].read_text()==dropin_text,'actual installed dropin changed'
    return {'fragment':str(fragment),'dropins':[str(p) for p in drops]}


def exec_argv(value):
    paths=re.findall(r'\bpath=([^ ;]+)',value)
    argv=re.findall(r'\bargv\[\]=(.+?) ;',value)
    assert len(paths)==len(argv)==1,'missing/ambiguous loaded command'
    result=shlex.split(argv[0]);assert result and result[0]==paths[0]
    return result


def verify_loaded(properties,files,argv=None,fields=None):
    assert Path(properties['FragmentPath']).resolve()==Path(files['fragment']).resolve(),'loaded unit fragment changed'
    actual=[str(Path(p).resolve()) for p in shlex.split(properties['DropInPaths'])]
    expected=[str(Path(p).resolve()) for p in files['dropins']]
    assert actual==expected,'loaded unit dropin chain changed'
    if argv is not None:assert exec_argv(properties['ExecStart'])==argv,'loaded daemon command changed'
    for key,value in (fields or {}).items():assert properties[key]==value,'loaded unit property changed: '+key
    return True


def alias_state(path,present,symlink):
    path=Path(path);exists=os.path.lexists(path)
    assert exists==present,'installed activation alias presence changed'
    if present:assert path.is_symlink() and os.readlink(path)==symlink and path.exists(),'installed activation alias binding changed'
    return {'present':exists,'symlink':os.readlink(path) if exists and path.is_symlink() else None}


def verify_accounts(profile,baseline,passwd,groups):
    expected_user={'uid':1102,'group':'foundationSvc','isSystemUser':True}
    assert profile['users'].get('foundationSvc')==expected_user
    assert {k:v for k,v in profile['users'].items() if k!='foundationSvc'}==baseline['users'],'original account declarations changed'
    assert profile['groups'].get('foundationSvc')=={'gid':1102} and profile['groups'].get('foundationExtra')=={'gid':1103}
    assert {k:v for k,v in profile['groups'].items() if k not in ('foundationSvc','foundationExtra')}==baseline['groups'],'original group declarations changed'
    users={row['name']:row for row in passwd};group_map={row['name']:row for row in groups}
    assert len(users)==len(passwd) and len(group_map)==len(groups),'duplicate account/group names'
    assert set(users)==set(profile['users']) and set(group_map)==set(profile['groups']),'undeclared/missing accounts or groups'
    for name,declaration in profile['groups'].items():
        if declaration['gid'] is not None:assert group_map[name]['gid']==declaration['gid'],'group ID binding changed: '+name
    for name,declaration in profile['users'].items():
        actual=users[name]
        if declaration['uid'] is not None:assert actual['uid']==declaration['uid'],'user ID binding changed: '+name
        assert actual['gid']==group_map[declaration['group']]['gid'],'primary group binding changed: '+name
    assert 'foundationSvc' in group_map['foundationExtra']['members'],'fixture supplementary group missing'
    return {'matched':True,'users':passwd,'groups':groups,
            'dynamic_users':{name:users[name]['uid'] for name,row in profile['users'].items() if row['uid'] is None},
            'dynamic_groups':{name:group_map[name]['gid'] for name,row in profile['groups'].items() if row['gid'] is None}}
