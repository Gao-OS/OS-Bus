"""Up to eight fresh invocations under one absolute disposable-guest deadline."""
import argparse,copy,hashlib,importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=Path('/run/osbus-fd02-all-boundaries');GUEST_SECONDS=120
INPUT_NAMES=('candidate','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope','reuse-fixtures','freeze')
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def check_deadline(deadline,phase):
 assert time.monotonic()<deadline,'absolute guest batch deadline: '+phase
def persist(report,output,started,deadline):
 try:
  report['elapsed_seconds']=time.monotonic()-started
  if report['result']=='passed':check_deadline(deadline,'before final serialization')
  raw=json.dumps(report,indent=2,sort_keys=True)+'\n'
  if report['result']=='passed':check_deadline(deadline,'after final serialization')
  output.write_text(raw)
  if report['result']=='passed':
   check_deadline(deadline,'after final persistence')
   persisted=json.loads(output.read_text());assert persisted['result']=='passed' and 0<persisted['elapsed_seconds']<=GUEST_SECONDS
   check_deadline(deadline,'after persisted report check')
 except Exception as error:
  if report['result']!='passed':raise
  report.update(result='failed',error=repr(error),elapsed_seconds=time.monotonic()-started)
  output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
def main(argv=None):
 started=time.monotonic();deadline=started+GUEST_SECONDS
 parser=argparse.ArgumentParser(description=__doc__)
 for name in INPUT_NAMES:parser.add_argument('--'+name,required=True,type=Path)
 parser.add_argument('--first',required=True,type=int);parser.add_argument('--count',required=True,type=int);args=parser.parse_args(argv)
 assert type(args.first) is int and args.first>=1 and (args.first-1)%8==0 and 1<=args.count<=8
 assert os.geteuid()==0 and Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n' and args.fixtures.resolve()==HERE
 assert Path(sys.executable).resolve().is_relative_to('/nix/store') and str(args.reference_executable).startswith('/nix/store/')
 stripped=sorted(key for key in os.environ if key.startswith('DBUS_'))
 for key in stripped:del os.environ[key]
 os.environ.update(PYTHONDONTWRITEBYTECODE='1',FD02_PIPE_FIXTURES=str(args.reuse_fixtures))
 Q=load(HERE/'qualify.py','fd02_all_batch_controller');plan=load(HERE/'plan.py','fd02_all_batch_plan')
 ROOT.mkdir(mode=0o755,exist_ok=True);output=ROOT/'batch.json';assert not output.exists(),'occupied batch evidence'
 run_batch(args,Q,plan,started,deadline,output,stripped)
def run_batch(args,Q,plan,started,deadline,output,stripped):
 report=dict(schema=1,scope='FD02/all-boundaries/core/batch',result='running',first=args.first,count=args.count,geometry=None,guest_seconds=120,stripped_dbus_keys=stripped,cases=[],controller_invocations=0,backend_invocations=0,mode_observations=0,physical_vm_count=None)
 accepted=[];child=None
 def save():
  persist(report,output,started,deadline)
 save()
 try:
  for boundary in range(args.first,args.first+args.count):
   remaining=deadline-time.monotonic();assert remaining>0,'whole batch deadline exhausted'
   evidence=Q.socket_path(boundary).parent;assert not evidence.exists(),'occupied private invocation'
   evidence.mkdir(mode=0o755)
   command=[sys.executable,'-B',str(HERE/'qualify.py')]
   for name in INPUT_NAMES:command.extend(('--'+name,str(getattr(args,name.replace('-','_')))))
   command.extend(('--boundary',str(boundary),'--evidence',str(evidence)))
   row=dict(boundary=boundary,result='running',command=command,controller_reaped=False);report['cases'].append(row);save()
   with (evidence/'controller.stdout').open('wb') as stdout,(evidence/'controller.stderr').open('wb') as stderr:
    child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,env=os.environ.copy());row['controller_pid']=child.pid;report['controller_invocations']+=1;save()
    try:row['returncode']=child.wait(timeout=max(0.001,deadline-time.monotonic()))
    except subprocess.TimeoutExpired:
     row.update(result='failed',error='absolute guest batch deadline',backend_containment='requires disposable VM shutdown')
     os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1);row['controller_reaped']=True;raise
    row['controller_reaped']=True;child=None;save()
   path=evidence/'report.json'
   if path.exists():
    raw=path.read_bytes();case=json.loads(raw);row.update(report_path=str(path),report_sha256=hashlib.sha256(raw).hexdigest(),reported_counts=case.get('counts'),reported_mode_observations=case.get('mode_observations'))
    report['backend_invocations']+=case.get('counts',{}).get('executed',0)
   assert row['returncode']==0,'boundary controller failure'
   assert path.exists(),'missing boundary report';check_deadline(deadline,'before case oracle');Q.assert_report(case);check_deadline(deadline,'after case oracle')
   row['result']='passed';accepted.append(case);report['mode_observations']+=case['mode_observations']
   if report['geometry'] is None:
    report['geometry']=case['geometry'];assert args.count==min(8,case['geometry']['boundaries']-args.first+1),'explicit final batch count required'
   assert case['geometry']==report['geometry'],'fresh invocation geometry drift';save()
  # The persisted report remains running during synchronous full-batch replay.
  check_deadline(deadline,'before full-batch replay');candidate=copy.deepcopy(report);candidate.update(result='passed',elapsed_seconds=time.monotonic()-started)
  plan.assert_batch(candidate,accepted,Q.assert_report);check_deadline(deadline,'after full-batch replay')
  report['result']='passed'
 except Exception as error:
  report.update(result='failed',error=repr(error))
  if report['cases'] and report['cases'][-1]['result']=='running':report['cases'][-1].update(result='failed',error=repr(error))
  for boundary in range(args.first+len(report['cases']),args.first+args.count):report['cases'].append(dict(boundary=boundary,result='blocked',reason='prior invocation failed'))
 finally:
  if child is not None and child.poll() is None:
   os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1)
   report['cases'][-1].update(controller_reaped=True,backend_containment='requires disposable VM shutdown')
  save()
 try:
  assert report['result']=='passed',report
  check_deadline(deadline,'before return serialization')
  summary=json.dumps(dict(result='passed',first=args.first,count=args.count,geometry=report['geometry'],backend_invocations=report['backend_invocations'],mode_observations=report['mode_observations'],physical_vm_count=None))
  check_deadline(deadline,'after return serialization');print(summary);check_deadline(deadline,'before return')
 except Exception as error:
  report.update(result='failed',error=repr(error));save();raise
 return report
if __name__=='__main__':main()
