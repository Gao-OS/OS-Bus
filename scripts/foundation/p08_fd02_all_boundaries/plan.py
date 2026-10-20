"""Offline batch geometry and full-oracle coverage replay; no runtime starts."""
import argparse,hashlib,json
from pathlib import Path
MAX_BATCH=8
def batches(geometry):
 n=geometry['boundaries'];assert type(n) is int and n>=1 and n==geometry['frame_bytes']-1
 return [dict(first=first,count=min(MAX_BATCH,n-first+1)) for first in range(1,n+1,MAX_BATCH)]
def assert_batch(batch,reports,oracle):
 assert (batch['schema'],batch['scope'],batch['result'])==(1,'FD02/all-boundaries/core/batch','passed')
 first,count=batch['first'],batch['count'];assert type(first) is int and type(count) is int and first>=1 and 1<=count<=MAX_BATCH
 assert batch['guest_seconds']==120 and 0<batch['elapsed_seconds']<=120
 geometry=batch['geometry'];n=geometry['boundaries'];assert count==min(MAX_BATCH,n-first+1)
 assert len(reports)==len(batch['cases'])==count and batch['controller_invocations']==count and batch['backend_invocations']==2*count and batch['mode_observations']==4*count
 assert batch['physical_vm_count'] is None,'guest cannot invent physical VM receipts'
 identities={key:set() for key in ('observer','broker','actor','launcher')}
 for boundary,row,report in zip(range(first,first+count),batch['cases'],reports):
  assert row['boundary']==report['boundary']==boundary and row['result']=='passed' and row['returncode']==0 and row['controller_reaped'] is True
  assert row['report_sha256']==hashlib.sha256((json.dumps(report,indent=2,sort_keys=True)+'\n').encode()).hexdigest()
  assert report['geometry']==geometry and report['freeze']==reports[0]['freeze']
  oracle(report)
  for key in identities:
   processes=[report[key]] if key=='observer' else [combination[key] for combination in report['combinations']]
   for process in processes:
    identity=(process['pid'],process['starttime_ticks'])
    assert identity not in identities[key],'backend/actor/controller reused within physical guest batch'
    identities[key].add(identity)
 return geometry
def assert_coverage(entries,oracle,host_receipts=None):
 assert entries,'no batch execution'
 geometry=entries[0][0]['geometry'];expected=batches(geometry);actual=[];observations=[];freeze=entries[0][1][0]['freeze']
 for batch,reports in entries:
  assert assert_batch(batch,reports,oracle)==geometry
  actual.append(dict(first=batch['first'],count=batch['count']))
  for report in reports:
   assert report['freeze']==freeze,'cross-VM freeze drift'
   for combination in report['combinations']:
    for mode in combination['modes']:observations.append((report['boundary'],combination['backend'],mode['mode']))
 assert actual==expected,'missing, duplicate, reordered or extra batches'
 wanted={(offset,backend,mode) for offset in range(1,geometry['frame_bytes']) for backend in ('gao','reference') for mode in ('prefix-right','last-byte-right')}
 assert len(observations)==len(set(observations))==len(wanted) and set(observations)==wanted,'exact coverage missing or duplicated'
 physical=None
 if host_receipts is not None:
  assert len(host_receipts)==len(entries) and len({row['vm_id'] for row in host_receipts})==len(entries)
  for receipt,(batch,_) in zip(host_receipts,entries):
   assert receipt['sealed'] is True and receipt['shutdown_confirmed'] is True and receipt['host_seconds']==900 and 0<receipt['elapsed_seconds']<=900
   assert receipt['batch_first']==batch['first'] and receipt['batch_sha256']==hashlib.sha256((json.dumps(batch,indent=2,sort_keys=True)+'\n').encode()).hexdigest()
  physical=len(host_receipts)
 n=geometry['boundaries']
 return dict(logical_backend_combinations=2,boundaries=n,backend_invocations=2*n,mode_observations=4*n,accepted_guest_batches=len(entries),physical_vm_count=physical)
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--geometry',required=True,type=Path);args=parser.parse_args()
 print(json.dumps(batches(json.loads(args.geometry.read_text())),indent=2))
if __name__=='__main__':main()
