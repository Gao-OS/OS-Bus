"""Bounded FD03/core different-bundles controller; runtime is isolated guest only.

Frozen lifecycle composition retains every setup/health/identity/credit and
teardown assertion. Only exact resource-count/association nodes are adapted.
"""
import ast,copy,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
SHARED=Path(sys.argv[sys.argv.index('--shared')+1]) if '--shared' in sys.argv else HERE.parent/'p08_fd01_singleton_resources'
ORIGINAL_SHA='1e17175dd92c795702de4d5dd69f85e9f632340fb769672e17122d4227e736f6'
ACTOR_SHA='1abe51b28ed36e57711ac2d181c8645d384228c8f37f7a25f115067ce545ff95'
source=(SHARED/'qualify.py').read_text();assert hashlib.sha256(source.encode()).hexdigest()==ORIGINAL_SHA,'shared controller drift'
spec=importlib.util.spec_from_file_location('fd03_frozen_controller',SHARED/'qualify.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
WORKLOAD=json.loads((HERE/'workload.json').read_text());expected=copy.deepcopy(S.WORKLOAD)
expected.update(requirement='FD-03',subcase='different-bundles');expected['bundles']=expected.pop('singleton')
expected['bundles'].update(resources=2,serials=[100,101],contents=['FD-A','FD-B']);del expected['bundles']['serial']
assert WORKLOAD==expected,'contract/cap/deadline drift'
CONTENTS=(b'FD-A',b'FD-B');PASS='passed_independent_fd03_different_bundles_core';SELECTION=['FD-03/core/different-bundles/gao','FD-03/core/different-bundles/reference']
SHARED_FILES={'shared_'+name:file for name,file in [('actor','actor.py'),('actor_test','actor_test.py'),('qualify','qualify.py'),('oracle_test','oracle_test.py'),('workload','workload.json'),('test_nix','test.nix'),('readme','README.md')]}
INPUT_KEYS=S.INPUT_KEYS|set(SHARED_FILES);SHAPES={};TREE=ast.parse(source)
def node(text):return ast.parse(text).body[0]
def replace_statement(fn,old,new):
    old_dump=ast.dump(node(old),include_attributes=False);matches=[]
    class Replace(ast.NodeTransformer):
        def visit(self,n):
            if isinstance(n,ast.stmt) and ast.dump(n,include_attributes=False)==old_dump:
                matches.append(n);return ast.parse(new).body
            return super().visit(n)
    result=Replace().visit(fn);assert len(matches)==1,('frozen node shape drift',old,len(matches));return result
def function(name):
    matches=[n for n in TREE.body if isinstance(n,ast.FunctionDef) and n.name==name];assert len(matches)==1
    return copy.deepcopy(matches[0])
NS=dict(vars(S));NS.update(HERE=HERE,WORKLOAD=WORKLOAD,PASS=PASS,SELECTION=SELECTION,INPUT_KEYS=INPUT_KEYS,CONTENTS=CONTENTS)
def compile_function(original,fn):
    before=ast.dump(function(original),include_attributes=False);after=ast.dump(fn,include_attributes=False)
    SHAPES[fn.name]=dict(original_function=original,original_ast_sha256=hashlib.sha256(before.encode()).hexdigest(),executed_ast_sha256=hashlib.sha256(after.encode()).hexdigest())
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),str(HERE/'qualify.py'),'exec'),NS)
    return NS[fn.name]
f=function('assert_exercise');f.name='_assert_transfer';f.args.args.append(ast.arg(arg='ordinal'))
class BundleExpectations(ast.NodeTransformer):
    def __init__(self):self.counts={100:0,'PIPE':0,b'PIPE':0}
    def visit_Constant(self,n):
        if n.value in self.counts:
            self.counts[n.value]+=1
            expression='100+ordinal' if n.value==100 else 'CONTENTS[ordinal].decode()' if n.value=='PIPE' else 'CONTENTS[ordinal]'
            return ast.parse(expression,mode='eval').body
        return n
t=BundleExpectations();f=t.visit(f);assert t.counts=={100:2,'PIPE':1,b'PIPE':2},'frozen singleton expectation shape drift'
_assert_transfer=compile_function('assert_exercise',f)
def resources(row):return [t[k] for t in row['transfers'] for k in ('source_fd','received_fd')]
def assert_exercise(row):
    assert 'transfer' not in row and len(row['transfers'])==2,'two different bundles required'
    fds=resources(row);assert len({r['fd'] for r in fds})==4,'four distinct held descriptors required'
    assert len({(t['source_fd']['dev'],t['source_fd']['ino'],t['source_fd']['target']) for t in row['transfers']})==2,'different pipe identities required'
    for i,t in enumerate(row['transfers']):
        _assert_transfer({**row,'transfer':t},i)
        assert t['eof'] is True and t['read_chunks_hex'] and t['read_chunks_hex'][-1]=='','actual resource EOF missing'
        chunks=[bytes.fromhex(c) for c in t['read_chunks_hex']]
        assert all(chunks[:-1]) and b''.join(chunks)==CONTENTS[i] and all(len(c)<=4 for c in chunks)
        sent=t['sent'];S.integer(sent['sendmsg_bytes'],1);assert sent['sendmsg_bytes']<=sent['wire_bytes']
        assert sent['completed_bytes']==sent['wire_bytes'] and sent['right_fd']==t['source_fd'],'actual singleton send identity/count mismatch'
    for fd in fds:assert fd in row['fd_state']['fds']
f=function('assert_closed')
f=replace_statement(f,"t=exercise['transfer']","transfers=exercise['transfers']")
f=replace_statement(f,"owned=[('received',t['received_fd']),('original',t['source_fd'])]","owned=[(f'received-{i}',t['received_fd']) for i,t in enumerate(transfers)]+[(f'original-{i}',t['source_fd']) for i,t in enumerate(transfers)]")
f=replace_statement(f,"active={'source':[exercise['health'][0]['received']], 'target':[t['received'],exercise['health'][1]['received']]}","active={'source':[exercise['health'][0]['received']], 'target':[t['received'] for t in transfers]+[exercise['health'][1]['received']]}")
assert_closed=compile_function('assert_closed',f)
NS.update(resources=resources,assert_exercise=assert_exercise,assert_closed=assert_closed)
f=function('assert_report')
f=replace_statement(f,"assert (report['schema'],report['requirement'],report['subcase'],report['profile'])==(1,'FD-01','pipe','core')","assert (report['schema'],report['requirement'],report['subcase'],report['profile'])==(1,'FD-03','different-bundles','core')")
f=replace_statement(f,"resources=[c['exercise']['transfer'][key] for key in ('source_fd','received_fd')]","resources=[t[key] for t in c['exercise']['transfers'] for key in ('source_fd','received_fd')]")
f=replace_statement(f,"assert len({(r['dev'],r['ino'],r['target']) for r in resources})==1","assert len(resources)==4 and len({(r['dev'],r['ino'],r['target']) for r in resources})==2")
_assert_report=compile_function('assert_report',f)
def assert_report(report):
    _assert_report(report)
    assert report['inputs_before']['shared_qualify']['sha256']==ORIGINAL_SHA and report['inputs_before']['shared_actor']['sha256']==ACTOR_SHA
    assert report['adapter_provenance']==ADAPTER_PROVENANCE,'executed adapter/original source binding mismatch'
def capture_inputs(args,manifest):
    assert args.shared.resolve()==SHARED.resolve()
    inputs=S.capture_inputs(args,manifest)
    for key,file in SHARED_FILES.items():
        p=args.shared/file;assert p.is_absolute() and p.is_file();inputs[key]=dict(path=str(p),sha256=S.sha(p))
    assert inputs['shared_qualify']['sha256']==ORIGINAL_SHA and inputs['shared_actor']['sha256']==ACTOR_SHA
    return inputs
NS.update(assert_report=assert_report,capture_inputs=capture_inputs)
f=function('run_backend')
f=replace_statement(f,"command=[inputs['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir)]","command=[inputs['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir),str(args.shared)]")
f=replace_statement(f,"for key in ('source_fd','received_fd'):\n resource=receipt['transfer'][key]\n assert resource in row['actor']['fds']\n assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in row['broker']['fds'])","for resource in resources(receipt):\n assert resource in row['actor']['fds']\n assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in row['broker']['fds'])")
run_backend=compile_function('run_backend',f)
f=function('main')
f=replace_statement(f,"for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope'):\n parser.add_argument('--'+name,required=True,type=Path)","for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope','shared'):\n parser.add_argument('--'+name,required=True,type=Path)")
class MainLabels(ast.NodeTransformer):
    def __init__(self):self.counts={'FD-01':0,'pipe':0}
    def visit_Constant(self,n):
        if n.value in self.counts:self.counts[n.value]+=1;return ast.Constant(value='FD-03' if n.value=='FD-01' else 'different-bundles')
        return n
labels=MainLabels();f=labels.visit(f);assert labels.counts=={'FD-01':1,'pipe':1}
report_assign=[n for n in f.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='report' for t in n.targets)]
assert len(report_assign)==1 and isinstance(report_assign[0].value,ast.Call)
report_assign[0].value.keywords.append(ast.keyword(arg='adapter_provenance',value=ast.Name(id='ADAPTER_PROVENANCE',ctx=ast.Load())))
main=compile_function('main',f)
ADAPTER_PROVENANCE=dict(original_source_sha256=ORIGINAL_SHA,original_actor_sha256=ACTOR_SHA,executed_adapter_sha256=S.sha(HERE/'qualify.py'),frozen_exact_node_adaptations=SHAPES)
NS['ADAPTER_PROVENANCE']=ADAPTER_PROVENANCE
for name in ('sha','assert_wire','parse_frame','assert_connections','assert_native','native_config','reference_config','counts','candidate_inventory','CAPS','NORMALIZED_CAPS','BUS','METRICS','AUTHORITIES'):
    globals()[name]=getattr(S,name)
if __name__=='__main__':main()
