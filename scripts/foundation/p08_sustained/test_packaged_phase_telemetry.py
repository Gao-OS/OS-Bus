"""Offline independent-pipe diagnostics with finite actor/controller barriers."""
from contextlib import contextmanager
import importlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch


def optional(name):
    return importlib.import_module(name) if importlib.util.find_spec(name) else None

telemetry = optional('packaged_diagnostics')
channel = optional('packaged_diagnostic_channel')

RESPONDER = r'''
import json,os,socket,sys,time
from packaged_diagnostic_actor import serve
nonce,path,mode=sys.argv[1:]
control=socket.socket(socket.AF_UNIX);control.settimeout(3);control.connect(path)
f=control.makefile('r')
def event(kind): control.sendall((json.dumps(dict(kind=kind,at_ns=time.monotonic_ns()))+'\n').encode())
original=json.loads
def decode(line):
    if mode=='actor-barrier':
        event('actor-before-rpc');assert f.readline()=='release\n'
    return original(line)
json.loads=decode
class Workload:
    def health(self):
        event('rpc-entry');return dict(latency_ms=1.0,name=':1.13')
class Output:
    def write(self,text): return sys.stdout.write(text)
    def flush(self):
        sys.stdout.flush();event('emitted')
print(json.dumps(dict(ok=True,result=dict(pid=os.getpid(),uid=1100,name=':1.13'))),flush=True)
serve(Workload(),'0'*32 if mode=='wrong-nonce' else nonce,sys.stdin,Output())
f.close();control.close()
'''


class PhaseTelemetryTests(unittest.TestCase):
    def modules(self):
        self.assertIsNotNone(telemetry,'buffered save/endpoint telemetry is missing')
        self.assertIsNotNone(channel,'diagnostic Actor wrapper is missing')
        return telemetry,channel

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.threads=[];self.errors=[];self.actors=[];self.sockets=[];self.files=[]
        self.release=threading.Event()

    def tearDown(self):
        self.release.set()
        for thread in self.threads:
            thread.join(4);self.assertFalse(thread.is_alive(),'reader not joined')
        from channel import Channel
        for actor in self.actors:
            if actor.process.poll() is None: Channel.stop(actor,grace=1)
            else:
                if not actor.process.stdin.closed: actor.process.stdin.close()
                if not actor.process.stdout.closed: actor.process.stdout.close()
        for f in self.files: f.close()
        for sock in self.sockets: sock.close()
        self.tmp.cleanup();self.assertEqual(self.errors,[])

    def reader(self,fn):
        result=[]
        def run():
            try: result.append(fn())
            except BaseException as error: self.errors.append(error)
        thread=threading.Thread(target=run,name='diagnostic-reader')
        self.threads.append(thread);thread.start();return thread,result

    def responder(self,mode='normal'):
        t,c=self.modules();d=t.Diagnostics('a'*32)
        listener=socket.socket(socket.AF_UNIX);listener.settimeout(3)
        self.sockets.append(listener);path=str(self.root/'control.sock')
        listener.bind(path);listener.listen(1)
        actor=c.DiagnosticActor([sys.executable,'-B','-c',RESPONDER,d.nonce,path,mode],self.root/'healthy.log',d)
        self.actors.append(actor)
        control,_=listener.accept();control.settimeout(3);self.sockets.append(control)
        f=control.makefile('r');self.files.append(f);self.assertTrue(actor.read()['ok'])
        return actor,d,control,f

    def event(self,f,kind):
        row=json.loads(f.readline());self.assertEqual(row['kind'],kind);return row

    def stop(self,actor):
        result=actor.stop(grace=2)
        self.assertEqual(result['method'],'eof');self.assertEqual(result['returncode'],0)
        self.assertTrue(result['diagnostic_eof_bound'])

    def test_save_keeps_exact_full_bytes_and_buffers_phases(self):
        t,_=self.modules();d=t.Diagnostics('a'*32)
        report={'unicode':'雪 é\n','kills':[{'full':'x'*8192} for _ in range(250)],'healthy':{'count':2,'observations':[1,2]}}
        target=self.root/'qualification.json';sidecar=self.root/'diagnostics.jsonl'
        d.save_report(report,target,900)
        self.assertEqual(target.read_bytes(),(json.dumps(report,indent=2,sort_keys=True)+'\n').encode())
        self.assertFalse(sidecar.exists(),'per-mark synchronous sidecar write')
        row=d.rows[0];self.assertEqual(row['owner'],'save');self.assertEqual(row['operation_index'],900)
        self.assertEqual(row['phase_schema'],2)
        self.assertEqual(row['buffer_characters'],64*1024)
        self.assertLessEqual(row['max_write_characters'],64*1024)
        self.assertEqual(row['payload_characters'],target.stat().st_size)
        self.assertGreater(row['write_chunks'],1)
        phases=row['phases'];keys=['save_started_ns','encode_write_started_ns','encode_write_finished_ns','save_finished_ns']
        self.assertEqual([phases[k] for k in keys],sorted(phases[k] for k in keys))
        self.assertFalse(any(k.startswith(('dumps_','write_text_')) for k in phases))
        d.persist(sidecar);d.persist(sidecar)
        self.assertEqual([json.loads(s) for s in sidecar.read_text().splitlines()],[row])

    def test_exact_protocol_result_raw_previous_and_final_emission_binding(self):
        actor,d,_,f=self.responder()
        for _ in range(2):
            self.assertEqual(actor.request(op='health'),dict(latency_ms=1.0,name=':1.13'))
            self.event(f,'rpc-entry');self.event(f,'emitted')
        self.stop(actor)
        raw=[json.loads(s) for s in actor.log.read_text().splitlines()]
        requests=[r for r in d.rows if r['owner']=='controller'];emitted=[r for r in d.rows if r['owner']=='actor-emission']
        self.assertEqual([r['request_id'] for r in requests],[1,2]);self.assertEqual([r['request_id'] for r in emitted],[1,2])
        self.assertEqual(raw[1]['diagnostic'],requests[0]['actor']);self.assertEqual(raw[2]['diagnostic'],requests[1]['actor'])
        self.assertEqual(raw[2]['diagnostic']['previous_emission'],emitted[0]['emission'])
        self.assertEqual(raw[-1]['diagnostic_eof']['emission'],emitted[1]['emission'])
        self.assertEqual([r['command_json'] for r in requests],[json.dumps({'op':'health'})]*2)
        for row in requests:
            p=row['phases'];keys=['request_enter_ns','command_ready_ns','write_started_ns','write_finished_ns','flush_finished_ns','read_started_ns','line_available_ns','log_started_ns','log_finished_ns','decode_started_ns','decode_finished_ns','request_finished_ns']
            self.assertEqual([p[k] for k in keys],sorted(p[k] for k in keys))
            self.assertTrue(p['selects']);self.assertTrue(p['reads'])
            a=row['actor']['phases'];self.assertLessEqual(a['received_ns'],a['rpc_started_ns']);self.assertLessEqual(a['rpc_finished_ns'],p['line_available_ns'])

    def test_pre_rpc_actor_barrier_discriminates_actor_dispatch_delay(self):
        actor,d,control,f=self.responder('actor-barrier')
        thread,result=self.reader(lambda:actor.request(op='health'))
        before=self.event(f,'actor-before-rpc');self.assertFalse(result)
        released=time.monotonic_ns();control.sendall(b'release\n')
        self.event(f,'rpc-entry');self.event(f,'emitted');thread.join(3)
        self.assertEqual(result,[dict(latency_ms=1.0,name=':1.13')]);self.stop(actor)
        row=next(r for r in d.rows if r['owner']=='controller');a=row['actor']['phases']
        self.assertLessEqual(a['received_ns'],before['at_ns']);self.assertLessEqual(before['at_ns'],released)
        self.assertGreaterEqual(a['decoded_ns'],released);self.assertGreaterEqual(a['rpc_started_ns'],released)

    def test_post_emission_barrier_discriminates_controller_decode_delay(self):
        actor,d,_,f=self.responder();original=json.loads;entered=threading.Event()
        def decode(text,*args,**kwargs):
            if threading.current_thread().name=='diagnostic-reader':
                entered.set();self.assertTrue(self.release.wait(3),'decode barrier deadline')
            return original(text,*args,**kwargs)
        with patch.object(channel.json,'loads',side_effect=decode):
            thread,result=self.reader(lambda:actor.request(op='health'))
            self.event(f,'rpc-entry');emission=self.event(f,'emitted')
            self.assertTrue(entered.wait(3),'decode entry deadline');self.assertFalse(result)
            released=time.monotonic_ns();self.release.set();thread.join(3)
        self.assertEqual(result,[dict(latency_ms=1.0,name=':1.13')]);self.stop(actor)
        row=next(r for r in d.rows if r['owner']=='controller');final=next(r for r in d.rows if r['owner']=='actor-emission')
        self.assertLessEqual(emission['at_ns'],released);self.assertLessEqual(row['actor']['phases']['rpc_finished_ns'],released)
        self.assertLessEqual(row['phases']['decode_started_ns'],released);self.assertGreaterEqual(row['phases']['decode_finished_ns'],released)
        self.assertLessEqual(final['emission']['flush_finished_ns'],row['phases']['decode_finished_ns'])

    def test_nonce_mismatch_fails_closed_with_failure_receipt(self):
        actor,d,_,f=self.responder('wrong-nonce')
        with self.assertRaisesRegex(AssertionError,'diagnostic nonce'): actor.request(op='health')
        self.event(f,'rpc-entry');self.event(f,'emitted')
        rows=[r for r in d.rows if r['owner']=='controller'];self.assertEqual(len(rows),1);self.assertIn('error',rows[0])

    def fake(self):
        t,c=self.modules();d=t.Diagnostics('a'*32);actor=object.__new__(c.DiagnosticActor)
        actor.diagnostics=d;actor.request_id=0;actor.active=None;actor.buffer=b'';actor.command=['finite-fake'];actor.log=self.root/'unused.log'
        actor.process=types.SimpleNamespace(stdin=io.BytesIO(),stdout=types.SimpleNamespace(fileno=lambda:0))
        return actor,d

    def test_original_read_deadline_not_extended(self):
        actor,d=self.fake()
        with patch.object(channel.time,'monotonic',side_effect=[0,11]):
            with self.assertRaisesRegex(AssertionError,'channel deadline'): actor.request(op='health')
        self.assertIn('error',d.rows[-1]);self.assertEqual(d.rows[-1]['request_id'],1)

    def test_original_output_cap_not_expanded(self):
        actor,d=self.fake();actor.buffer=b'x'*4_194_304
        with patch.object(channel.select,'select',return_value=([actor.process.stdout],[],[])),patch.object(channel.os,'read',return_value=b'x'):
            with self.assertRaisesRegex(AssertionError,'fixture output line too large'): actor.request(op='health')
        self.assertIn('error',d.rows[-1])


class ControllerIntegrationTests(unittest.TestCase):
    def test_guest_save_uses_diagnostics_and_existing_save_opportunity(self):
        self.assertIsNotNone(telemetry,'save diagnostics are missing')
        import packaged_qualify as controller
        guest=object.__new__(controller.Guest)
        guest.started=controller.time.monotonic();guest.health={'count':0}
        guest.report={'rows':{name:{'status':'blocked','executed':False} for name in controller.ROWS},'operation_count':900}
        guest.diagnostics=telemetry.Diagnostics('a'*32)
        with tempfile.TemporaryDirectory() as directory,patch.object(controller,'EVIDENCE',Path(directory)):
            guest.save()
            self.assertTrue((Path(directory)/'diagnostics.jsonl').exists())
            self.assertEqual(len(guest.diagnostics.rows),1)
            self.assertEqual(guest.diagnostics.rows[0]['operation_index'],900)

    def test_request_binding_is_captured_before_exclusion_exit_admits_next_probe(self):
        import packaged_qualify as controller
        guest=object.__new__(controller.Guest);guest.diagnostics=telemetry.Diagnostics('a'*32)
        gate=controller.HealthGate();guest.health_lock=gate;guest.report={'operation_count':900}
        origin=controller.time.monotonic()
        guest.health={'started':origin,'count':0,'max_ms':0,'errors':[],'observations':[]}
        first_called,post_queued,first_released,post_finished=[threading.Event() for _ in range(4)]
        observer=types.SimpleNamespace(request_id=0)
        def request(**command):
            observer.request_id+=1
            identity=observer.request_id
            if identity==1:
                first_called.set()
                self.assertTrue(post_queued.wait(2),'post-kill queue barrier deadline')
            return dict(latency_ms=1.0,request_identity=identity)
        observer.request=request
        @contextmanager
        def exclusion(kind):
            with gate.section(kind,900):
                yield
            if kind=='health-regular':
                first_released.set()
                self.assertTrue(post_finished.wait(2),'post-kill completion barrier deadline')
        guest.exclusion=exclusion
        original_wait=gate.condition.wait
        def waiting(timeout=None):
            if threading.current_thread().name=='binding-post-kill':
                post_queued.set()
            return original_wait(timeout)
        receipts={};errors=[]
        def run(kind):
            try:
                receipts[kind]=guest.health_probe(observer,regular=kind=='regular')
            except BaseException as error:
                errors.append(error)
            finally:
                if kind=='post-kill': post_finished.set()
        first=threading.Thread(target=lambda:run('regular'),name='binding-regular')
        second=threading.Thread(target=lambda:run('post-kill'),name='binding-post-kill')
        with patch.object(gate.condition,'wait',side_effect=waiting):
            first.start()
            try:
                self.assertTrue(first_called.wait(2),'regular actor entry deadline')
                second.start()
                self.assertTrue(first_released.wait(2),'regular gate release deadline')
                self.assertTrue(post_finished.wait(2),'post-kill receipt deadline')
            finally:
                post_queued.set();post_finished.set()
                first.join(3)
                if second.ident is not None: second.join(3)
        self.assertFalse(first.is_alive());self.assertFalse(second.is_alive());self.assertEqual(errors,[])
        self.assertEqual(observer.request_id,2)
        self.assertEqual(receipts['regular']['actor']['request_identity'],1)
        self.assertEqual(receipts['post-kill']['actor']['request_identity'],2)
        self.assertEqual(receipts['regular']['diagnostic_request_id'],1)
        self.assertEqual(receipts['post-kill']['diagnostic_request_id'],2)
        self.assertEqual(receipts['regular']['due'],origin)
        self.assertEqual(guest.health['count'],1)

    def test_health_receipt_binds_diagnostic_request_without_changing_due(self):
        self.assertIsNotNone(telemetry,'health diagnostics are missing')
        import packaged_qualify as controller
        guest=object.__new__(controller.Guest);guest.diagnostics=telemetry.Diagnostics('a'*32)
        guest.health_lock=controller.HealthGate();guest.report={'operation_count':900}
        origin=controller.time.monotonic();guest.health={'started':origin,'count':0,'max_ms':0,'errors':[],'observations':[]}
        observer=types.SimpleNamespace(request_id=0,request=lambda **command:dict(latency_ms=1.0))
        def request(**command): observer.request_id+=1;return dict(latency_ms=1.0)
        observer.request=request
        row=guest.health_probe(observer)
        self.assertEqual(row['due'],origin);self.assertEqual(row['diagnostic_request_id'],1)
        self.assertEqual(row['diagnostic_nonce'],guest.diagnostics.nonce)


if __name__=='__main__': unittest.main()
