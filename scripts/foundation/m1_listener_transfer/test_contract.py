"""Pure checker controls authored first; root owns all RED/GREEN execution."""
import copy
import importlib.util
import os
from pathlib import Path
import unittest

SOURCE = Path(os.environ.get('LISTENER_CONTRACT_SOURCE', str(Path(__file__).with_name('contract.py'))))
spec = importlib.util.spec_from_file_location('listener_contract_under_test', SOURCE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def witness():
    """Synthetic checker input, explicitly not a runtime receipt."""
    client = dict(pid=123, uid=1101, gid=1101)
    observer = dict(identity=dict(pid=124, uid=1100, gid=1100), unique=':1.1', peer='#PID<0.10.0>')
    state = dict(event='snapshot', router='#PID<0.102.0>', peers=[dict(peer=observer['peer'],
                 name=observer['unique'], credentials=observer['identity'])], names=['org.foundation.Observer', ':1.1'],
                 queues=[], usage=dict({'global': dict(connections=1, authenticating=0)}, reservations=0),
                 policy='unchanged', authority=dict(authorities={name:'#PID<0.'+str(index)+'.0>' for index,name in enumerate(('GaoBus.Supervisor','GaoBus.Listener','GaoBus.Router','GaoBus.Limits','GaoBus.NameRegistry','GaoBus.MatchRules','GaoBus.Policy','GaoBus.PeerSupervisor'),100)},
                 children=[dict(peer=observer['peer'],phase='connected',credentials=observer['identity'],unique=observer['unique'])], core_children=[], accounting={'peers':{observer['peer']:{'uid':1100,'monitor':'#Reference<0.1.2.5>'}}}, name_state={},name_tables={},match_state={},match_entries=[],capabilities=[]),
                 native_fds={'8':'socket:[100]'}, incumbent=dict(inode=777, major_device=1, minor_device=0, type='other'))
    event = dict(event='listener_transfer_failure', operation='GaoBus.Listener.transfer_ownership/2',
                 error=['error',['invalid','not_owner']], peer='#PID<0.11.0>', caller='#PID<0.1.0>',
                 holder='#PID<0.12.0>', owner_before='#PID<0.12.0>', accepted_credentials=client,
                 marker_hex='2a', fd=9, fd_before='socket:[101]', fd_after=['error','enoent'],
                 socket_after=['error','closed'], incomplete=dict(phase='waiting_socket', native_socket=None,
                 unique=None, credentials=None, registry=[], router_member=False, accounting_member=False),
                 down=dict(peer='#PID<0.11.0>', monitor='#Reference<0.1.2.3>', reason='shutdown'),
                 holder_down=dict(peer='#PID<0.12.0>', monitor='#Reference<0.1.2.4>', reason='normal'),
                 before=state, after=copy.deepcopy(state), explicit_peer_cleanup=[], fault_path_removed=True,
                 daemon_elapsed_ms=10)
    client_result=dict(closed=True, method='eof', response_hex='', sent_hex='2a', elapsed_ms=10)
    probe=dict(identity=observer['identity'],unique=observer['unique'],elapsed_ms=10,
               owner=dict(type=2,error=None,sender='org.freedesktop.DBus',reply_serial=4,body=[':1.1']),
               bus=dict(type=2,error=None,sender='org.freedesktop.DBus',reply_serial=5,body=['bus-id']))
    return event, client, observer, client_result, probe


class TransferControls(unittest.TestCase):
    def test_genuine_shape_is_accepted(self):
        event, client, observer, _, _ = witness()
        checker.validate_transfer(event, client, observer)

    def rejected(self, mutate):
        event, client, observer, _, _ = witness()
        mutate(event)
        with self.assertRaises((AssertionError, KeyError)):
            checker.validate_transfer(event, client, observer)

    def test_reject_wrong_owner_error(self):
        self.rejected(lambda event:event.update(error=['error','closed']))

    def test_missing_error_or_wrong_down_is_rejected(self):
        for key in ('error','down','fd_after','socket_after','accepted_credentials','before','after'):
            self.rejected(lambda event,k=key:event.pop(k))
        for key,value in [('reason','killed'),('peer','#PID<0.99.0>'),('monitor','#Ref<0.1.2.3>')]:
            self.rejected(lambda event,k=key,v=value:event['down'].update({k:v}))

    def test_incomplete_peer_must_never_be_admitted(self):
        for key,value in [('phase','connected'),('native_socket','handle'),('unique',':1.9'),
                          ('credentials',{'uid':1101}),('registry',[':1.9']),
                          ('router_member',True),('accounting_member',True)]:
            self.rejected(lambda event,k=key,v=value:event['incomplete'].update({k:v}))

    def test_real_holder_socket_and_native_fd_removal_required(self):
        for key,value in [('owner_before','#PID<0.1.0>'),('marker_hex','00'),('fd_before','/tmp/file'),
                          ('fd_after',['ok','socket:[101]']),('socket_after',['ok','#PID<0.12.0>']),
                          ('fault_path_removed',False),('explicit_peer_cleanup',['unregister'])]:
            self.rejected(lambda event,k=key,v=value:event.update({k:v}))

    def test_kernel_client_identity_and_separate_observer_required(self):
        for key,value in [('pid',124),('uid',0),('gid',100)]:
            self.rejected(lambda event,k=key,v=value:event['accepted_credentials'].update({k:v}))
        event,client,observer,_,_=witness();observer['identity']=client
        with self.assertRaises(AssertionError):checker.validate_transfer(event,client,observer)

    def test_authority_inode_resource_and_observer_baseline_exact(self):
        for key in ('router','peers','names','queues','usage','policy','authority','native_fds','incumbent'):
            self.rejected(lambda event,k=key:event['after'].update({k:'changed'}))
        self.rejected(lambda event:event['before'].update(peers=[]))

    def test_deadlines_and_holder_retirement_required(self):
        self.rejected(lambda event:event.update(daemon_elapsed_ms=1001))
        self.rejected(lambda event:event['holder_down'].update(reason='killed'))

    def test_exact_client_eof_not_reset(self):
        _,_,_,result,_=witness();checker.validate_eof(result)
        for key in ('method','closed','response_hex','sent_hex','elapsed_ms'):
            broken=dict(result);broken.pop(key)
            with self.assertRaises((AssertionError,KeyError)):checker.validate_eof(broken)
        for key,value in [('method','reset'),('closed',False),('response_hex','00'),('sent_hex','00'),('elapsed_ms',1001)]:
            broken=dict(result,**{key:value})
            with self.assertRaises((AssertionError,KeyError)):checker.validate_eof(broken)

    def test_real_registered_observer_wire_responses(self):
        _,_,observer,_,probe=witness();checker.validate_probe(probe,observer,['bus-id'])
        for key,value in [('unique',':1.9'),('identity',{'uid':0}),('elapsed_ms',1001)]:
            with self.assertRaises((AssertionError,KeyError)):
                checker.validate_probe(dict(probe,**{key:value}),observer,['bus-id'])
        for part in ('owner','bus'):
            for key,value in [('type',3),('sender',':1.9'),('error','denied'),('reply_serial',None),('body',[])]:
                broken=copy.deepcopy(probe);broken[part][key]=value
                with self.assertRaises((AssertionError,KeyError)):checker.validate_probe(broken,observer,['bus-id'])

    def test_empty_duplicate_unexecuted_or_broader_selection_rejected(self):
        good=dict(selected=['FAIL-02/transfer-failure'],outcomes={'FAIL-02/transfer-failure':{'status':'passed'}},
                  counts=dict(selected=1,executed=1,passed=1,failed=0,blocked=0,skipped=0))
        checker.validate_selection(good)
        for value in ([],['FAIL-02/transfer-failure']*2,['FAIL-02']):
            with self.assertRaises(AssertionError):checker.validate_selection(dict(good,selected=value))
        with self.assertRaises(AssertionError):checker.validate_selection(dict(good,outcomes={}))
        with self.assertRaises(AssertionError):checker.validate_selection(dict(good,counts=dict(good['counts'],executed=0)))

    def test_natural_teardown_and_actual_pid_absence_required(self):
        good=dict(method='eof',returncode=0,pid_absent=True,actor_pid_absent=True,group_absent=True,
                  before_containment=dict(stdin_closed=True,wrapper_waited=True,wrapper_returncode=0,
                  pid_absent=True,actor_pid_absent=True,group_absent=True,timed_out=False,errors=[]))
        checker.validate_shutdown(good)
        for key,value in [('method','kill'),('returncode',1),('pid_absent',False),('actor_pid_absent',False),('group_absent',False)]:
            with self.assertRaises(AssertionError):checker.validate_shutdown(dict(good,**{key:value}))
        for key,value in [('timed_out',True),('errors',['probe']),('wrapper_returncode',1),('stdin_closed',False),('wrapper_waited',False),('group_absent',False)]:
            broken=copy.deepcopy(good);broken['before_containment'][key]=value
            with self.assertRaises(AssertionError):checker.validate_shutdown(broken)


if __name__ == '__main__':
    unittest.main()
