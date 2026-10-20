"""Finite PRO05 orchestration; an existing guest adapter owns every operation.

No backend, actor, socket, sampler, or cleanup process is launched here. The
caller must clean up owned channels if run_cases raises. Returned and persisted
records remain pending independent runtime review; fake drivers cannot qualify
a requirement. Adapter snapshots retain raw resource samples alongside their
normalized, exact-comparable authority state.
"""
import copy
import hashlib
import json
import time

from vectors import CASES, call, wire_string
from wire_replay import (BUS, bounded, decode_frames, verify_observer, verify_target,
                         verify_terminal, verify_trace)


GROUPS = (
    ('variant', 1, ('variant64', 'variant65')),
    ('array', 1, ('array32', 'array33')),
    ('struct', 1, ('struct32', 'struct33')),
    ('match', 1, ('match_string', 'match_uint32')),
    ('collection', 1, ('collection',)),
) + tuple(('prefix', iteration, ('prefix',)) for iteration in range(1, 33))


def _identity(value, uid):
    assert type(value) is dict
    assert type(value['pid']) is int and value['pid'] > 1
    assert type(value['uid']) is type(value['gid']) is int
    assert value['uid'] == value['gid'] == uid


def _actor(value, uid, bus_id=None):
    _identity(value['identity'], uid)
    assert type(value['unique']) is str and value['unique'].startswith(':')
    assert type(value['bus_id']) is str and len(value['bus_id']) == 32
    if bus_id is not None:
        assert value['bus_id'] == bus_id


def _resources(value, observer, baseline=None):
    assert type(value) is dict
    for role in ('daemon', 'observer'):
        sample = value[role]
        assert sample['complete'] is True
        _identity(sample['identity'], 0 if role == 'daemon' else 1100)
        assert type(sample['fd_targets']) in (dict, list) and sample['fd_targets']
        if role == 'observer':
            assert sample['identity'] == observer['identity']
        if baseline is not None:
            for field in ('identity', 'fd_targets'):
                assert sample[field] == baseline[role][field], 'resource endpoint drift'


def _snapshot(value, observer, source=None, baseline=None):
    authority = value['authority']
    expected = {key: observer[key] for key in ('identity', 'unique', 'owner', 'bus_id')}
    expected.update(uid=1100, pid=observer['identity']['pid'])
    assert authority['observer'] == expected
    assert type(authority['core']) is dict and authority['core']
    for field in ('device', 'inode'):
        assert type(authority['endpoint'][field]) is int and authority['endpoint'][field] > 0
    names = [BUS, observer['unique'], observer['owner']]
    if source is None:
        assert authority['source'] is None
    else:
        expected_source = {key: source[key] for key in ('identity', 'unique', 'bus_id')}
        expected_source.update(uid=1101, pid=source['identity']['pid'])
        assert authority['source'] == expected_source
        names.append(source['unique'])
    assert authority['names'] == sorted(names)
    _resources(value['resources'], observer)
    if baseline is not None:
        assert authority == baseline['authority'], 'authority was not restored exactly'
        _resources(value['resources'], observer, baseline['resources'])


def _native(event, watch, reason=None):
    assert event['complete'] is True and event['errors'] == []
    assert type(event['authority']) is dict and event['authority']
    assert type(event['resources']) is dict and event['resources']
    for field in ('name', 'peer', 'reference'):
        assert event[field] == watch[field]
    if reason is not None:
        assert event['reason'] == reason
    bounded(event['elapsed_ms'], 1500)


def _public_reply(response, expected, source_name, observer_name):
    row = response['result']
    assert row['type'] == 2 and row['sender'] == BUS and row['error'] is None
    assert type(row['reply_serial']) is int and row['reply_serial'] > 0
    assert row['body'] == [expected]
    request = call('NameHasOwner', row['reply_serial'], 's', wire_string(source_name))
    frames = decode_frames(verify_trace(response, [request], 3000))
    assert len(frames) == 1 and frames[0]['message'] == row
    assert frames[0]['fields'].get(6) == observer_name and frames[0]['fields'].get(8) == 'b'


def _watch(value, source, backend, observer):
    assert value['source_identity'] == source['identity'] and value['name'] == source['unique']
    if backend == 'gao_bus':
        assert value['kind'] == 'beam-monitor'
        assert type(value['peer']) is str and value['peer']
        assert type(value['reference']) is str and value['reference']
        _native(value['watch_event'], value)
    else:
        assert value['kind'] == 'public-name'
        assert not {'peer', 'reference', 'watch_event', 'native_down'} & value.keys()
        _public_reply(value['watch_receipt'], True, source['unique'], observer['unique'])


def _down(value, watch, source, backend, observer):
    assert value['kind'] == watch['kind']
    assert value['source_identity'] == source['identity'] and value['name'] == source['unique']
    bounded(value['elapsed_ms'], 1500)
    if backend == 'gao_bus':
        assert value['reason'] == 'normal'
        for field in ('peer', 'reference'):
            assert value[field] == watch[field]
        _native(value['native_down'], watch, 'normal')
    else:
        assert not {'peer', 'reference', 'reason', 'watch_event', 'native_down'} & value.keys()
        assert value['has_owner'] is False
        _public_reply(value['public_reply'], False, source['unique'], observer['unique'])


def _retirement(value):
    assert value['method'] == 'eof' and value['returncode'] == 0
    before = value['before_containment']
    assert before['pid_absent'] is before['actor_pid_absent'] is before['group_absent'] is True
    assert before['timed_out'] is False and before['errors'] == []


def authorization(down, restoration):
    """Join retained observations; the digest never substitutes for their checks."""
    raw = json.dumps(dict(down=down, restoration=restoration), sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def run_cases(driver):
    """Run exactly 37 source groups/41 targets through an existing adapter.

    Adapter methods: start_source(family, iteration), request(worker, command),
    snapshot(source_or_None, remaining_ms=None), watch(source),
    await_down(source, watch, remaining_ms=None), retire(source),
    observe(source_name=None)->{response,serial}, persist(record).
    Every operation must bound its own blocking I/O. In particular snapshot and
    await_down must honor the supplied remaining_ms within their shared 1500ms.
    """
    assert driver.backend in ('gao_bus', 'reference')
    observer = copy.deepcopy(driver.observer)
    _actor(observer, 1100)
    assert type(observer['owner']) is str and observer['owner'] and not observer['owner'].startswith(':')
    report = dict(backend=driver.backend, result='pending-independent-runtime-review',
                  runtime_qualification=False, groups=[], events=[])
    phase = 'baseline'
    seen_names = {observer['unique']}

    def retain(event, **data):
        record = copy.deepcopy(dict(event=event, **data, runtime_qualification=False))
        report['events'].append(record)
        driver.persist(copy.deepcopy(record))

    def snapshot(source=None, remaining_ms=None):
        value = copy.deepcopy(driver.snapshot(source, remaining_ms=remaining_ms))
        retain('snapshot', source=None if source is None else source['identity'], value=value)
        _snapshot(value, observer, source)
        assert driver.observer == observer, 'observer identity changed'
        return value

    def observe(source_name=None):
        began = time.monotonic()
        result = copy.deepcopy(driver.observe(source_name=source_name))
        retain('observer', value=result)
        bounded((time.monotonic() - began) * 1000, 1000)
        verification = verify_observer(result['response'], observer['owner'], observer['unique'],
                                       observer['bus_id'], result['serial'], source_name)
        assert driver.observer == observer, 'observer identity changed'
        return verification

    try:
        baseline = snapshot()
        for family, iteration, cases in GROUPS:
            phase = family + '/' + str(iteration)
            before = snapshot()
            _snapshot(before, observer, baseline=baseline)
            source = driver.start_source(family, iteration)
            public = copy.deepcopy({key: source[key] for key in ('identity', 'unique', 'bus_id')})
            retain('source', family=family, iteration=iteration, value=public)
            _actor(public, 1101, observer['bus_id'])
            assert public['identity']['pid'] != observer['identity']['pid']
            assert public['unique'] not in seen_names, 'source unique name reused'
            seen_names.add(public['unique'])
            active = snapshot(source)
            assert active['authority']['endpoint'] == baseline['authority']['endpoint']
            assert active['resources']['daemon']['identity'] == baseline['resources']['daemon']['identity']
            watch = copy.deepcopy(driver.watch(source))
            retain('watch', value=watch)
            _watch(watch, public, driver.backend, observer)
            group = dict(family=family, iteration=iteration, source=public, before=before,
                         active=active, watch=watch, targets=[])
            report['groups'].append(group)
            terminal_case = None
            for case in cases:
                phase = case + '/' + str(iteration)
                began = time.monotonic()
                response = copy.deepcopy(driver.request(source, dict(op='target', case=case)))
                retain('target', case=case, iteration=iteration, response=response)
                bounded((time.monotonic() - began) * 1000, CASES[case]['request_ms'])
                verification = verify_target(case, response, public['unique'], public['bus_id'])
                target = dict(case=case, response=response, verification=verification)
                group['targets'].append(target)
                if CASES[case]['oracle'] == 'close':
                    terminal_case = case
                else:
                    target['observer'] = observe(public['unique'] if case == 'match_string' else None)
                    unchanged = snapshot(source)
                    _snapshot(unchanged, observer, source, active)
                    target['after'] = unchanged
            if terminal_case is None:
                closed = copy.deepcopy(driver.request(source, dict(op='close')))
                retain('explicit-close', response=closed)
                assert verify_trace(closed, [], 3000) == b'' and closed['wire'] == []
                assert closed['result'] == dict(disposition='controller-close', socket_closed=True)
                group['close'] = closed
            # The actor remains open for terminal groups until both real checks
            # finish. Reading EOF or retiring it earlier would invalidate proof.
            began = time.monotonic()
            down = copy.deepcopy(driver.await_down(source, watch, remaining_ms=1500))
            retain('down', value=down)
            _down(down, watch, public, driver.backend, observer)
            remaining = 1500 - (time.monotonic() - began) * 1000
            assert remaining > 0, 'DOWN/restoration deadline'
            restored = snapshot(remaining_ms=remaining)
            _snapshot(restored, observer, baseline=baseline)
            elapsed = (time.monotonic() - began) * 1000
            bounded(elapsed, 1500)
            group.update(down=down, restoration=restored, down_restoration_ms=elapsed)
            if terminal_case is not None:
                token = authorization(down, restored)
                retain('terminal-authorization', authorization=token, down=down, restoration=restored)
                began_eof = time.monotonic()
                terminal = copy.deepcopy(driver.request(source, dict(op='terminal', case=terminal_case,
                                                                    authorization=token)))
                retain('terminal', response=terminal)
                bounded((time.monotonic() - began_eof) * 1000, 3000)
                group['terminal'] = dict(response=terminal,
                    verification=verify_terminal(terminal_case, terminal, token), authorization=token)
            group['observer'] = observe()
            retired = copy.deepcopy(driver.retire(source))
            retain('retirement', value=retired)
            _retirement(retired)
            group['retirement'] = retired
            final = snapshot()
            _snapshot(final, observer, baseline=baseline)
            group['after'] = final
            retain('group-complete', family=family, iteration=iteration,
                   target_count=len(group['targets']))
        assert len(report['groups']) == 37
        assert sum(len(group['targets']) for group in report['groups']) == 41
        report['counts'] = dict(source_groups=37, targets=41)
        retain('pending-independent-runtime-review', counts=report['counts'])
        return report
    except Exception as error:
        report['result'] = 'failed'
        retain('failure', phase=phase, error=repr(error))
        raise
