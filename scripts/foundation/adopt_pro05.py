"""Prepare existing-schema PRO05 core receipts/index from root-accepted saved data.

Root invokes with --inputs RELATIVE_JSON --inputs-sha256 EXACT_SHA256 and -B.
The input object contains `records` (the twelve names in RECORDS, each a
repository-relative {path, sha256}) and `fixture` (the immutable Nix fixture).
No fixture code is imported, no command is launched, and no consumer is run.
Outputs are proposals until root runs and accepts the unchanged index consumer.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys


ROOT = Path(__file__).absolute().parents[2]
RESUME = 'test/reports/foundation/resume-20261019'
OUTPUT = RESUME + '/pro05-adoption1'
FIXTURE = '/nix/store/iv6hsk58kw8pfdrspsw1dnkmviqc4yja-os-bus-pro05-fixtures'
SOURCE = 'scripts/foundation/pro05_complete'
SCENARIO = 'PRO-05/complete-requirement'
INVARIANT = ('Work/memory/atom counts bounded; no arithmetic, pattern-match, or '
             'string-function crash in authority.')
BACKENDS = ('reference', 'gao_bus')
ACTORS = ['independent_client', 'external_observer']
COUNTS = dict(selected=2, executed=2, passed=2, failed=0, blocked=0, skipped=0)
REPORT_SHA = '41e085084b79e2f8557be0d2678ffcc8a600d4cba3bb29a5ede7c9db52591190'
VMOFF_SHA = 'd26a2518348e812ec3f3516fc95c0a636194a2546856787d82080ee90028624e'
ARTIFACT_SHA = '712d86ed1b2439909b3942edbae475043935e31fdc1c2519261d9df7163c099b'
SOURCE_SHA = '51e6ecbcf1c91869e1db147b6ce0d37c808360f293f4c7a4d7761e80854e5130'
ORIGIN_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
BASELINE_SHA = 'd1b3030217d0990e90fe078cb5edd92e8eb4349fc4fadbe875f709f4c465bbe3'
CONTRACT_SHA = 'a6bed4b9cdfc2769352b1ecd300c779078b7a282bf7d42c527c4136ae938bb0d'
RUN_SHA = '38f526ae50a25450b3a98c922dbadb5179f3c1fd55865b5f889ca2b0e638e3ec'
RECORDS = {'report', 'vmoff', 'lifecycle', 'started', 'build_result', 'build_started',
           'build_stdout', 'validation_result', 'validation_started', 'artifact',
           'baseline_index', 'acceptance'}
EXCERPT = '# PRO-05/complete-requirement source-bound invariant measurement.'
ASSERTION = "assert record['invariant_measurement'] == expected_invariant()"
# Transcribed from expected_invariant() in the exact CONTRACT_SHA source above,
# independently of both backend measurements. No fixture function is executed.
EXPECTED = dict(categories=['deep signatures/containers', 'adversarial match argument values',
                            'large collections', 'repeated invalid prefixes'],
                source_groups=37, targets=41, prefix_incarnations=32,
                exact_finite_inputs=True, raw_receipts_bound=True,
                distinct_kernel_actors=True, observer_identity_preserved=True,
                authority_fd_restored=True, sampled_memory_bounded=True,
                sampled_atom_growth_bounded=True, normal_source_retirement=True,
                natural_teardown=True)
DRIFT = {'apps/ex_d_bus/lib/ex_dbus/message.ex',
         'apps/gao_bus/lib/gao_bus/config/runtime.ex', 'apps/gao_bus/lib/gao_bus/peer.ex'}
DEMOTIONS = {(required, 'complete-requirement', backend, 'core')
             for required in ('SEC-01', 'SEC-02', 'SEC-04', 'SEC-05', 'SEC-07',
                              'SEC-14', 'SEC-15', 'PRO-03') for backend in BACKENDS}
DEMOTIONS.add(('SEC-13', 'complete-requirement', 'gao_bus', 'core'))


def identity(value):
    return tuple(value[key] for key in ('required_id', 'subcase_id', 'backend', 'profile'))


def local(root, name):
    relative = PurePosixPath(name)
    assert isinstance(name, str) and name == relative.as_posix()
    assert not relative.is_absolute() and relative.parts
    assert all(part not in ('.', '..') for part in relative.parts)
    path = root
    for part in relative.parts:
        path = path / part
        assert not path.is_symlink(), path
    return path


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def main():
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError('Run with -B and without Python optimization so provenance checks remain enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--inputs-sha256', required=True)
    args = parser.parse_args()
    checked = {}

    def read(path, digest=None):
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode), path
        data = path.read_bytes()
        pin = dict(bytes=len(data), mode=stat.S_IMODE(metadata.st_mode),
                   sha256=hashlib.sha256(data).hexdigest())
        if digest is not None:
            assert isinstance(digest, str) and len(digest) == 64
            assert all(character in '0123456789abcdef' for character in digest)
            assert pin['sha256'] == digest, path
        assert path not in checked or checked[path] == pin, path
        checked[path] = pin
        return data

    def load(path, digest=None):
        def unique(pairs):
            value = {}
            for key, item in pairs:
                assert key not in value, key
                value[key] = item
            return value
        return json.loads(read(path, digest), object_pairs_hook=unique)

    helper = Path(__file__).absolute()
    read(helper)
    inputs_path = local(ROOT, args.inputs)
    inputs = load(inputs_path, args.inputs_sha256)
    assert set(inputs) == {'records', 'fixture'} and set(inputs['records']) == RECORDS
    assert inputs['fixture'] == FIXTURE
    references, paths, records = {}, {}, {}
    for name, reference in inputs['records'].items():
        assert set(reference) == {'path', 'sha256'}, name
        path = local(ROOT, reference['path'])
        references[name], paths[name] = reference, path
        records[name] = (read(path, reference['sha256']).decode() if name == 'build_stdout'
                         else load(path, reference['sha256']))
    for name, digest in [('report', REPORT_SHA), ('vmoff', VMOFF_SHA),
                         ('artifact', ARTIFACT_SHA), ('baseline_index', BASELINE_SHA)]:
        assert references[name]['sha256'] == digest
    assert paths['acceptance'] == ROOT / RESUME / 'pro05-core-runtime-acceptance1.json'
    report, artifact = records['report'], records['artifact']
    selected = [SCENARIO + '/' + backend + '/core' for backend in BACKENDS]
    assert report['selected'] == selected and report['counts'] == COUNTS
    assert report['scenario'] == SCENARIO and report['profile'] == 'core'
    assert report['result'] == 'passed_complete_core_PRO05_runtime_pending_independent_review'
    assert report['readiness'] == 'L0'
    assert all(report[key] is False for key in ('runtime_qualification', 'requirement_qualification',
                                              'accepted_index_mutation', 'product_qualified'))
    assert report['artifact'] == artifact and artifact['not_a_release'] is True
    assert artifact['origin_pin']['sha256'] == ORIGIN_SHA
    assert report['candidate_artifact_sha256'] == ARTIFACT_SHA
    assert report['candidate_source_sha256'] == SOURCE_SHA
    assert hashlib.sha256(json.dumps(artifact['sources'], sort_keys=True).encode()).hexdigest() == SOURCE_SHA
    assert len(artifact['sources']) == 71 and len(artifact['files']) == 80
    for name, pin in artifact['sources'].items():
        path = local(ROOT, name)
        read(path, pin['sha256'])
        assert checked[path] == pin, path
    candidate = paths['artifact'].parent
    assert {path.relative_to(candidate).as_posix() for path in (candidate / 'lib').rglob('*')
            if path.is_file()} == set(artifact['files'])
    for name, pin in artifact['files'].items():
        assert name.startswith('lib/')
        path = local(candidate, name)
        read(path, pin['sha256'])
        assert checked[path] == pin, path

    fixture = Path(FIXTURE)
    assert not fixture.is_symlink() and fixture.is_dir()
    assert all(not path.is_symlink() for path in fixture.iterdir())
    fixture_files = {path.name for path in fixture.iterdir() if path.is_file()}
    assert fixture_files == set(report['fixture_pins']) and len(fixture_files) == 26
    for name, pin in report['fixture_pins'].items():
        frozen, source = local(fixture, name), local(ROOT, SOURCE + '/' + name)
        read(frozen, pin['sha256'])
        read(source, pin['sha256'])
        assert checked[frozen] == pin and pin['mode'] & 0o222 == 0
        assert dict(checked[source], mode=checked[source]['mode'] & ~0o222) == pin
    assert checked[ROOT / SOURCE / 'contract.py']['sha256'] == CONTRACT_SHA
    runner = ROOT / SOURCE / 'run.py'
    runner_text = read(runner, RUN_SHA).decode()
    assert EXCERPT in runner_text and ASSERTION in runner_text
    bindings = load(fixture / 'bindings.json')
    assert bindings == report['bindings'] and bindings['artifact_sha256'] == ARTIFACT_SHA
    assert bindings['runtime_manifest_sha256'] == ORIGIN_SHA
    assert bindings['profiles_prepared'] == ['core'] and bindings['network_profile_prepared'] is False
    for name, pin in bindings['helpers'].items():
        path = local(ROOT, name)
        read(path, pin['sha256'])
        assert checked[path] == pin

    build, build_started = records['build_result'], records['build_started']
    started, lifecycle = records['started'], records['lifecycle']
    assert build['returncode'] == 0 and build['inputs_match'] is True and build['vm_invocations'] == 0
    assert all(build[key] == value for key, value in build_started.items())
    assert build['input_sha256'] == started['input_sha256']
    for name, digest in started['input_sha256'].items():
        read(local(ROOT, name), digest)
    driver = records['build_stdout'].strip()
    assert driver.startswith('/nix/store/') and driver.endswith('-nixos-test-driver-os-bus-foundation-pro05-complete-core')
    assert started['argv'] == [driver + '/bin/nixos-test-driver', '--no-interactive', '-o',
                               str(paths['started'].parent / 'out'), '--junit-xml',
                               str(paths['started'].parent / 'junit.xml')]
    assert started['cwd'] == build['cwd'] == str(ROOT)
    assert lifecycle['returncode'] == 0 and lifecycle['status'] == 'passed_host_graceful'
    assert lifecycle['timed_out'] is False and lifecycle['containment'] == []
    assert all(lifecycle[key] is True for key in ('leader_reaped', 'pid_absent', 'group_absent',
                                                 'inputs_match', 'graceful_success'))
    assert lifecycle['monitor_errors'] == lifecycle['input_errors'] == []
    assert records['vmoff'] == dict(VMoff=True, socket_removed=True)
    validation, validation_started = records['validation_result'], records['validation_started']
    assert validation['returncode'] == 0 and validation['inputs_match'] is True
    assert all(validation[key] == value for key, value in validation_started.items())
    assert validation['cwd'] == str(ROOT)
    argv = validation['argv']
    assert len(argv) == 17 and argv[:3] == [
        '/nix/store/xqnbm0vgqcq9b1b54c80qj9s0qhbwa08-python3-3.13.15/bin/python3.13',
        '-B', SOURCE + '/validate_saved.py']
    assert argv[3:] == ['--report', str(paths['report']), '--report-sha256', REPORT_SHA,
                        '--vmoff', str(paths['vmoff']), '--vmoff-sha256', VMOFF_SHA,
                        '--repository', str(ROOT), '--candidate', str(candidate), '--fixture', FIXTURE]
    for name, digest in validation['source_sha256'].items():
        path = Path(name)
        assert path.is_relative_to(ROOT)
        read(local(ROOT, path.relative_to(ROOT).as_posix()), digest)
    acceptance = records['acceptance']
    assert acceptance['decision'] == 'ACCEPTED_PRO05_COMPLETE_CORE_RUNTIME'
    assert acceptance['selected'] == selected and acceptance['counts'] == COUNTS
    assert acceptance['report_sha256'] == REPORT_SHA and acceptance['vmoff_sha256'] == VMOFF_SHA
    assert acceptance['candidate_artifact_sha256'] == ARTIFACT_SHA
    assert acceptance['candidate_source_sha256'] == SOURCE_SHA
    assert acceptance['catalogue_invariant'] == INVARIANT and acceptance['log_failures'] == 0

    original = records['baseline_index']
    proposed = deepcopy(original)
    assert original['index_schema'] == original['catalogue_version'] == 1
    assert 'counts' not in original and len(original['rows']) == 426
    assert len({identity(row) for row in original['rows']}) == 426
    demoted = set()
    for row in proposed['rows']:
        ref = row['record_ref']
        if ref is None:
            continue
        assert identity(row) in DEMOTIONS
        old = load(local(ROOT, ref['path']), ref['sha256'])
        observation = old['observations'][ref['selector']]
        assert identity(observation) == identity(row) and old['currency'] == 'current'
        assert observation['status'] == 'passed'
        old_sources = [binding for binding in old['bindings'] if binding['kind'] == 'source']
        assert len(old_sources) == 71
        assert {binding['path'] for binding in old_sources
                if artifact['sources'][binding['path']]['sha256'] != binding['sha256']} == DRIFT
        row['retained_evidence'].append(dict(
            path=ref['path'], sha256=ref['sha256'], selector=['observations', ref['selector']],
            value=observation, currency='historical', disposition='historical', run_id=old['run_id'],
            reason='Executed old-candidate evidence preserved; artifact712d changes Message, Runtime and Peer sources. This historical observation does not qualify the current candidate.'))
        row.update(record_ref=None, source_scenario_id=None, block=dict(kind='candidate_changed',
                   reason='Current artifact/source changed; fresh complete execution is required. Existing retained failures remain failed.'))
        demoted.add(identity(row))
    assert demoted == DEMOTIONS and len(demoted) == 17

    outputs = {}

    def output(name, value):
        data = encoded(value)
        outputs[name] = data
        return dict(path=OUTPUT + '/' + name, sha256=hashlib.sha256(data).hexdigest())

    def binding(path, kind):
        digest = checked[path]['sha256']
        return dict(path=path.relative_to(ROOT).as_posix(), kind=kind, sha256=digest,
                    before_sha256=digest, after_sha256=digest)

    assert [backend['backend'] for backend in report['backends']] == list(BACKENDS)
    for backend in report['backends']:
        name = backend['backend']
        assert backend['status'] == 'passed_pending_independent_review'
        assert backend['invariant_measurement'] == EXPECTED
        assert backend['shutdown_errors'] == [] and backend['endpoint_removed'] is True
        retirement = backend['daemon_retirement']
        assert retirement['returncode'] == 0 and retirement['pid_absent'] is retirement['group_absent'] is True
        key = ('PRO-05', 'complete-requirement', name, 'core')
        row, = [row for row in proposed['rows'] if identity(row) == key]
        assert row['record_ref'] is None and row['retained_evidence'] == []
        assert row['coverage_scope'] == SCENARIO
        assert row['requirements'] == dict(layer='independent-system', actors=ACTORS, invariants=[INVARIANT])
        fields = dict(zip(('required_id', 'subcase_id', 'backend', 'profile'), key))
        run_id = 'pro05-vm9-' + name + '-' + RUN_SHA[:16] + '-' + REPORT_SHA[:16]
        witness = dict(fields, coverage_scope=SCENARIO, source_scenario_id=SCENARIO, run_id=run_id,
                       invariant=INVARIANT, source_sha256=RUN_SHA, executed=True,
                       actor='independent_client', assertion_source=ASSERTION,
                       expected=deepcopy(EXPECTED), actual=backend['invariant_measurement'], status='passed',
                       raw_qualification=checked[paths['report']], backend_selector=name,
                       root_runtime_acceptance=references['acceptance'])
        witness_ref = output('ASSERTION_WITNESS1-' + name + '.json', witness)
        config_name = 'reference.conf' if name == 'reference' else 'policy.exs'
        config_path = ROOT / SOURCE / config_name
        config = checked[config_path]['sha256']
        assert backend['configuration']['sha256'] == config
        receipt_bindings = [binding(config_path, 'config')]
        receipt_bindings += [binding(ROOT / path, 'source') for path in artifact['sources']]
        receipt_bindings += [binding(runner, 'test')]
        receipt_bindings += [binding(ROOT / SOURCE / path, 'fixture') for path in sorted(fixture_files)
                             if path not in (config_name, 'run.py')]
        receipt_bindings += [binding(ROOT / path, 'fixture') for path in sorted(bindings['helpers'])]
        assert len(backend['actors']) == 38
        observer, client = backend['actors'][:2]
        assert observer['identity'] == backend['observer']['identity']
        actor_receipts = []
        for role, actor, uid in [('external_observer', observer, 1100), ('independent_client', client, 1101)]:
            assert actor['identity']['uid'] == uid and actor['identity']['pid'] > 0
            actor_receipts.append(dict(actor=role, backend=name, profile='core', executed=True,
                pid=actor['identity']['pid'], uid=uid, config_sha256=config,
                primary_kernel_status=actor['proc_status'], additional_incarnations=[item for item in backend['actors']
                    if item['identity']['uid'] == uid and item['identity'] != actor['identity']]))
        source_ref = dict(path=SOURCE + '/run.py', sha256=RUN_SHA,
                          binding_path=SOURCE + '/run.py', excerpt=EXCERPT)
        observation = dict(fields, coverage_scope=SCENARIO, source_scenario_id=SCENARIO, status='passed',
                           actors_executed=ACTORS, source_ref=source_ref,
                           assertions=[dict(invariant=INVARIANT, record_ref=dict(witness_ref, selector=[]))])
        receipt = dict(currency='current', scope='independent-system', run_id=run_id,
            identity=dict(backend=name, profile='core', actors=ACTORS),
            backend_receipt=dict(backend=name, profile='core', pid=backend['daemon']['identity']['pid'],
                                 version=backend['daemon']['version'], config_sha256=config, independent=True),
            actor_receipts=actor_receipts, bindings=receipt_bindings, observations=[observation],
            counts=dict(selected=1, executed=1, passed=1, failed=0, blocked=0, skipped=0),
            command=dict(argv=started['argv'], cwd=started['cwd'], exit=lifecycle['returncode'],
                         teardown_exit=retirement['returncode'], log_failures=acceptance['log_failures']),
            supporting_evidence=dict(references, backend_selector=name, candidate_artifact_sha256=ARTIFACT_SHA,
                                     candidate_source_sha256=SOURCE_SHA,
                                     adoption_helper=dict(path=helper.relative_to(ROOT).as_posix(),
                                                          sha256=checked[helper]['sha256']),
                                     adoption_inputs=dict(path=args.inputs, sha256=args.inputs_sha256)),
            product_qualified=False, readiness='L0')
        receipt_ref = output('COMPLETE_ROW_RECEIPT1-' + name + '.json', receipt)
        row.update(record_ref=dict(receipt_ref, selector=0), source_scenario_id=SCENARIO, block=None)

    targets = {('PRO-05', 'complete-requirement', backend, 'core') for backend in BACKENDS}
    for before, after in zip(original['rows'], proposed['rows']):
        assert set(before) == set(after)
        assert identity(before) == identity(after)
        assert before['requirements'] == after['requirements'] and before['coverage_scope'] == after['coverage_scope']
        assert after['retained_evidence'][:len(before['retained_evidence'])] == before['retained_evidence']
        changed = {key for key in before if before[key] != after[key]}
        if identity(before) in demoted:
            assert changed == {'record_ref', 'source_scenario_id', 'block', 'retained_evidence'}
            assert len(after['retained_evidence']) == len(before['retained_evidence']) + 1
        elif identity(before) in targets:
            assert changed == {'record_ref', 'source_scenario_id', 'block'}
            assert after['retained_evidence'] == before['retained_evidence']
        else:
            assert before == after
    proposed['notes'] = original.get('notes', []) + [
        'Current artifact712d/source51e6: seventeen old current core references retained as historical; only two root-accepted PRO05 core observations newly mapped. Network PRO05 stays blocked; readiness L0; no product qualification.']
    index_ref = output('REQUIRED_EVIDENCE_INDEX.json', proposed)
    for path, pin in list(checked.items()):
        read(path, pin['sha256'])
        assert checked[path] == pin, path
    destination = local(ROOT, OUTPUT)
    assert destination.parent.is_dir() and not destination.exists()
    destination.mkdir()
    for name, data in outputs.items():
        with (destination / name).open('xb') as target:
            target.write(data)
    print(json.dumps(dict(status='PREPARED_EXISTING_SCHEMA_PRO05_CORE_INDEX_PENDING_CONSUMERS',
        proposed_index=index_ref, prepared_receipts=2, prepared_witnesses=2,
        historical_demotions=17, unchanged_other_combinations=407,
        product_qualified=False, readiness='L0', new_vm_executions=0, consumer_execution='NOT RUN'), sort_keys=True))


if __name__ == '__main__':
    main()
