"""Prepare existing-schema SEC03 core evidence from root-accepted VM1 saved data.

Invoke with -B, --inputs REPOSITORY_RELATIVE_JSON and --inputs-sha256 SHA256.
Inputs: {"fixture": FIXTURE, "records": {NAME: {"path": RELATIVE, "sha256": SHA256}}}.
The twelve record names are RECORDS below. No fixture import, command, consumer,
or target execution occurs. Outputs remain proposals pending root validation.
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
OUTPUT = RESUME + '/sec03-adoption1'
HISTORICAL = ('test/reports/foundation/continuation-20261011-full-goal/environment/'
              'm1-sec03-complete1/source7')
FIXTURE = '/nix/store/pbxys7xfvhsj9acl1909qscigvm1wqzk-osbus-authentication-current-inputs/fixtures'
CANDIDATE = '/nix/store/rzxfgq32pxd260za71r7qgv45s771wsv-osbus-authorization-current-inputs/candidate'
SCENARIO = 'SEC-03/complete-requirement'
INVARIANT = 'Valid standard flows remain valid; bad assertions never grant identity or crash the daemon.'
BACKENDS = ('reference', 'gao_bus')
ACTORS = ['independent_client', 'external_observer']
COUNTS = dict(selected=2, executed=2, passed=1, failed=1, blocked=0, skipped=0)
REPORT_SHA = 'de6fb24838bea132befac541de45ea8d80373216d838e46f4bc8f7fb2815764e'
BASELINE_SHA = '3d5d2507ad0bf66cf8b0cb0b243c09750fdef62ae0a26c7814a97af7cf4134e0'
ARTIFACT_SHA = '712d86ed1b2439909b3942edbae475043935e31fdc1c2519261d9df7163c099b'
RUNTIME_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
MANIFEST_SHA = '750247535e499f560db490184f060211338c5d28b64fd1c944468195b29adb90'
SOURCE_SHA = '33c7e8efd78adf0120c031554f03240524cef883f899763c8a2cd5f516cf374a'
CORPUS_SHA = '092fb09ada4d49e4cc5644b64562fd45b8a19097e0a6d60b8fdda304b4c679b9'
RUN_SHA = '767eb64b9c38907e20af36694d5388ea1dda0e7f7b0d66222df8c3d21168dec2'
CONTRACT_SHA = '92f5ae5af9a75b04ecac605c480110f624a794ecf98a554518dbf7b22849c22a'
VMOFF_SHA = 'd26a2518348e812ec3f3516fc95c0a636194a2546856787d82080ee90028624e'
RECORDS = {'report', 'vmoff', 'lifecycle', 'started', 'build_result', 'build_started',
           'build_stdout', 'artifact', 'runtime', 'acceptance', 'bindings', 'baseline_index'}
EXCERPT = '# SCENARIO = SEC-03/complete-requirement'
ASSERTION = "assert current['invariant_measurement']==invariant_actual(current)"
# Literal transcription of expected_invariant(), independent of either result.
EXPECTED = dict(all51_original_exchanges=True, normative_valid_flows_and_numeric_meaning=True,
                original_kernel_identity_preserved=True, no_privileged_ownership_or_delivery=True,
                authorized_controls_before_after=True, observer_incarnation_connection_epoch_preserved=True,
                same_stream_or_distinct_terminal_recovery=True,
                complete_state_serial_and_native_fds_recovered=True)
ASSIGNMENTS = [
    ("MANIFEST_SHA='372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7'",
     "MANIFEST_SHA='" + MANIFEST_SHA + "'"),
    ("SOURCE_SHA='efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9'",
     "SOURCE_SHA='" + SOURCE_SHA + "'")]


def require(condition, detail):
    if not condition:
        raise ValueError(str(detail))


def identity(value):
    return tuple(value[key] for key in ('required_id', 'subcase_id', 'backend', 'profile'))


def local(root, name):
    require(isinstance(name, str), 'path must be a string')
    relative = PurePosixPath(name)
    require(name == relative.as_posix() and not relative.is_absolute() and relative.parts
            and all(part not in ('.', '..') for part in relative.parts), name)
    path = root
    require(not root.is_symlink(), root)
    for part in relative.parts:
        path = path / part
        require(not path.is_symlink(), path)
    return path


def store(name):
    require(isinstance(name, str) and name.startswith('/nix/store/'), name)
    return local(Path('/'), name[1:])


def leaves(root):
    require(root.is_dir() and not root.is_symlink(), root)
    paths = list(root.rglob('*'))
    require(all(not path.is_symlink() for path in paths), root)
    return {path.relative_to(root).as_posix() for path in paths if path.is_file()}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def main():
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError('Run with -B and without Python optimization')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--inputs-sha256', required=True)
    args = parser.parse_args()
    checked = {}

    def read(path, digest=None):
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode), path)
        data = path.read_bytes()
        pin = dict(bytes=len(data), mode=stat.S_IMODE(metadata.st_mode),
                   sha256=hashlib.sha256(data).hexdigest())
        if digest is not None:
            require(isinstance(digest, str) and len(digest) == 64
                    and all(c in '0123456789abcdef' for c in digest), 'invalid digest')
            require(pin['sha256'] == digest, path)
        require(path not in checked or checked[path] == pin, 'changed input: ' + str(path))
        checked[path] = pin
        return data

    def load(path, digest=None):
        def unique(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, 'duplicate JSON key: ' + key)
                value[key] = item
            return value
        return json.loads(read(path, digest), object_pairs_hook=unique)

    helper = local(ROOT, Path(__file__).absolute().relative_to(ROOT).as_posix())
    read(helper)
    inputs = load(local(ROOT, args.inputs), args.inputs_sha256)
    require(set(inputs) == {'records', 'fixture'} and set(inputs['records']) == RECORDS, 'input schema')
    require(inputs['fixture'] == FIXTURE, 'fixture path')
    references, paths, records = {}, {}, {}
    for name, reference in inputs['records'].items():
        require(set(reference) == {'path', 'sha256'}, name)
        path = local(ROOT, reference['path'])
        references[name], paths[name] = reference, path
        records[name] = (read(path, reference['sha256']).decode() if name == 'build_stdout'
                         else load(path, reference['sha256']))
    for name, digest in [('report', REPORT_SHA), ('baseline_index', BASELINE_SHA),
                         ('artifact', ARTIFACT_SHA), ('runtime', RUNTIME_SHA), ('vmoff', VMOFF_SHA)]:
        require(references[name]['sha256'] == digest, name)
    fixed = dict(report=RESUME + '/runtime-authentication/vm1/out/authentication-current-evidence/sec03-complete/qualification.json',
                 acceptance=RESUME + '/sec03-core-runtime-acceptance1.json',
                 baseline_index=RESUME + '/pro05-adoption1/REQUIRED_EVIDENCE_INDEX.json',
                 bindings=RESUME + '/runtime-authentication/vm1/out/authentication-current-evidence/sec03-complete/current-bindings.json')
    for name, path in fixed.items():
        require(references[name]['path'] == path, name + ' path')
    report, artifact, runtime, bindings = (records[n] for n in ('report', 'artifact', 'runtime', 'bindings'))
    selected = [dict(requirement=SCENARIO, backend=b, profile='core', execution='independent-system', actors=ACTORS)
                for b in BACKENDS]
    require(report['selected'] == selected and report['counts'] == COUNTS, 'selected/counts')
    require(report['collection_complete'] is True and report['corpus_pairs'] == 102, 'collection')
    require(report['readiness'] == 'L0' and all(report[k] is False for k in
            ('accepted_index_mutation', 'requirement_qualification', 'product_qualified')), 'qualification boundary')
    require(report['candidate_manifest_sha256'] == MANIFEST_SHA
            and report['candidate_source_sha256'] == SOURCE_SHA, 'report candidate')
    manifest = load(store(CANDIDATE) / 'candidate.json', MANIFEST_SHA)
    require(report['candidate'] == manifest == bindings['candidate_manifest'], 'candidate equality')
    require(artifact['not_a_release'] is runtime['not_a_release'] is manifest['not_a_release'] is True,
            'not a release')
    require(artifact['origin_pin']['sha256'] == RUNTIME_SHA and manifest['runtime'] == runtime['runtime'], 'runtime')
    require(len(artifact['sources']) == 71 and len(artifact['files']) == 80, 'artifact cardinality')
    sources = {name: pin['sha256'] for name, pin in artifact['sources'].items()}
    require(manifest['sources'] == sources and set(sources) == set(runtime['sources']), 'source set')
    require(hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest() == SOURCE_SHA
            and manifest['source_sha256'] == SOURCE_SHA, 'source digest')
    require(manifest['source_beams'] == runtime['source_beams'], 'source beam mapping')
    require(manifest['files'] == {n: p['sha256'] for n, p in artifact['files'].items()}
            and manifest['file_modes'] == {n: p['mode'] for n, p in artifact['files'].items()}, 'runnable pins')
    for name, pin in artifact['sources'].items():
        path = local(ROOT, name)
        read(path, pin['sha256'])
        require(checked[path] == pin, path)
    for candidate, immutable in [(paths['artifact'].parent, False), (store(CANDIDATE), True),
                                 (store(bindings['candidate_store']), True),
                                 (store(bindings['artifact_store']), True)]:
        metadata_name = 'artifact.json' if candidate in (paths['artifact'].parent, store(bindings['artifact_store'])) else 'candidate.json'
        require(leaves(candidate) == set(artifact['files']) | {metadata_name}, candidate)
        read(candidate / metadata_name, ARTIFACT_SHA if metadata_name == 'artifact.json' else MANIFEST_SHA)
        for name, pin in artifact['files'].items():
            require(name.startswith('lib/'), name)
            path = local(candidate, name)
            read(path, pin['sha256'])
            require(checked[path] == dict(pin, mode=pin['mode'] & ~0o222) if immutable else checked[path] == pin, path)
    read(store(bindings['runtime_store']), RUNTIME_SHA)
    corpus = load(local(ROOT, HISTORICAL + '/SOURCE_MANIFEST1.json'), CORPUS_SHA)
    require(load(store(bindings['corpus_store']), CORPUS_SHA) == corpus, 'corpus copy')
    require(corpus['cases'] == 51 and corpus['pairs'] == 102, 'corpus counts')
    fixture = store(FIXTURE)
    fixture_names = set(report['fixture_pins'])
    require(leaves(fixture) == fixture_names == set(corpus['fixture_files'])
            == set(bindings['fixture_inputs']) and len(fixture_names) == 27, 'fixture set')
    fixture_bytes = {}
    for name in sorted(fixture_names):
        original = local(ROOT, HISTORICAL + '/fixture1/' + name)
        frozen_original = local(store(bindings['fixtures_store']), name)
        old_pin = bindings['fixture_inputs'][name]
        read(original, old_pin['sha256'])
        require(dict(checked[original], mode=checked[original]['mode'] & ~0o222) == old_pin, original)
        old_data = read(frozen_original, old_pin['sha256'])
        require(checked[frozen_original] == old_pin, frozen_original)
        path = local(fixture, name)
        fixture_bytes[name] = read(path, report['fixture_pins'][name])
        expected_pin = bindings['patched_contract'] if name == 'contract.py' else old_pin
        require(checked[path] == expected_pin and expected_pin['mode'] & 0o222 == 0, path)
        if name == 'contract.py':
            patched = old_data
            for before, after in ASSIGNMENTS:
                require(patched.count(before.encode()) == 1 and after.encode() not in patched, 'contract assignment')
                patched = patched.replace(before.encode(), after.encode())
            require(patched == fixture_bytes[name] and checked[path]['sha256'] == CONTRACT_SHA, 'only two assignments')
            restored = patched
            for before, after in reversed(ASSIGNMENTS):
                restored = restored.replace(after.encode(), before.encode())
            require(restored == old_data, 'reversible contract')
        else:
            require(fixture_bytes[name] == old_data, path)
    require(checked[fixture / 'run.py']['sha256'] == RUN_SHA, 'runner pin')
    require(EXCERPT in fixture_bytes['run.py'].decode() and ASSERTION in fixture_bytes['run.py'].decode(), 'assertion source')
    require(bindings['artifact_sha256'] == ARTIFACT_SHA and bindings['runtime_sha256'] == RUNTIME_SHA
            and bindings['candidate_manifest_sha256'] == MANIFEST_SHA
            and bindings['candidate_source_sha256'] == SOURCE_SHA
            and bindings['fixture_files_unchanged'] == 26 and bindings['runnable_files_unchanged'] == 80,
            'adapter bindings')
    adapter = local(ROOT, 'scripts/foundation/authentication_current/normalize.py')
    read(adapter, bindings['adapter']['sha256'])
    require(dict(checked[adapter], mode=checked[adapter]['mode'] & ~0o222) == bindings['adapter'], 'adapter pin')

    build, build_started, started, lifecycle = (records[n] for n in ('build_result', 'build_started', 'started', 'lifecycle'))
    require(build['returncode'] == 0 and build['inputs_match'] is True and build['vm_invocations'] == 0, 'build result')
    require(all(build[k] == v for k, v in build_started.items()), 'build started/result')
    require(build['input_sha256'] == started['input_sha256'], 'build/runtime inputs')
    for name, digest in started['input_sha256'].items():
        read(local(ROOT, name), digest)
    recovered_runner = local(ROOT, RESUME + '/runtime-authentication/build1-runner-reconstructed.py')
    read(recovered_runner, build['runner_sha256'])
    read(local(ROOT, RESUME + '/runtime-authentication/run-vm.py'), started['runner_sha256'])
    read(local(ROOT, RESUME + '/runtime-authentication/vm1/runner.py'), started['runner_sha256'])
    driver = records['build_stdout'].strip()
    require(driver.startswith('/nix/store/') and driver.endswith('-nixos-test-driver-os-bus-foundation-authentication-current'), 'driver')
    require(started['argv'] == [driver + '/bin/nixos-test-driver', '--no-interactive', '-o',
            str(paths['started'].parent / 'out'), '--junit-xml', str(paths['started'].parent / 'junit.xml')], 'VM argv')
    require(started['cwd'] == build['cwd'] == str(ROOT), 'working directory')
    require(lifecycle['returncode'] == 0 and lifecycle['status'] == 'passed_host_graceful'
            and lifecycle['timed_out'] is False and lifecycle['containment'] == [], 'VM lifecycle')
    require(all(lifecycle[k] is True for k in ('leader_reaped', 'pid_absent', 'group_absent', 'inputs_match', 'graceful_success'))
            and lifecycle['monitor_errors'] == lifecycle['input_errors'] == [], 'VM cleanup')
    require(records['vmoff'] == dict(VMoff=True, socket_removed=True), 'VMoff')
    acceptance = records['acceptance']
    require(acceptance['decision'] == 'ACCEPTED_SEC03_CORE_COLLECTION_GAO_PASS_REFERENCE_FAILED', 'root decision')
    require(acceptance['report'] == references['report'] and acceptance['vmoff'] == references['vmoff']
            and acceptance['counts'] == COUNTS, 'root raw evidence')
    require(acceptance['candidate_artifact_sha256'] == ARTIFACT_SHA
            and acceptance['candidate_manifest_sha256'] == MANIFEST_SHA
            and acceptance['candidate_source_sha256'] == SOURCE_SHA
            and acceptance['readiness'] == 'L0' and acceptance['product_qualified'] is False, 'root boundary')

    original = records['baseline_index']
    proposed = deepcopy(original)
    require(original['index_schema'] == original['catalogue_version'] == 1
            and 'counts' not in original and len(original['rows']) == 426
            and len({identity(row) for row in original['rows']}) == 426, 'index schema')
    outputs = {}

    def output(name, value):
        data = encoded(value)
        outputs[name] = data
        return dict(path=OUTPUT + '/' + name, sha256=hashlib.sha256(data).hexdigest())

    def binding(name, kind, digest):
        return dict(path=name, kind=kind, sha256=digest, before_sha256=digest, after_sha256=digest)

    require([b['backend'] for b in report['backends']] == list(BACKENDS), 'backend order')
    require([b['backend'] for b in acceptance['observations']] == list(BACKENDS), 'acceptance order')
    for backend, accepted in zip(report['backends'], acceptance['observations']):
        name = backend['backend']
        failed = name == 'reference'
        status, gate_exit = ('failed', 1) if failed else ('passed', 0)
        actual = deepcopy(EXPECTED)
        actual['normative_valid_flows_and_numeric_meaning'] = not failed
        require(backend['invariant_measurement'] == actual and accepted['invariant_measurement'] == actual, 'measured invariant')
        require(backend['status'] == accepted['status'] == ('failed_conformance' if failed else 'passed'), 'backend status')
        require(len(backend['cases']) == accepted['cases'] == 51
                and sum(c['normative']['status'] == 'passed' for c in backend['cases']) == accepted['passed'] == (39 if failed else 51)
                and len(backend['failures']) == accepted['failed'] == (12 if failed else 0), 'case outcomes')
        require(len(backend['actors']) == len(backend['retirements']) == accepted['actors'] == accepted['retirements']
                == (90 if failed else 94), 'actor counts')
        require(backend['shutdown_errors'] == [] and backend['socket_removed'] is True, 'endpoint cleanup')
        gate = backend['gate_command']
        require(gate['exit'] == accepted['gate_exit'] == gate_exit and gate['natural'] is True
                and gate['pid_absent'] is True and gate['timed_out'] is False
                and gate['containment'] == gate['group_members'] == [], 'gate outcome')
        require(gate['cwd'] == FIXTURE and gate['argv'][2] == FIXTURE + '/run.py'
                and gate['argv'][3] == bindings['candidate_store'] and gate['argv'][5] == '/run/osbus-security/sec03-complete'
                and gate['argv'][6] == name, 'gate inputs')
        gate_stdout = local(ROOT, paths['report'].parent.relative_to(ROOT).as_posix() + '/' + name + '-gate.stdout.log')
        gate_summary = load(gate_stdout)
        require(gate_summary == dict(backend=name, status=backend['status'], cases=51,
                failed_observations=backend['failures']), 'observed gate output')
        shutdown = backend['daemon_shutdown']
        require(shutdown['returncode'] == 0 and shutdown['pid_absent'] is shutdown['group_absent'] is True, 'daemon cleanup')
        for retirement in backend['retirements']:
            retired = retirement['shutdown']
            require(retired['returncode'] == 0 and retired['pid_absent'] is retired['group_absent'] is retired['actor_pid_absent'] is True,
                    'actor cleanup')
        key = ('SEC-03', 'complete-requirement', name, 'core')
        rows = [row for row in proposed['rows'] if identity(row) == key]
        require(len(rows) == 1, key)
        row = rows[0]
        require(row['record_ref'] is None and row['source_scenario_id'] is None and row['block'] is not None, 'unmapped SEC03')
        require(row['coverage_scope'] == SCENARIO and row['requirements'] ==
                dict(layer='independent-system', actors=ACTORS, invariants=[INVARIANT]), 'row requirements')
        retained, = row['retained_evidence']
        require(retained['path'] == HISTORICAL + '/COMPLETE_ROW_RECEIPT1-' + name + '.json', 'retained template')
        template = load(local(ROOT, retained['path']), retained['sha256'])
        require(template['observations'][0] == retained['value'] and retained['currency'] == 'historical'
                and retained['disposition'] == ('failed' if failed else 'historical'), 'retained evidence')
        old_assertion = template['observations'][0]['assertions'][0]['record_ref']
        witness = load(local(ROOT, old_assertion['path']), old_assertion['sha256'])
        require(witness['expected'] == EXPECTED and witness['source_sha256'] == RUN_SHA, 'template expectation')
        run_id = 'sec03-current-vm1-' + name + '-' + RUN_SHA[:16] + '-' + REPORT_SHA[:16]
        witness.pop('raw_review', None)
        witness.update(run_id=run_id, expected=deepcopy(EXPECTED), actual=backend['invariant_measurement'],
                       status=status, raw_qualification=checked[paths['report']],
                       root_runtime_acceptance=references['acceptance'])
        witness_ref = output('ASSERTION_WITNESS1-' + name + '.json', witness)
        config_name = 'reference.conf' if failed else 'policy.exs'
        config = report['fixture_pins'][config_name]
        require(backend['configuration']['sha256'] == config
                and hashlib.sha256(backend['configuration']['bytes'].encode()).hexdigest() == config, 'configuration')
        receipt_bindings = [binding(OUTPUT + '/fixture/' + config_name, 'config', config)]
        receipt_bindings += [binding(n, 'source', p['sha256']) for n, p in artifact['sources'].items()]
        receipt_bindings += [binding(OUTPUT + '/fixture/run.py', 'test', RUN_SHA)]
        receipt_bindings += [binding(OUTPUT + '/fixture/' + n, 'fixture', report['fixture_pins'][n])
                             for n in sorted(fixture_names) if n not in (config_name, 'run.py')]
        observer, client = backend['observer'], backend['cases'][0]['actor']
        actor_receipts = []
        require(observer['identity']['pid'] != client['identity']['pid'], 'distinct actors')
        for role, actor in [('external_observer', observer), ('independent_client', client)]:
            require(any(all(saved.get(k) == v for k, v in actor.items()) for saved in backend['actors'])
                    and actor['identity']['uid'] == 1100
                    and actor['identity']['pid'] > 0 and actor['starttime_ticks'] > 0, 'actor identity')
            actor_receipts.append(dict(actor=role, backend=name, profile='core', executed=True,
                pid=actor['identity']['pid'], uid=actor['identity']['uid'], config_sha256=config,
                starttime_ticks=actor['starttime_ticks'], primary_kernel_status=actor['proc_status']))
        receipt = deepcopy(template)
        observation = receipt['observations'][0]
        observation.update(status=status, source_ref=dict(path=OUTPUT + '/fixture/run.py',
            binding_path=OUTPUT + '/fixture/run.py', sha256=RUN_SHA, excerpt=EXCERPT),
            assertions=[dict(invariant=INVARIANT, record_ref=dict(witness_ref, selector=[]))])
        if failed:
            version = 'dbus-daemon 1.14.10 pinned executable ' + backend['reference_executable']['sha256']
            read(store(backend['reference_executable']['path']), backend['reference_executable']['sha256'])
        else:
            version = 'Elixir ' + backend['ready']['elixir'] + '; ' + backend['ready']['otp'].strip()
        receipt.update(currency='current', run_id=run_id, bindings=receipt_bindings, actor_receipts=actor_receipts,
            backend_receipt=dict(backend=name, profile='core', pid=backend['daemon']['identity']['pid'],
                                 config_sha256=config, independent=True, version=version),
            counts=dict(selected=1, executed=1, passed=int(not failed), failed=int(failed), blocked=0, skipped=0),
            command=dict(argv=gate['argv'], cwd=gate['cwd'], exit=gate_exit,
                         teardown_exit=shutdown['returncode'], log_failures=len(gate_summary['failed_observations'])),
            supporting_evidence=dict(references, backend_selector=name, candidate_artifact_sha256=ARTIFACT_SHA,
                candidate_manifest_sha256=MANIFEST_SHA, candidate_source_sha256=SOURCE_SHA,
                build_runner=dict(path=recovered_runner.relative_to(ROOT).as_posix(),
                    sha256=checked[recovered_runner]['sha256'], provenance='reconstructed_by_exact_hash',
                    execution='NOT RUN'),
                actual_fixture=FIXTURE, fixture_pins={n: checked[local(fixture, n)] for n in sorted(fixture_names)},
                observed_cleanup=dict(daemon=shutdown, gate=gate, actors_retired=len(backend['retirements'])),
                gate_stdout=dict(path=gate_stdout.relative_to(ROOT).as_posix(), sha256=checked[gate_stdout]['sha256']),
                adoption_helper=dict(path=helper.relative_to(ROOT).as_posix(), sha256=checked[helper]['sha256']),
                adoption_inputs=dict(path=args.inputs, sha256=args.inputs_sha256)),
            product_qualified=False, readiness='L0')
        receipt_ref = output('COMPLETE_ROW_RECEIPT1-' + name + '.json', receipt)
        row.update(record_ref=dict(receipt_ref, selector=0), source_scenario_id=SCENARIO, block=None)

    targets = {('SEC-03', 'complete-requirement', backend, 'core') for backend in BACKENDS}
    for before, after in zip(original['rows'], proposed['rows']):
        require(set(before) == set(after) and identity(before) == identity(after), 'row schema/order')
        if identity(before) in targets:
            require({key for key in before if before[key] != after[key]} ==
                    {'record_ref', 'source_scenario_id', 'block'}, 'bounded SEC03 mutation')
            require(before['retained_evidence'] == after['retained_evidence'], 'retained evidence unchanged')
        else:
            require(before == after, 'unrelated row changed')
    require({k: v for k, v in original.items() if k != 'rows'} ==
            {k: v for k, v in proposed.items() if k != 'rows'}, 'index metadata unchanged')
    index_ref = output('REQUIRED_EVIDENCE_INDEX.json', proposed)
    for path, pin in list(checked.items()):
        read(path, pin['sha256'])
        require(checked[path] == pin, path)
    require(leaves(fixture) == fixture_names, 'fixture reread set')
    destination = local(ROOT, OUTPUT)
    require(destination.parent.is_dir() and not destination.exists(), 'fresh output required')
    destination.mkdir()
    for name, data in outputs.items():
        with (destination / name).open('xb') as target:
            target.write(data)
    for name, data in fixture_bytes.items():
        target = local(destination, 'fixture/' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(checked[local(fixture, name)]['mode'])
    print(json.dumps(dict(status='PREPARED_EXISTING_SCHEMA_SEC03_CORE_INDEX_PENDING_CONSUMERS',
        proposed_index=index_ref, prepared_receipts=2, prepared_witnesses=2, mirrored_fixture_files=27,
        unchanged_other_combinations=424, gao_bus='passed', reference='failed',
        product_qualified=False, readiness='L0', new_vm_executions=0, consumer_execution='NOT RUN'), sort_keys=True))


if __name__ == '__main__':
    main()
