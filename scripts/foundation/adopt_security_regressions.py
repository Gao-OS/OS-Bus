"""Prepare SEC04/SEC15 existing-schema evidence; never execute a target or consumer.

Run with python3 -B, --case sec04|sec15, --inputs REPO_RELATIVE_JSON,
--inputs-sha256 SHA256, and optional --output FRESH_REPO_RELATIVE_DIRECTORY.
Inputs: {"fixture": "/nix/store/.../fixtures", "records": {NAME: {"path":
REPO_RELATIVE_PATH, "sha256": SHA256}}}; the fourteen names are RECORDS below.
Root acceptance must bind report/vmoff/counts/current candidate/L0 and list
accepted_backends. Only those complete, passed backends may replace blocked rows.
Outputs are proposals pending the parent's independent consumer validation.
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
HISTORY = 'test/reports/foundation/continuation-20261011-full-goal/environment/'
ARTIFACT_SHA = 'b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1'
RUNTIME_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
MANIFEST_SHA = 'fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82'
SOURCE_SHA = 'f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c'
BACKENDS = ('reference', 'gao_bus')
ACTORS = ['independent_client', 'external_observer']
RECORDS = {'report', 'vmoff', 'lifecycle', 'started', 'build_result', 'build_started',
           'build_stdout', 'artifact', 'runtime', 'acceptance', 'bindings', 'baseline_index',
           'build_runner', 'vm_runner'}
CASES = {
    'sec04': dict(required='SEC-04', adapter='auth_bypass_current', driver='auth-bypass',
        corpus='d574c6b62b7c6fa3005b1170286bbc2d0dd619457c22f7a50eb131cf6757c206',
        runner='a61cdc9721d307fe64c998b6ff9b2ea951171d60bdf7db2642025b13e80e6c53',
        current_runner='3c625eb02e9c3e2ea60464161df3d803490987e58a7ac0e3d89c118b0647be2e',
        old_manifest='372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7',
        old_source='efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9',
        cases=['direct_begin', 'wrong_uid', 'anonymous', 'challenge_cancel', 'unsupported'],
        actors=8, template='source1', primary='no_normal_bus_entry',
        invariant='No entry into normal bus operations; observer remains connected with unchanged names.'),
    'sec15': dict(required='SEC-15', adapter='malformed_current', driver='malformed',
        corpus='a06264853f5732f5a33c274d66e17ed1fc76282c79a8f2e132e400ab6109ff28',
        runner='19462036703708bfcd94c891f090479496e3fbf0449c8ea2aaac5d3b6de65e4e',
        old_manifest='6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5',
        old_source='4e334b95bc0ddd0afed797f9640c6971ba2a339c2a369f6500a0d7230d9e8350',
        cases=['missing_final_u32', 'non_nul_string_terminator'], actors=5,
        template='receipt1', primary='malformed_closed_without_reply',
        invariant='Frame rejected before authority dispatch; no global peer restart or lost healthy ownership.')}
ASSERTION = "assert current['invariant_measurement']==expected_invariant()"
SEC04_OLD_REQUEST = b"""                response = worker['channel'].read(timeout=remaining(limit))
                receipt = dict(identity=worker['public']['identity'], request=command,
                               response=response, elapsed_ms=(time.monotonic()-began)*1000)
                current['receipts'].append(receipt)
                persist()
                assert time.monotonic() <= limit, 'SEC04 request exceeded fixed caller deadline'
                assert response['ok'] is True, response
                return response
"""
SEC04_NEW_REQUEST = b"""                response = worker['channel'].read(timeout=remaining(limit))
                received = time.monotonic()
                try:
                    assert received <= limit, 'SEC04 request exceeded fixed caller deadline'
                    assert response['ok'] is True, response
                    return response
                finally:
                    receipt = dict(identity=worker['public']['identity'], request=command,
                                   response=response, elapsed_ms=(received-began)*1000)
                    current['receipts'].append(receipt)
"""
BOUNDS = dict(authority_seconds=60, guest_seconds=120, host_seconds=900,
              cleanup_seconds=5, startup_seconds=10, request_ms=1000, attack_ms=2000,
              authentication_ms=1500, authentication_idle_ms=500, settle_ms=1000,
              settle_reads=128, poll_seconds=0.05, observer_seconds=30)


def require(condition, detail):
    if not condition:
        raise ValueError(str(detail))


def sec04_runner_patch(original, current, before, after, bindings, original_store):
    spec = CASES['sec04']
    require(hashlib.sha256(original).hexdigest() == before['sha256'] == spec['runner']
            and hashlib.sha256(current).hexdigest() == after['sha256'] == spec['current_runner']
            and before['bytes'] == len(original) and after['bytes'] == len(current)
            and before['mode'] == after['mode']
            and before == bindings['fixture_inputs']['run.py']
            and after == bindings['patched_run'], 'SEC04 runner pins')
    require(original.count(SEC04_OLD_REQUEST) == 1 and SEC04_NEW_REQUEST not in original
            and current.count(SEC04_NEW_REQUEST) == 1 and SEC04_OLD_REQUEST not in current
            and original.replace(SEC04_OLD_REQUEST, SEC04_NEW_REQUEST, 1) == current
            and current.replace(SEC04_NEW_REQUEST, SEC04_OLD_REQUEST, 1) == original,
            'SEC04 reversible runner patch')
    provenance = bindings['runner_patch_provenance']
    flags = ('reversible_byte_change', 'response_deadline_checked_before_persistence',
             'receipt_persisted_on_assertion_failure', 'numerical_bounds_unchanged',
             'persistence_at_original_enclosing_boundaries')
    require(provenance == dict(origin=str(original_store / 'run.py'), before=before, after=after,
            original=SEC04_OLD_REQUEST.decode(), replacement=SEC04_NEW_REQUEST.decode(),
            replacement_count=1, per_request_full_graph_persistence=False, **dict.fromkeys(flags, True))
            and type(provenance['replacement_count']) is int
            and provenance['per_request_full_graph_persistence'] is False
            and all(provenance[key] is True for key in flags), 'SEC04 runner patch provenance')


def local(root, name):
    require(isinstance(name, str), 'path must be a string')
    relative = PurePosixPath(name)
    require(name == relative.as_posix() and not relative.is_absolute() and relative.parts
            and all(part not in ('.', '..') for part in relative.parts), name)
    path = root
    require(not path.is_symlink(), root)
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


def identity(value):
    return tuple(value[key] for key in ('required_id', 'subcase_id', 'backend', 'profile'))


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def kernel(actor, uid):
    ident = actor['identity']
    require(set(ident) == {'pid', 'uid', 'gid'} and type(ident['pid']) is int
            and ident['pid'] > 0 and ident['uid'] == ident['gid'] == uid, 'actor identity')
    fields = {line.split(':', 1)[0]: line.split(':', 1)[1].split()
              for line in actor['proc_status'].splitlines() if ':' in line}
    require(fields['Pid'] == [str(ident['pid'])] and fields['Uid'] == fields['Gid'] == [str(uid)] * 4,
            'kernel identity')


def main():
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError('Run with -B and without Python optimization')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    spec = CASES[args.case]
    current_runner = spec.get('current_runner', spec['runner'])
    scenario = spec['required'] + '/complete-requirement'
    historical = HISTORY + 'm1-' + args.case + '-complete1/'
    output_path = args.output or RESUME + '/' + args.case + '-adoption1'
    destination = local(ROOT, output_path)
    require(destination.parent.is_dir() and not destination.exists(), 'fresh output required')
    checked, directories = {}, {}

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
        return json.loads(read(path, digest), object_pairs_hook=unique,
                          parse_constant=lambda value: require(False, 'nonfinite JSON: ' + value))

    def directory(path, expected):
        require(leaves(path) == expected, path)
        directories[path] = expected

    helper = local(ROOT, Path(__file__).absolute().relative_to(ROOT).as_posix())
    read(helper)
    inputs = load(local(ROOT, args.inputs), args.inputs_sha256)
    require(set(inputs) == {'fixture', 'records'} and set(inputs['records']) == RECORDS, 'input schema')
    fixture = store(inputs['fixture'])
    references, paths, records = {}, {}, {}
    for name, ref in inputs['records'].items():
        require(set(ref) == {'path', 'sha256'}, name)
        path = local(ROOT, ref['path'])
        references[name], paths[name] = ref, path
        records[name] = (read(path, ref['sha256']).decode() if name in
                         ('build_stdout', 'build_runner', 'vm_runner') else load(path, ref['sha256']))
    require(references['artifact']['sha256'] == ARTIFACT_SHA
            and references['runtime']['sha256'] == RUNTIME_SHA, 'current product')
    report, bindings, artifact, runtime = (records[n] for n in ('report', 'bindings', 'artifact', 'runtime'))
    require(fixture.name == 'fixtures' and load(fixture.parent / 'bindings.json',
            references['bindings']['sha256']) == bindings, 'actual adapter fixture')
    require(report['fixture'] == 'complete-core-' + args.case and report['bounds'] == BOUNDS
            and report['selected'] == [scenario + '/' + b + '/core' for b in BACKENDS], 'scenario selection')
    require(report['readiness'] == 'L0' and all(report[k] is False for k in
            ('product_qualified', 'requirement_qualification', 'accepted_index_mutation')), 'raw boundary')
    require(report['candidate_manifest_sha256'] == MANIFEST_SHA
            and report['candidate_source_sha256'] == SOURCE_SHA, 'report candidate')
    manifest = load(store(bindings['candidate_store']) / 'candidate.json', MANIFEST_SHA)
    require(report['candidate'] == bindings['candidate_manifest'] == manifest, 'candidate equality')
    require(artifact['not_a_release'] is runtime['not_a_release'] is manifest['not_a_release'] is True
            and artifact['origin_pin']['sha256'] == RUNTIME_SHA
            and manifest['runtime'] == runtime['runtime'], 'runtime identity')
    sources = {name: pin['sha256'] for name, pin in artifact['sources'].items()}
    require(manifest['sources'] == sources and set(sources) == set(runtime['sources'])
            and hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest() == SOURCE_SHA
            and manifest['source_sha256'] == SOURCE_SHA, 'source digest')
    require(manifest['source_beams'] == runtime['source_beams']
            and (len(sources), len(manifest['source_beams']),
                 sum(map(len, manifest['source_beams'].values())), len(artifact['files'])) == (71, 57, 61, 80)
            and set(manifest['source_beams']) <= set(sources)
            and all('lib/' + beam in artifact['files'] for beams in manifest['source_beams'].values()
                    for beam in beams), 'source beam mapping')
    require(manifest['files'] == {n: p['sha256'] for n, p in artifact['files'].items()}
            and manifest['file_modes'] == {n: p['mode'] for n, p in artifact['files'].items()}, 'runnable manifest')
    for name, pin in artifact['sources'].items():
        path = local(ROOT, name)
        read(path, pin['sha256'])
        require(checked[path] == pin, path)
    for root, metadata, immutable in [(paths['artifact'].parent, 'artifact.json', False),
            (store(bindings['artifact_store']), 'artifact.json', True),
            (store(bindings['candidate_store']), 'candidate.json', True)]:
        directory(root, set(artifact['files']) | {metadata})
        read(root / metadata, ARTIFACT_SHA if metadata == 'artifact.json' else MANIFEST_SHA)
        for name, pin in artifact['files'].items():
            require(name.startswith('lib/'), name)
            path = local(root, name)
            read(path, pin['sha256'])
            require(checked[path] == dict(pin, mode=pin['mode'] & ~0o222) if immutable
                    else checked[path] == pin, path)
    require(bindings['candidate_files'] == {n: checked[local(store(bindings['candidate_store']), n)]
            for n in artifact['files']}, 'candidate file pins')
    read(store(bindings['runtime_store']), RUNTIME_SHA)
    corpus = load(local(ROOT, historical + 'source1/SOURCE_MANIFEST1.json'), spec['corpus'])
    require(load(store(bindings['corpus_store']), spec['corpus']) == corpus, 'immutable corpus')
    if args.case == 'sec04':
        original_pins = {}
        for name in corpus['fixture_files']:
            matches = [pin for path, pin in corpus['files'].items()
                       if path.endswith('/m1-sec04-complete1/source1/fixture1/' + name)]
            require(len(matches) == 1, name)
            original_pins[name] = matches[0]
    else:
        original_pins = {n.removeprefix('fixture1/'): p for n, p in corpus['files'].items()
                         if n.startswith('fixture1/')}
    fixture_names = set(original_pins)
    require(len(fixture_names) == 20 and set(bindings['fixture_inputs']) == fixture_names
            and set(report['fixture_pins']) == fixture_names, 'fixture set')
    original_store = store(bindings['fixtures_store'])
    directory(fixture, fixture_names)
    directory(original_store, fixture_names)
    replacements = [("MANIFEST_SHA = '" + spec['old_manifest'] + "'", "MANIFEST_SHA = '" + MANIFEST_SHA + "'"),
                    ("SOURCE_SHA = '" + spec['old_source'] + "'", "SOURCE_SHA = '" + SOURCE_SHA + "'")]
    fixture_bytes = {}
    for name, pin in sorted(original_pins.items()):
        original = local(ROOT, historical + 'source1/fixture1/' + name)
        old_data = read(original, pin['sha256'])
        require(checked[original] == pin, original)
        frozen = local(original_store, name)
        require(read(frozen, pin['sha256']) == old_data and checked[frozen] ==
                bindings['fixture_inputs'][name] == dict(pin, mode=pin['mode'] & ~0o222), frozen)
        current = local(fixture, name)
        fixture_bytes[name] = read(current, report['fixture_pins'][name])
        if name == 'contract.py':
            patched = old_data
            for before, after in replacements:
                require(patched.count(before.encode()) == 1 and after.encode() not in patched, 'assignment')
                patched = patched.replace(before.encode(), after.encode())
            restored = patched
            for before, after in reversed(replacements):
                restored = restored.replace(after.encode(), before.encode())
            require(fixture_bytes[name] == patched and restored == old_data
                    and checked[current] == bindings['patched_contract']
                    and checked[current]['mode'] == checked[frozen]['mode'], 'contract patch')
        elif args.case == 'sec04' and name == 'run.py':
            sec04_runner_patch(old_data, fixture_bytes[name], checked[frozen], checked[current],
                               bindings, original_store)
        else:
            require(fixture_bytes[name] == old_data and checked[current] == checked[frozen], current)
    provenance = bindings['patch_provenance']
    require(provenance == dict(origin=str(original_store / 'contract.py'),
            before=bindings['fixture_inputs']['contract.py'], after=bindings['patched_contract'],
            assignments=[dict(original=a, replacement=b) for a, b in replacements],
            reversible_byte_change=True), 'patch provenance')
    require(bindings['adapter_revision'] == (4 if args.case == 'sec04' else 2)
            and bindings['artifact_sha256'] == ARTIFACT_SHA
            and bindings['runtime_sha256'] == RUNTIME_SHA and bindings['corpus_manifest_sha256'] == spec['corpus']
            and bindings['candidate_manifest_sha256'] == MANIFEST_SHA
            and bindings['candidate_source_sha256'] == SOURCE_SHA and bindings['not_a_release'] is True
            and bindings['product_qualified'] is False
            and bindings['fixture_files_unchanged'] == (18 if args.case == 'sec04' else 19)
            and bindings['runnable_files_unchanged'] == 80 and bindings['cases_per_backend'] == len(spec['cases'])
            and bindings['corpus_pairs'] == 2 * len(spec['cases'])
            and bindings['positive_controls_per_backend'] == 2, 'adapter bindings')
    adapter = local(ROOT, 'scripts/foundation/' + spec['adapter'] + '/normalize.py')
    read(adapter, bindings['adapter']['sha256'])
    require(dict(checked[adapter], mode=checked[adapter]['mode'] & ~0o222) == bindings['adapter'], 'adapter source')
    excerpt = '# ' + scenario + ' source-bound invariant measurement.'
    require(checked[fixture / 'run.py']['sha256'] == current_runner
            and excerpt in fixture_bytes['run.py'].decode() and ASSERTION in fixture_bytes['run.py'].decode(), 'assertion source')
    if args.case == 'sec04':
        require(fixture_bytes['run.py'].decode().count(excerpt) == 1
                and fixture_bytes['run.py'].decode().count(ASSERTION) == 1, 'SEC04 unique assertion source')
    require(report['original_pins'] == load(fixture / 'INHERITED_INPUTS.json')['security']
            and report['workload'] == load(fixture / 'workload.json'), 'inherited/workload inputs')

    build, build_started, started, lifecycle = (records[n] for n in ('build_result', 'build_started', 'started', 'lifecycle'))
    require(build['returncode'] == 0 and build['inputs_match'] is True and build['vm_invocations'] == 0
            and all(build[k] == v for k, v in build_started.items()), 'build outcome')
    require(build['input_sha256'] == started['input_sha256'] and build['cwd'] == started['cwd'] == str(ROOT)
            and references['build_runner']['sha256'] == build['runner_sha256']
            and references['vm_runner']['sha256'] == started['runner_sha256'], 'build/VM source bindings')
    for name in ('artifact', 'runtime'):
        require(started['input_sha256'][references[name]['path']] == references[name]['sha256'], name + ' VM input')
    require(started['input_sha256'][adapter.relative_to(ROOT).as_posix()] == checked[adapter]['sha256']
            and started['input_sha256'][historical + 'source1/SOURCE_MANIFEST1.json'] == spec['corpus']
            and paths['lifecycle'].parent == paths['started'].parent, 'scenario lifecycle inputs')
    read(local(paths['started'].parent, 'runner.py'), started['runner_sha256'])
    for name, digest in started['input_sha256'].items():
        read(local(ROOT, name), digest)
    driver = records['build_stdout'].strip()
    store(driver)
    require(driver.endswith('-nixos-test-driver-os-bus-foundation-' + spec['driver'] + '-current')
            and started['argv'] == [driver + '/bin/nixos-test-driver', '--no-interactive', '-o',
                str(paths['started'].parent / 'out'), '--junit-xml', str(paths['started'].parent / 'junit.xml')], 'VM argv')
    output_root = paths['started'].parent / 'out'
    require(paths['report'] == output_root / (spec['driver'] + '-current-evidence') / (args.case + '-complete') / 'qualification.json'
            and paths['bindings'] == paths['report'].parent / 'current-bindings.json'
            and paths['vmoff'] == output_root / (spec['driver'] + '-current-vmoff.json'), 'guest export paths')
    require(lifecycle['returncode'] == 0 and lifecycle['status'] == 'passed_host_graceful'
            and lifecycle['timed_out'] is False and lifecycle['containment'] == []
            and all(lifecycle[k] is True for k in ('leader_reaped', 'pid_absent', 'group_absent', 'inputs_match', 'graceful_success'))
            and lifecycle['monitor_errors'] == lifecycle['input_errors'] == [], 'VM lifecycle')
    require(records['vmoff'] == dict(VMoff=True, socket_removed=True), 'VMoff')
    require(len(report['backends']) <= 2 and [b['backend'] for b in report['backends']] ==
            list(BACKENDS[:len(report['backends'])]) and all(b['status'] in ('passed', 'failed', 'running')
            and b['profile'] == 'core' for b in report['backends']), 'backend selection')
    passed = sum(b['status'] == 'passed' for b in report['backends'])
    failed = sum(b['status'] == 'failed' for b in report['backends'])
    counts = dict(selected=2, executed=passed + failed, passed=passed, failed=failed,
                  blocked=2 - passed - failed, skipped=0)
    require(report['counts'] == counts, 'raw counts')
    acceptance = records['acceptance']
    require(acceptance['decision'] == 'ACCEPTED_' + args.case.upper() + '_COMPLETE_CORE_RUNTIME'
            and acceptance['report'] == references['report'] and acceptance['vmoff'] == references['vmoff']
            and acceptance['counts'] == counts and acceptance['candidate_artifact_sha256'] == ARTIFACT_SHA
            and acceptance['candidate_manifest_sha256'] == MANIFEST_SHA
            and acceptance['candidate_source_sha256'] == SOURCE_SHA and acceptance['readiness'] == 'L0'
            and acceptance['product_qualified'] is False, 'root runtime acceptance')
    accepted = acceptance['accepted_backends']
    require(isinstance(accepted, list) and accepted and len(accepted) == len(set(accepted))
            and set(accepted) <= {b['backend'] for b in report['backends'] if b['status'] == 'passed'}, 'accepted backends')
    expected = dict(observer_connected_same_identity=True, observer_names_unchanged=True,
        no_ownership_or_delivery_effects=True, no_fabricated_credentials=True,
        valid_external_and_retry_preserved=True, native_resources_recovered=True, natural_teardown=True,
        cases=spec['cases'], **{spec['primary']: True})
    original = records['baseline_index']
    proposed = deepcopy(original)
    require(original['index_schema'] == original['catalogue_version'] == 1 and 'counts' not in original
            and len(original['rows']) == 426 and len({identity(r) for r in original['rows']}) == 426, 'index schema')
    outputs, targets = {}, set()

    def output(name, value):
        data = encoded(value)
        outputs[name] = data
        return dict(path=output_path + '/' + name, sha256=hashlib.sha256(data).hexdigest())

    def binding(name, kind, digest):
        return dict(path=name, kind=kind, sha256=digest, before_sha256=digest, after_sha256=digest)

    for backend in report['backends']:
        name = backend['backend']
        if name not in accepted:
            continue
        require(backend['invariant_measurement'] == expected
                and [c['case'] for c in backend['cases']] == spec['cases']
                and [p['flow'] for p in backend['positives']] == ['plain', 'discovery']
                and len({a['identity']['pid'] for a in backend['actors']}) == spec['actors']
                and 'failure' not in backend and len(backend['actors']) ==
                len(backend['retirements']) == spec['actors'] and backend['shutdown_errors'] == []
                and backend['recovered'] == backend['baseline'], 'complete passed backend')
        for case in backend['cases']:
            require(case['before'] == case['after'] == backend['baseline']
                    and any(a['identity'] == case['identity'] and a['proc_status'] == case['proc_status']
                            for a in backend['actors']), 'case actor and recovered state')
        for retired in backend['retirements']:
            require(retired['identity'] in [a['identity'] for a in backend['actors']], 'retired identity')
            before = retired['before_containment']
            require(retired['method'] == 'eof' and retired['returncode'] == 0
                    and all(retired[k] is True for k in ('pid_absent', 'actor_pid_absent', 'group_absent'))
                    and all(before[k] is True for k in ('stdin_closed', 'wrapper_waited', 'pid_absent', 'actor_pid_absent', 'group_absent'))
                    and before['wrapper_returncode'] == 0 and before['timed_out'] is False
                    and before['errors'] == [], 'natural actor retirement')
        require({json.dumps(r['identity'], sort_keys=True) for r in backend['retirements']} ==
                {json.dumps(a['identity'], sort_keys=True) for a in backend['actors']}, 'all actors retired')
        shutdown, endpoint = backend['daemon_retirement'], backend['endpoint_cleanup']
        require(shutdown['returncode'] == 0 and shutdown['pid_absent'] is shutdown['group_absent'] is True
                and shutdown['forced'] is False and shutdown['method'] == ('sigterm' if name == 'reference' else 'eof')
                and endpoint['absent'] is True and endpoint['expected_identity'] is not None
                and (endpoint['removed_by_controller'] is False or name == 'reference'
                     and endpoint['observed_identity'] == endpoint['expected_identity']), 'daemon/endpoint cleanup')
        config_name = 'reference.conf' if name == 'reference' else 'policy.exs'
        config = report['fixture_pins'][config_name]
        require(backend['configuration']['sha256'] == config and
                backend['configuration']['bytes'].encode() == fixture_bytes[config_name]
                and all(backend['configuration'][k] is True for k in ('system_mode', 'external_only', 'isolated')), 'configuration')
        kernel(backend['daemon'], 0)
        observer = backend['observer']
        attacker = next(a for a in backend['actors'] if a['identity'] == backend['cases'][0]['identity'])
        require(observer in backend['actors'] and observer['identity']['pid'] != attacker['identity']['pid'], 'independent actors')
        actor_receipts = []
        for role, actor, uid in [('external_observer', observer, 1100), ('independent_client', attacker, 1101)]:
            kernel(actor, uid)
            actor_receipts.append(dict(actor=role, backend=name, profile='core', executed=True,
                pid=actor['identity']['pid'], uid=uid, config_sha256=config,
                primary_kernel_status=actor['proc_status']))
        key = (spec['required'], 'complete-requirement', name, 'core')
        row, = [r for r in proposed['rows'] if identity(r) == key]
        require(row['record_ref'] is None and row['source_scenario_id'] is None and row['block'] is not None
                and row['coverage_scope'] == scenario and row['requirements'] ==
                dict(layer='independent-system', actors=ACTORS, invariants=[spec['invariant']]), 'blocked target row')
        template_path = historical + spec['template'] + '/COMPLETE_ROW_RECEIPT1-' + name + '.json'
        retained, = [r for r in row['retained_evidence'] if r['path'] == template_path]
        template = load(local(ROOT, template_path), retained['sha256'])
        require(template['observations'] == [retained['value']] and retained['currency'] == 'historical', 'retained template')
        old_ref = template['observations'][0]['assertions'][0]['record_ref']
        witness = load(local(ROOT, old_ref['path']), old_ref['sha256'])
        require(witness['expected'] == expected and witness['source_sha256'] == spec['runner']
                and witness['invariant'] == spec['invariant'] and witness['assertion_source'] == ASSERTION, 'witness template')
        run_id = args.case + '-current-' + name + '-' + references['report']['sha256'][:16]
        witness.pop('raw_review', None)
        if args.case == 'sec04':
            witness['source_sha256'] = current_runner
        witness.update(run_id=run_id, status='passed', actual=backend['invariant_measurement'],
                       raw_qualification=checked[paths['report']], root_runtime_acceptance=references['acceptance'])
        witness_ref = output('ASSERTION_WITNESS1-' + name + '.json', witness)
        receipt = deepcopy(template)
        receipt['observations'][0].update(status='passed', source_ref=dict(path=output_path + '/fixture/run.py',
            binding_path=output_path + '/fixture/run.py', sha256=current_runner, excerpt=excerpt),
            assertions=[dict(invariant=spec['invariant'], record_ref=dict(witness_ref, selector=[]))])
        receipt_bindings = [binding(output_path + '/fixture/' + config_name, 'config', config)]
        receipt_bindings += [binding(n, 'source', p['sha256']) for n, p in artifact['sources'].items()]
        receipt_bindings += [binding(output_path + '/fixture/run.py', 'test', current_runner)]
        receipt_bindings += [binding(output_path + '/fixture/' + n, 'fixture', report['fixture_pins'][n])
                             for n in sorted(fixture_names) if n not in (config_name, 'run.py')]
        receipt.update(currency='current', run_id=run_id, bindings=receipt_bindings, actor_receipts=actor_receipts,
            backend_receipt=dict(backend=name, profile='core', pid=backend['daemon']['identity']['pid'],
                config_sha256=config, independent=True, version=backend['daemon']['version']),
            counts=dict(selected=1, executed=1, passed=1, failed=0, blocked=0, skipped=0),
            command=dict(argv=started['argv'], cwd=started['cwd'], exit=lifecycle['returncode'],
                         teardown_exit=shutdown['returncode'], log_failures=0),
            supporting_evidence=dict(references, backend_selector=name, root_runtime_acceptance=references['acceptance'],
                candidate_artifact_sha256=ARTIFACT_SHA, candidate_manifest_sha256=MANIFEST_SHA,
                candidate_source_sha256=SOURCE_SHA, actual_fixture=str(fixture),
                fixture_pins={n: checked[local(fixture, n)] for n in sorted(fixture_names)},
                observed_cleanup=dict(daemon=shutdown, endpoint=endpoint, actors_retired=len(backend['retirements'])),
                adoption_helper=dict(path=helper.relative_to(ROOT).as_posix(), sha256=checked[helper]['sha256']),
                adoption_inputs=dict(path=args.inputs, sha256=args.inputs_sha256)), readiness='L0', product_qualified=False)
        receipt_ref = output('COMPLETE_ROW_RECEIPT1-' + name + '.json', receipt)
        row.update(record_ref=dict(receipt_ref, selector=0), source_scenario_id=scenario, block=None)
        targets.add(key)
    require(len(targets) == len(accepted), 'all accepted backends prepared')
    for before, after in zip(original['rows'], proposed['rows']):
        require(set(before) == set(after) and identity(before) == identity(after), 'row schema/order')
        if identity(before) in targets:
            require({k for k in before if before[k] != after[k]} == {'record_ref', 'source_scenario_id', 'block'}
                    and before['retained_evidence'] == after['retained_evidence'], 'bounded mutation')
        else:
            require(before == after, 'unadopted row changed')
    require({k: v for k, v in original.items() if k != 'rows'} ==
            {k: v for k, v in proposed.items() if k != 'rows'}, 'index metadata unchanged')
    index_ref = output('REQUIRED_EVIDENCE_INDEX.json', proposed)
    for path, pin in list(checked.items()):
        read(path, pin['sha256'])
        require(checked[path] == pin, path)
    for path, names in directories.items():
        require(leaves(path) == names, 'changed directory: ' + str(path))
    require(local(ROOT, output_path) == destination and not destination.exists(), 'fresh output reread')
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
    print(json.dumps(dict(status='PREPARED_EXISTING_SCHEMA_SECURITY_INDEX_PENDING_CONSUMERS',
        case=args.case, proposed_index=index_ref, accepted_backends=accepted,
        prepared_receipts=len(targets), prepared_witnesses=len(targets), mirrored_fixture_files=20,
        unchanged_combinations=426-len(targets), readiness='L0', product_qualified=False,
        new_vm_executions=0, consumer_execution='NOT RUN'), sort_keys=True))


if __name__ == '__main__':
    main()
