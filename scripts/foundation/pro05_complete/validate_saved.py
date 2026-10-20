"""Read-only bindings for a supplied PRO05 report, never runtime acceptance.

Exact hashes identify the supplied files; they cannot establish that observations
came from an authentic runtime. Independent review and adoption remain required.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys

import contract


ROOT = '/run/osbus-security/pro05-complete'
RESULT = 'passed_complete_core_PRO05_runtime_pending_independent_review'
HELPERS = {
    'scripts/foundation/vm_security/actor.py',
    'scripts/foundation/vm_security/run.py',
    'scripts/foundation/vm_security/workload.json',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), f'not a regular file: {path}')
    data = path.read_bytes()
    return data, dict(bytes=len(data), mode=stat.S_IMODE(info.st_mode), sha256=digest(data))


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f'duplicate JSON key: {key}')
        value[key] = item
    return value


def invalid_constant(value):
    raise ValueError(f'nonfinite JSON value: {value}')


def read_json(path, expected_sha256=None):
    data, observed = read_file(path)
    if expected_sha256 is not None:
        require(isinstance(expected_sha256, str) and
                re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None,
                f'exact SHA256 required: {path}')
        require(observed['sha256'] == expected_sha256, f'SHA256 mismatch: {path}')
    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object,
                       parse_constant=invalid_constant)
    require(type(value) is dict, f'JSON object required: {path}')
    return value, observed


def local_file(root, name):
    require(isinstance(name, str), 'relative file name required')
    relative = PurePosixPath(name)
    require(name == relative.as_posix() and not relative.is_absolute() and
            relative.parts and all(part not in ('.', '..') for part in relative.parts),
            f'noncanonical relative file name: {name}')
    path = root
    for part in relative.parts:
        path = path / part
        require(not path.is_symlink(), f'symlink in pinned path: {path}')
    return path


def check_pin(root, name, expected):
    require(type(expected) is dict and set(expected) == {'bytes', 'mode', 'sha256'},
            f'invalid file pin: {name}')
    require(type(expected['bytes']) is int and expected['bytes'] >= 0 and
            type(expected['mode']) is int and 0 <= expected['mode'] <= 0o7777,
            f'invalid file size or mode: {name}')
    _, observed = read_file(local_file(root, name))
    require(observed == expected, f'file pin mismatch: {name}')


def fixture_pins(fixture):
    pins = {}
    for path in sorted(fixture.iterdir()):
        require(not path.is_symlink(), f'symlink in fixture: {path}')
        if path.is_dir():
            continue
        _, observed = read_file(path)
        pins[path.name] = dict(observed, mode=observed['mode'] & ~0o222)
    return pins


def validate_saved(report_path, report_sha256, vmoff_path, vmoff_sha256,
                   repository, candidate, fixture):
    """Validate only saved shape and current local source/file bindings.

    This function only reads the explicitly supplied paths and trees. It never
    launches a process, writes evidence, or qualifies a requirement/product.
    """
    require(not sys.flags.optimize, 'enabled assertions required')
    report_path, vmoff_path = Path(report_path), Path(vmoff_path)
    repository, candidate, fixture = (Path(path).resolve(strict=True)
                                      for path in (repository, candidate, fixture))
    require(report_sha256 is not None and vmoff_sha256 is not None,
            'both exact input SHA256 values are required')
    report, report_pin = read_json(report_path, report_sha256)
    vmoff, vmoff_pin = read_json(vmoff_path, vmoff_sha256)
    require(set(vmoff) == {'VMoff', 'socket_removed'} and
            vmoff['VMoff'] is True and vmoff['socket_removed'] is True,
            'complete VMoff and socket removal observations required')

    contract.validate_complete(report)
    require(report['profile'] == 'core' and report['selected'] == contract.SELECTED,
            'only the exact selected core profile is supported')
    require(report['result'] == RESULT and report['readiness'] == 'L0',
            'saved report is not pending independent runtime review')
    for field in ('runtime_qualification', 'requirement_qualification',
                  'accepted_index_mutation', 'product_qualified'):
        require(report[field] is False, f'{field} must remain false')

    bindings, _ = read_json(fixture / 'bindings.json')
    require(report['bindings'] == bindings, 'current fixture bindings mismatch')
    require(bindings['production_sources'] == 71 and bindings['artifact_files'] == 80 and
            bindings['profiles_prepared'] == ['core'] and
            bindings['network_profile_prepared'] is False and
            bindings['runtime_qualification'] is False and bindings['not_a_release'] is True,
            'unsupported source/artifact/profile binding')
    artifact, artifact_pin = read_json(candidate / 'artifact.json', bindings['artifact_sha256'])
    require(report['artifact'] == artifact and artifact['not_a_release'] is True,
            'current candidate artifact mismatch')
    require(artifact['origin_pin']['sha256'] == bindings['runtime_manifest_sha256'],
            'inherited runtime manifest binding mismatch')
    require(report['candidate_artifact_sha256'] == artifact_pin['sha256'] and
            report['candidate_source_sha256'] == contract.source_sha(artifact),
            'candidate artifact/source identity mismatch')
    require(len(artifact['sources']) == 71 and len(artifact['files']) == 80,
            'incomplete source or runnable file pins')
    for name, expected in artifact['sources'].items():
        check_pin(repository, name, expected)
    for name, expected in artifact['files'].items():
        require(name.startswith('lib/'), f'runnable file outside lib: {name}')
        check_pin(candidate, name, expected)
    runnable = set()
    for path in (candidate / 'lib').rglob('*'):
        require(not path.is_symlink(), f'symlink in runnable artifact: {path}')
        if path.is_file():
            runnable.add(path.relative_to(candidate).as_posix())
    require(runnable == set(artifact['files']), 'runnable file set mismatch')
    require(artifact['sources']['devenv.lock']['sha256'] == bindings['nixpkgs_lock_sha256'],
            'runtime source lock binding mismatch')

    require(set(bindings['helpers']) == HELPERS, 'inherited helper set mismatch')
    for name, expected in bindings['helpers'].items():
        check_pin(repository, name, expected)
    observed_fixture = fixture_pins(fixture)
    require(report['fixture_pins'] == observed_fixture, 'fixture file set/bytes/hash/mode mismatch')
    require(observed_fixture['cleanup.py']['sha256'] == bindings['cleanup_sha256'],
            'cleanup helper binding mismatch')

    backends = report['backends']
    require([row['backend'] for row in backends] == ['reference', 'gao_bus'],
            'backend selection mismatch')
    for row in backends:
        backend = row['backend']
        name = 'reference.conf' if backend == 'reference' else 'policy.exs'
        data, pin = read_file(fixture / name)
        expected = dict(path=f'{ROOT}/{backend}/{name}', bytes=data.decode('utf-8'),
                        sha256=pin['sha256'], system_mode=True, external_only=True,
                        isolated=True, profile='core', backend=backend,
                        endpoint=f'{ROOT}/{backend}/bus')
        configuration = row['configuration']
        require(configuration == expected and all(configuration[key] is True
                for key in ('system_mode', 'external_only', 'isolated')),
                f'prepared configuration mismatch: {backend}')

    return dict(validated_saved_report=True, acceptance='pending_independent_runtime_review',
                runtime_qualification=False, requirement_qualification=False,
                accepted_index_mutation=False, product_qualified=False, readiness='L0',
                inputs=dict(report=dict(path=str(report_path), sha256=report_pin['sha256'],
                                        bytes=report_pin['bytes']),
                            vmoff=dict(path=str(vmoff_path), sha256=vmoff_pin['sha256'],
                                       bytes=vmoff_pin['bytes']),
                            repository=str(repository), candidate=str(candidate), fixture=str(fixture),
                            candidate_artifact_sha256=artifact_pin['sha256'],
                            candidate_source_sha256=contract.source_sha(artifact)),
                observed_counts=dict(backends=len(backends), production_sources=len(artifact['sources']),
                    runnable_files=len(runnable), fixture_files=len(observed_fixture),
                    inherited_helpers=len(bindings['helpers'])))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('report', 'report-sha256', 'vmoff', 'vmoff-sha256',
                   'repository', 'candidate', 'fixture'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_saved(args.report, args.report_sha256, args.vmoff, args.vmoff_sha256,
                                args.repository, args.candidate, args.fixture)
    except (AssertionError, ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, f'invalid saved report: {error}\n')
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
