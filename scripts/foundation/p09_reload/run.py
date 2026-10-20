"""Run frozen reload, alias and Properties.Set/GetAll tests in a disposable three-UID guest."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(candidate, fixtures, evidence, selected):
    assert os.geteuid() == 0
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert evidence == Path('/run/osbus-p09-reload')
    assert selected == 6, 'the reload, alias and Properties.Set/GetAll selection contains exactly six tests'
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert manifest['version'] == 1 and manifest['not_a_release']
    candidate_hashes_before = {name: digest(candidate / name) for name in manifest['files']}
    assert candidate_hashes_before == manifest['files'], 'candidate artifact hashes differ before execution'

    reference_name = shutil.which('dbus-daemon')
    assert reference_name, 'BLOCKED_ENV: pinned reference dbus-daemon is unavailable'
    reference = Path(reference_name).resolve()

    case = fixtures / 'apps/gao_bus/test/policy/file_reload_socket_test.exs'
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += ['-r', str(fixtures / 'apps/gao_bus/test/test_helper.exs'),
                '-e', 'ExUnit.configure(seed: 1703); Code.require_file(hd(System.argv()))',
                '--', str(case)]
    settings = {'OSBUS_RELOAD_ORDINARY_UID': '1101',
                'OSBUS_RELOAD_SERVICE_UID': '1100',
                'OSBUS_RELOAD_EVIDENCE_DIRECTORY': str(evidence / 'actors'),
                'OSBUS_RELOAD_REFERENCE_DAEMON': str(reference)}
    environment = dict(os.environ, **settings)
    record = {
        'result': 'running',
        'scope': 'POL-05/POL-06/API-03 reload, POL-02/SEC-09 alias and API-02 Properties.Set/GetAll development selection',
        'scopes': ['wire-reload', 'destination-alias', 'properties-set', 'properties-get-all', 'api-dispatch'],
        'installed_profile_qualified': False,
        'candidate_manifest_sha256': digest(candidate / 'candidate.json'),
        'candidate_hashes_before': candidate_hashes_before,
        'candidate_artifacts': len(manifest['files']), 'candidate_source_sha256': manifest['source_sha256'],
        'fixtures_sha256': {str(p.relative_to(fixtures)): digest(p)
                            for p in sorted(fixtures.rglob('*')) if p.is_file()},
        'command': command, 'environment': settings, 'cwd': str(fixtures),
        'runtime': manifest['runtime'], 'uid': os.getuid(), 'groups': os.getgroups(),
        'reference': {'path': str(reference), 'sha256': digest(reference),
                      'version': subprocess.check_output([str(reference), '--version'], text=True).strip()},
        'selected_tests': selected, 'seed': 1703,
        'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'readiness': 'L0', 'not_a_release': True,
    }
    report = evidence / 'verification.json'

    def save():
        report.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')

    expected_actors = {'candidate-actor.json': ('candidate', 'wire-reload'),
                       'reference-actor.json': ('reference', 'wire-reload'),
                       'alias-candidate-actor.json': ('candidate', 'destination-alias'),
                       'alias-reference-actor.json': ('reference', 'destination-alias'),
                       'properties-candidate-actor.json': ('candidate', 'properties-set'),
                       'properties-reference-actor.json': ('reference', 'properties-set'),
                       'getall-candidate-actor.json': ('candidate', 'properties-get-all'),
                       'getall-reference-actor.json': ('reference', 'properties-get-all'),
                       'api-candidate-actor.json': ('candidate', 'api-dispatch'),
                       'api-reference-actor.json': ('reference', 'api-dispatch')}

    def account_actors():
        actors, results = {}, {}
        actor_files = sorted((evidence / 'actors').glob('*-actor.json'))
        for actor_file in actor_files:
            entry = {'sha256': digest(actor_file)}
            try:
                result = json.loads(actor_file.read_text())
                assert isinstance(result, dict), 'actor report must be an object'
                entry.update(backend=result.get('backend'), result=result.get('result', 'INVALID'),
                             scope=expected_actors.get(actor_file.name, (None, None))[1])
                assert actor_file.name in expected_actors, 'unexpected actor report'
                backend, scope = expected_actors[actor_file.name]
                assert result.get('backend') == backend, 'actor backend does not match its required report'
                assert result.get('result') in ('PASS', 'FAIL'), 'invalid actor result'
                assert result.get('installed_profile_qualified') is False, 'invalid actor profile claim'
                if scope != 'wire-reload':
                    assert result.get('scope') == scope and result.get('readiness') == 'L0', \
                        'invalid actor scope or readiness'
                actors[actor_file.name] = result
            except (ValueError, AssertionError) as error:
                entry.update(result='INVALID', error=repr(error))
            results[actor_file.name] = entry
        present = set(results) & set(expected_actors)
        passed = sum(results[name]['result'] == 'PASS' for name in present)
        record['actor_results'] = results
        record['actor_counts'] = {'required': len(expected_actors), 'executed': len(present),
                                  'passed': passed, 'failed': len(present) - passed,
                                  'skipped': 0, 'blocked': len(expected_actors) - len(present)}
        record['missing_actor_reports'] = sorted(set(expected_actors) - present)
        pair_file = evidence / 'actors/properties-set-pair.json'
        if pair_file.is_file():
            record['properties_set'] = {'pair_sha256': digest(pair_file)}
            try:
                pair = json.loads(pair_file.read_text())
                record['properties_set']['pair_result'] = pair['result']
                record['properties_set']['config_hashes'] = pair['config_hashes']
                record['properties_set']['candidate_shutdown'] = pair['candidate_shutdown']
                record['properties_set']['reference_shutdown'] = pair['reference_shutdown']
                record['properties_set']['backends'] = {
                    backend: {'exit_status': pair[backend]['exit_status'],
                              'actual_error': pair[backend]['report'].get('properties', {}).get('set_actual_error'),
                              'result': pair[backend]['report'].get('result')}
                    for backend in ['candidate', 'reference']}
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                record['properties_set']['error'] = repr(error)
        get_all_pair_file = evidence / 'actors/properties-get-all-pair.json'
        if get_all_pair_file.is_file():
            record['properties_get_all'] = {'pair_sha256': digest(get_all_pair_file)}
            try:
                pair = json.loads(get_all_pair_file.read_text())
                record['properties_get_all']['pair_result'] = pair['result']
                record['properties_get_all']['config_hashes'] = pair['config_hashes']
                record['properties_get_all']['candidate_shutdown'] = pair['candidate_shutdown']
                record['properties_get_all']['reference_shutdown'] = pair['reference_shutdown']
                record['properties_get_all']['backends'] = {
                    backend: {'exit_status': pair[backend]['exit_status'],
                              'actual_error': pair[backend]['report'].get('properties', {}).get('unknown_interface_actual_error'),
                              'consistent': pair[backend]['report'].get('properties', {}).get('consistent'),
                              'result': pair[backend]['report'].get('result')}
                    for backend in ['candidate', 'reference']}
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                record['properties_get_all']['error'] = repr(error)
        api_file = evidence / 'actors/api-dispatch-pair.json'
        if api_file.is_file():
            record['api_dispatch'] = {'pair_sha256': digest(api_file)}
            try:
                pair = json.loads(api_file.read_text())
                record['api_dispatch']['pair_result'] = pair['result']
                record['api_dispatch']['backends'] = {
                    backend: {'exit_status': pair[backend]['exit_status'],
                              'result': pair[backend]['report'].get('result'),
                              'contract_failures': pair[backend]['report'].get('contract_failures')}
                    for backend in ['candidate', 'reference']}
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                record['api_dispatch']['error'] = repr(error)
        return actors, actor_files

    save()
    started = time.monotonic()
    output = ''
    try:
        completed = subprocess.run(command, cwd=fixtures, env=environment, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=150)
        output = completed.stdout
        (evidence / 'wire-reload.log').write_text(output)
        record['exit_status'] = completed.returncode
        matches = re.findall(r'(?m)^(\d+) tests?, (\d+) failures?(.*)$', output)
        assert len(matches) == 1, ('missing or ambiguous test accounting', matches)
        executed, failed, remainder = matches[0]
        assert not remainder.strip(), ('unexpected test accounting', remainder)
        record['counts'] = {'selected': selected, 'executed': int(executed),
                            'passed': int(executed) - int(failed), 'failed': int(failed),
                            'skipped': 0, 'blocked': 0}
        actors, actor_files = account_actors()
        assert int(executed) == selected, record['counts']
        assert completed.returncode == 0 and int(failed) == 0, record['counts']
        assert {p.name for p in actor_files} == set(expected_actors), [p.name for p in actor_files]
        for actor_file in actor_files:
            result = actors[actor_file.name]
            backend, scope = expected_actors[actor_file.name]
            assert result['result'] == 'PASS' and result['backend'] == backend, actor_file.name
            assert result['installed_profile_qualified'] is False, actor_file.name
            if scope in ('destination-alias', 'properties-set', 'properties-get-all', 'api-dispatch'):
                assert result['scope'] == scope and result['readiness'] == 'L0', actor_file.name
        candidate_alias = actors['alias-candidate-actor.json']
        reference_alias = actors['alias-reference-actor.json']
        hashes = candidate_alias['config_hashes_before']
        assert set(hashes) == {'bus.conf', 'policy.conf', 'rules.conf'}, hashes
        assert all(re.fullmatch(r'[0-9a-f]{64}', value) for value in hashes.values()), hashes
        for result in [candidate_alias, reference_alias]:
            for phase in ['before', 'release', 'after']:
                assert result['config_hashes_' + phase] == hashes, (result['backend'], phase)
        decision_keys = ['phase', 'destination_kind', 'allowed', 'deliveries', 'error_name']
        matrices = [[{key: row[key] for key in decision_keys} for row in result['probes']]
                    for result in [candidate_alias, reference_alias]]
        expected_matrix = [
            {'phase': 'protected-owned', 'destination_kind': kind, 'allowed': False,
             'deliveries': 0, 'error_name': 'org.freedesktop.DBus.Error.AccessDenied'}
            for kind in ['protected', 'unique', 'alternate']
        ] + [
            {'phase': 'protected-released', 'destination_kind': kind, 'allowed': True,
             'deliveries': 1, 'error_name': None}
            for kind in ['unique', 'alternate']
        ]
        assert matrices == [expected_matrix, expected_matrix], matrices
        pair_file = evidence / 'actors/destination-alias-pair.json'
        paired = json.loads(pair_file.read_text())
        assert paired['result'] == 'PASS' and paired['scope'] == 'destination-alias', paired
        assert paired['config_hashes'] == hashes and paired['matrix'] == expected_matrix, paired
        assert paired['candidate_shutdown'] == {
            'core_down_reason': 'shutdown', 'listener_down_reason': 'shutdown',
            'socket_removed': True}, paired
        record['destination_alias'] = {
            'config_hashes': hashes, 'matrix': expected_matrix,
            'candidate_shutdown': paired['candidate_shutdown'],
            'pair_sha256': digest(pair_file)}
        properties_pair_file = evidence / 'actors/properties-set-pair.json'
        properties_pair = json.loads(properties_pair_file.read_text())
        assert properties_pair['result'] == 'PASS' and properties_pair['scope'] == 'properties-set'
        properties_hashes = properties_pair['config_hashes']
        assert set(properties_hashes) == {'bus.conf', 'policy.conf', 'rules.conf'}
        assert all(re.fullmatch(r'[0-9a-f]{64}', value) for value in properties_hashes.values())
        assert properties_pair['expected_error'] == 'org.freedesktop.DBus.Error.PropertyReadOnly'
        assert properties_pair['candidate_shutdown'] == {
            'core_down_reason': 'shutdown', 'listener_down_reason': 'shutdown', 'socket_removed': True}
        assert properties_pair['reference_shutdown'] == {'socket_removed': True}
        assert properties_pair['candidate_policy_unchanged'] is True
        assert properties_pair['candidate_authorities_unchanged'] is True
        for phase in ['candidate_after', 'reference_before', 'reference_after']:
            assert properties_pair['config_hashes_' + phase] == properties_hashes
        for backend in ['candidate', 'reference']:
            result = actors['properties-' + backend + '-actor.json']
            assert properties_pair[backend] == {'exit_status': 0, 'report': result}
            assert result['config_hashes_before'] == result['config_hashes_after'] == properties_hashes
            properties = result['properties']
            assert properties['set_actual_error'] == 'org.freedesktop.DBus.Error.PropertyReadOnly'
            assert properties['set_advertised'] and properties['unchanged']
            assert properties['features_before'] == properties['features_after']
        get_all_pair_file = evidence / 'actors/properties-get-all-pair.json'
        get_all_pair = json.loads(get_all_pair_file.read_text())
        assert get_all_pair['result'] == 'PASS' and get_all_pair['scope'] == 'properties-get-all'
        get_all_hashes = get_all_pair['config_hashes']
        assert set(get_all_hashes) == {'bus.conf', 'policy.conf', 'rules.conf'}
        assert all(re.fullmatch(r'[0-9a-f]{64}', value) for value in get_all_hashes.values())
        assert get_all_pair['expected_error'] == 'org.freedesktop.DBus.Error.UnknownInterface'
        assert get_all_pair['candidate_shutdown'] == {
            'core_down_reason': 'shutdown', 'listener_down_reason': 'shutdown', 'socket_removed': True}
        assert get_all_pair['reference_shutdown'] == {'socket_removed': True}
        assert get_all_pair['candidate_policy_unchanged'] is True
        assert get_all_pair['candidate_authorities_unchanged'] is True
        for phase in ['candidate_after', 'reference_before', 'reference_after']:
            assert get_all_pair['config_hashes_' + phase] == get_all_hashes
        for backend in ['candidate', 'reference']:
            result = actors['getall-' + backend + '-actor.json']
            assert get_all_pair[backend] == {'exit_status': 0, 'report': result}
            assert result['config_hashes_before'] == result['config_hashes_after'] == get_all_hashes
            properties = result['properties']
            assert properties['unknown_interface_actual_error'] == 'org.freedesktop.DBus.Error.UnknownInterface'
            assert properties['unknown_interface_expected_error'] == 'org.freedesktop.DBus.Error.UnknownInterface'
            assert properties['consistent'] is True and properties['peer_properties'] == {}
            assert properties['bus_properties'] == {
                'Features': {'signature': 'as', 'value': properties['features']},
                'Interfaces': {'signature': 'as', 'value': properties['interfaces']}}
        api_file = evidence / 'actors/api-dispatch-pair.json'
        pair = json.loads(api_file.read_text())
        assert pair['result'] == 'PASS' and pair['scope'] == 'api-dispatch'
        api_hashes = pair['config_hashes']
        assert set(api_hashes) == {'bus.conf', 'policy.conf', 'rules.conf'}
        assert pair['candidate_policy_coherent'] and pair['candidate_authorities_unchanged']
        assert pair['candidate_shutdown'] == {
            'core_down_reason': 'shutdown', 'listener_down_reason': 'shutdown', 'socket_removed': True}
        assert pair['reference_shutdown'] == {'socket_removed': True}
        for phase in ['candidate_after', 'reference_before', 'reference_after']:
            assert pair['config_hashes_' + phase] == api_hashes
        selection = json.loads((fixtures / 'apps/gao_bus/test/fixtures/api_contract_selection.json').read_text())
        assert selection['total_count'] == 234
        assert pair['candidate_policy_generation_before'] == 1 and pair['candidate_policy_generation_after'] == 2
        for backend in ['candidate', 'reference']:
            result = actors['api-' + backend + '-actor.json']
            assert pair[backend] == {'exit_status': 0, 'report': result}
            assert result['config_hashes_before'] == result['config_hashes_after'] == api_hashes
            assert result['operation_count'] == 234
            for key, count in [('api', 212), ('api_root', 22)]:
                api = result[key]
                expected = selection['backends'][backend][key]
                assert api['contract_failures'] == []
                assert len(api['rows']) == api['operation_count'] == len(api['operation_labels']) == count
                assert api['operation_labels'] == [row['label'] for row in expected]
                assert [{key: row[key] for key in expected[0]} for row in api['rows']] == expected
                assert all(row['result'] == 'PASS' for row in api['rows'])
        record['result'] = 'passed_selected_scope' 
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        (evidence / 'wire-reload.log').write_text(output)
        record['result'] = 'failed'
        record['error'] = 'standalone ExUnit exceeded the frozen 150s deadline'
        raise
    except Exception as error:
        record['result'] = 'failed'
        record['error'] = repr(error)
        raise
    finally:
        account_actors()
        record['actor_evidence_sha256'] = {
            str(path.relative_to(evidence)): digest(path)
            for path in sorted((evidence / 'actors').glob('*')) if path.is_file()}
        record['candidate_hashes_after'] = {name: digest(candidate / name) for name in manifest['files']}
        record['candidate_unchanged'] = record['candidate_hashes_after'] == manifest['files']
        if not record['candidate_unchanged']:
            record['result'] = 'failed'
            record['error'] = 'candidate artifacts changed'
        record['elapsed_seconds'] = time.monotonic() - started
        record['ended_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if (evidence / 'wire-reload.log').is_file():
            record['log_sha256'] = digest(evidence / 'wire-reload.log')
        save()
    assert record['candidate_unchanged'], 'candidate artifacts changed'
    print(json.dumps({'result': record['result'], 'counts': record['counts'],
                      'elapsed_seconds': record['elapsed_seconds']}, sort_keys=True))


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]))
