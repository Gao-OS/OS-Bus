"""Fixture-only regressions; no bus or VM traffic."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('method_matrix_under_test', HERE / 'run.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class MethodMatrixTests(unittest.TestCase):
    def test_aggregate_only_success_cannot_qualify_ten_subcases(self):
        report = dict(selected=matrix.SELECTED, outcomes={
            key: dict(status='passed', evidence='aggregate-only')
            for key in matrix.SELECTED
        })
        with self.assertRaises(AssertionError):
            matrix.complete(report)

    def test_required_manifest_keeps_all_ten_and_original_selection(self):
        self.assertEqual(matrix.SELECTED, [
            'SEC-14.request-name-signature', 'SEC-14.release-name-signature',
            'SEC-14.get-name-owner-signature', 'SEC-14.name-has-owner-signature',
            'SEC-14.add-match-signature', 'SEC-14.remove-match-signature',
            'SEC-14.properties-get-signature', 'SEC-14.list-names-signature',
            'SEC-14.list-names-interface', 'SEC-14.properties-get-path'
        ])
        self.assertEqual(matrix.WORKLOAD['inherited_security_selection'],
            [f'SEC-{number:02d}' for number in range(1, 18)] +
            ['SYS-02', 'FAIL-01', 'FAIL-02', 'RES-03'])
        self.assertEqual(matrix.WORKLOAD['guest_timeout_seconds'], 120)
        self.assertEqual(matrix.WORKLOAD['host_timeout_seconds'], 900)


# These response fixtures use the unchanged independent primitive encoder,
# never the production encoder or transport.
import copy
import struct

FEATURES_FRAME = bytes.fromhex(
    '6c02000108000000090000000f000000'
    '050175002a0000000801670001760000'
    '0261730000000000')


def response_frame(serial, signature='', body=(), error=None):
    headers = bytearray()
    for code, kind, value in [(4, 's', error), (5, 'u', serial),
            (7, 's', matrix.BUS), (8, 'g', signature or None)]:
        if value is not None:
            matrix.wire.original.pad(headers, 8)
            headers.append(code)
            matrix.wire.original.encode_value(headers, 'g', kind)
            matrix.wire.original.encode_value(headers, kind, value)
    payload = bytearray()
    if signature == 'v':
        payload.extend(bytes.fromhex('0261730000000000'))
    else:
        for kind, value in zip(matrix.wire.original.signatures(signature), body):
            matrix.wire.original.encode_value(payload, kind, value)
    prefix = struct.pack('<BBBBIII', ord('l'), 3 if error else 2, 0, 1,
        len(payload), 9, len(headers))
    matrix.wire.original.pad(headers, 8)
    return prefix + headers + payload


def exchange_fixture(method, serial, signature='', body=(), error=None):
    return dict(request_serial=serial, request_hex=matrix.wire.packet(serial, **method).hex(),
        reply=matrix.wire.decode_frame(response_frame(serial, signature, body, error)))


def baseline_fixture():
    identities, peers = {}, []
    for index, (role, uid) in enumerate([('observer', 1100), ('test', 1101)], 1):
        pid, unique = 2100 + index, f':1.{index}'
        identities[role] = dict(pid=pid, uid=uid, gid=uid, unique=unique,
            proc_status=f'Pid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        peers.append(dict(peer=f'#PID<0.{index}.0>', name=unique,
            credentials=dict(pid=pid, uid=uid, gid=uid),
            names=[unique] + ([matrix.OBSERVER] if role == 'observer' else []),
            match_rules=False, capabilities=0))
    zero = dict.fromkeys(['authenticating', 'frame_bytes', 'frame_fds',
        'ingress_messages', 'ingress_bytes', 'ingress_fds',
        'egress_messages', 'egress_bytes', 'egress_fds'], 0)
    state = dict(event='snapshot', router='#PID<0.99.0>', peers=peers,
        names=[matrix.BUS, matrix.OBSERVER, ':1.1', ':1.2'],
        queues=[dict(name=matrix.OBSERVER, owner=peers[0]['peer'], unique=':1.1', flags=0, queue=[])],
        usage={}, policy='native policy generation 1')
    state['usage'] = {'global': dict(zero, connections=2), 'reservations': 0,
        'peers': [dict(peer=peer['peer'], counts=dict(zero, connections=1)) for peer in peers],
        'uids': [dict(uid=uid, counts=dict(zero, connections=1)) for uid in (1100, 1101)]}
    return state, identities


def settled_fixture(state):
    sample = dict(event='metrics', snapshot=copy.deepcopy(state), policy_queue=0, router_queue=0)
    return dict(state=copy.deepcopy(state), samples=[copy.deepcopy(sample), sample], attempts=2, elapsed_ms=1)


def shutdown_fixture():
    owned = [dict(pid=pid, pgid=pid, sid=pid, command=[f'owned-{pid}']) for pid in (2001, 2002, 2003)]
    return dict(owned=owned, shutdown=[dict(pid=row['pid'], command=row['command'],
        returncode=0, method='eof', pid_absent=True, group_absent=True) for row in owned],
        shutdown_errors=[], socket_removed=True, actor_pids_absent=dict(observer=True, test=True))


def report_fixture():
    state, identities = baseline_fixture()
    report = dict(selected=matrix.SELECTED[:], execution_order=matrix.SELECTED[:], outcomes={}, **shutdown_fixture())
    serial, observer_serial = 2, 3
    for index, case in enumerate(matrix.WORKLOAD['cases']):
        method = {key: case[key] for key in ('member', 'signature', 'body', 'interface', 'path')}
        detail = dict(index=index, case=copy.deepcopy(case), before=settled_fixture(state),
            after_error=settled_fixture(state), retired=settled_fixture(state),
            identities_before=copy.deepcopy(identities), identities_after=copy.deepcopy(identities),
            invalid=exchange_fixture(method, serial, 's', ['Invalid method arguments'], case['error']),
            followups=[], effects=[])
        plan = matrix.followup_plan(case)
        for step, following in enumerate(plan):
            member = following['member']
            if member in ('RequestName', 'ReleaseName'):
                signature, body = 'u', [1]
            elif member == 'GetNameOwner':
                signature, body = 's', [identities['test' if following['body'] == [matrix.OWNED] else 'observer']['unique']]
            elif member == 'NameHasOwner':
                signature, body = 'b', [following['body'] == [matrix.OBSERVER]]
            elif member == 'Get':
                signature, body = 'v', []
            elif member == 'ListNames':
                signature, body = 'as', [state['names']]
            else:
                signature, body = '', []
            detail['followups'].append(exchange_fixture(following, serial + step + 1, signature, body))
            if step == 0 and member in ('RequestName', 'AddMatch'):
                changed = copy.deepcopy(state)
                if member == 'RequestName':
                    changed['names'].append(matrix.OWNED)
                    changed['peers'][1]['names'].append(matrix.OWNED)
                    changed['queues'].append(dict(name=matrix.OWNED, owner=changed['peers'][1]['peer'], unique=':1.2', flags=0, queue=[]))
                else:
                    changed['peers'][1]['match_rules'] = True
                detail['effects'].append(dict(after_step=0, observation=settled_fixture(changed)))
        detail['probe'] = dict(elapsed_ms=1, calls=[
            exchange_fixture(matrix.request('GetNameOwner', 's', [matrix.OBSERVER]), observer_serial, 's', [':1.1']),
            exchange_fixture(matrix.request('GetId'), observer_serial + 1, 's', ['fixture-bus-id'])])
        report['outcomes'][case['id']] = dict(status='passed', evidence=detail)
        serial += len(plan) + 1
        observer_serial += 2
    report['counts'] = matrix.counts(report['outcomes'])
    return report


class WireEvidenceTests(unittest.TestCase):
    def test_fixed_little_and_big_endian_empty_vectors(self):
        for raw in [bytes.fromhex('6c020001000000000900000000000000'),
                bytes.fromhex('42020001000000000000000900000000')]:
            decoded = matrix.wire.decode_frame(raw)
            self.assertEqual((decoded['type'], decoded['serial'], decoded['signature'], decoded['body']), (2, 9, '', []))
            self.assertEqual(decoded['frame_hex'], raw.hex())

    def test_fixed_features_variant_and_header_padding(self):
        decoded = matrix.wire.decode_frame(FEATURES_FRAME)
        self.assertEqual(decoded['reply_serial'], 42)
        self.assertEqual(decoded['body'], [dict(signature='as', value=[])])
        padded = bytearray(FEATURES_FRAME)
        struct.pack_into('<I', padded, 12, 16)
        self.assertEqual(matrix.wire.decode_frame(bytes(padded))['body'], decoded['body'])

    def test_truncated_trailing_and_unsupported_variant_rejected(self):
        unsupported = bytearray(FEATURES_FRAME)
        unsupported[-7:-5] = b'uu'
        truncated_variant = bytearray(FEATURES_FRAME[:-5])
        struct.pack_into('<I', truncated_variant, 4, 3)
        malformed_null = bytearray(FEATURES_FRAME)
        malformed_null[-5] = 1
        for raw in (FEATURES_FRAME[:-1], FEATURES_FRAME + b'\0', bytes(unsupported), bytes(truncated_variant), bytes(malformed_null)):
            with self.subTest(raw=raw.hex()), self.assertRaises(AssertionError):
                matrix.wire.decode_frame(raw)

    def test_duplicate_header_and_bad_padding_rejected(self):
        duplicate = bytearray(FEATURES_FRAME)
        duplicate[24] = 5
        padding = bytearray(FEATURES_FRAME)
        padding[31] = 1
        for raw in (bytes(duplicate), bytes(padding)):
            with self.assertRaises(AssertionError):
                matrix.wire.decode_frame(raw)

    def test_raw_error_exchange_requires_exact_request_and_serial(self):
        case = matrix.WORKLOAD['cases'][8]
        method = {key: case[key] for key in ('member', 'signature', 'body', 'interface', 'path')}
        value = exchange_fixture(method, 42, 's', ['Unknown interface'], case['error'])
        self.assertEqual(matrix.exchange(value, method, case['error'])['error'], case['error'])
        mutations = []
        wrong_raw = copy.deepcopy(value)
        wrong_raw['request_hex'] = matrix.wire.packet(42, **matrix.request('ListNames')).hex()
        mutations.append(wrong_raw)
        wrong_serial = copy.deepcopy(value)
        wrong_serial['reply'] = matrix.wire.decode_frame(response_frame(43, 's', ['Unknown interface'], case['error']))
        mutations.append(wrong_serial)
        altered_parsed = copy.deepcopy(value)
        altered_parsed['reply']['body'] = ['fabricated diagnostic']
        mutations.append(altered_parsed)
        for mutation in mutations:
            with self.assertRaises(AssertionError):
                matrix.exchange(mutation, method, case['error'])
        with self.assertRaises(AssertionError):
            matrix.exchange(value, method, matrix.BUS + '.Error.InvalidArgs')


class FullEvidenceTests(unittest.TestCase):
    def test_complete_evidence_fixture_qualifies(self):
        matrix.complete(report_fixture())

    def test_missing_duplicate_reordered_and_unexecuted_rows_rejected(self):
        for kind in ('missing', 'duplicate', 'reordered', 'unexecuted', 'unknown_status', 'wrong_count', 'boolean_count'):
            report = report_fixture()
            if kind == 'missing':
                del report['outcomes'][matrix.SELECTED[-1]]
            elif kind == 'duplicate':
                report['execution_order'][-1] = matrix.SELECTED[0]
            elif kind == 'reordered':
                report['execution_order'].reverse()
            elif kind == 'unexecuted':
                report['outcomes'][matrix.SELECTED[-1]]['status'] = 'blocked'
            elif kind == 'unknown_status':
                report['outcomes'][matrix.SELECTED[-1]]['status'] = 'skipped'
            elif kind == 'wrong_count':
                report['counts']['executed'] = 9
            else:
                report['counts']['failed'] = False
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                matrix.complete(report)

    def test_state_identity_effect_and_probe_drift_rejected(self):
        for kind in ('policy', 'router', 'uid_credit', 'peer_credit', 'boolean_credit', 'credential', 'effect', 'unretired_match', 'probe_deadline', 'probe_serial'):
            report = report_fixture()
            detail = report['outcomes'][matrix.SELECTED[0]]['evidence']
            state = copy.deepcopy(detail['after_error']['state'])
            if kind in ('policy', 'router'):
                state[kind] += ' drift'
            elif kind == 'uid_credit':
                state['usage']['uids'][1]['counts']['ingress_bytes'] = 1
            elif kind == 'peer_credit':
                state['usage']['peers'][1]['counts']['egress_messages'] = 1
            elif kind == 'boolean_credit':
                state['usage']['uids'][1]['counts']['ingress_bytes'] = False
            elif kind == 'credential':
                detail['identities_after']['test']['pid'] += 1
            elif kind == 'effect':
                detail['effects'] = []
            elif kind == 'unretired_match':
                state['peers'][1]['match_rules'] = True
                detail['retired'] = settled_fixture(state)
            elif kind == 'probe_deadline':
                detail['probe']['elapsed_ms'] = 1001
            else:
                detail['probe']['calls'][1]['request_serial'] += 1
            if kind in ('policy', 'router', 'uid_credit', 'peer_credit', 'boolean_credit'):
                detail['after_error'] = settled_fixture(state)
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                matrix.complete(report)

    def test_owned_teardown_must_reap_groups_actors_and_socket(self):
        for kind in ('socket', 'group', 'actor', 'exit', 'signal', 'session', 'missing', 'error'):
            report = shutdown_fixture()
            if kind == 'socket':
                report['socket_removed'] = False
            elif kind == 'group':
                report['shutdown'][0]['group_absent'] = False
            elif kind == 'actor':
                report['actor_pids_absent']['test'] = False
            elif kind == 'exit':
                report['shutdown'][0]['returncode'] = 1
            elif kind == 'signal':
                report['shutdown'][0]['method'] = 'kill'
            elif kind == 'session':
                report['owned'][0]['sid'] = 9999
            elif kind == 'missing':
                report['shutdown'].pop()
            else:
                report['shutdown_errors'] = ['cleanup failed']
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                matrix.validate_shutdown(report)


class QualityEvidenceTests(unittest.TestCase):
    def test_illegal_boolean_two_rejected_in_both_endians(self):
        # Fixed independent frames: signature b, body uint32 2, serial 9.
        for raw in (
                bytes.fromhex('6c020001040000000900000007000000080167000162000002000000'),
                bytes.fromhex('42020001000000040000000900000007080167000162000000000002')):
            with self.subTest(frame=raw.hex()), self.assertRaises(AssertionError):
                matrix.wire.decode_frame(raw)

    def test_legal_boolean_zero_and_one_kept_in_both_endians(self):
        headers = (
            bytes.fromhex('6c0200010400000009000000070000000801670001620000'),
            bytes.fromhex('420200010000000400000009000000070801670001620000'))
        for header, zero, one in (
                (headers[0], bytes.fromhex('00000000'), bytes.fromhex('01000000')),
                (headers[1], bytes.fromhex('00000000'), bytes.fromhex('00000001'))):
            for body, expected in ((zero, False), (one, True)):
                with self.subTest(frame=(header + body).hex()):
                    reply = matrix.wire.decode_frame(header + body)
                    self.assertEqual(reply['signature'], 'b')
                    self.assertEqual(reply['body'], [expected])
                    self.assertIs(type(reply['body'][0]), bool)

    def test_list_names_extra_missing_and_duplicate_baseline_names_rejected(self):
        for step in (0, 1):
            for mutation in ('extra', 'missing', 'duplicate'):
                report = report_fixture()
                detail = report['outcomes']['SEC-14.list-names-signature']['evidence']
                names = detail['before']['state']['names'][:]
                self.assertEqual(set(names), {matrix.BUS, matrix.OBSERVER,
                    detail['identities_before']['observer']['unique'],
                    detail['identities_before']['test']['unique']})
                if mutation == 'extra':
                    self.assertNotIn('org.foundation.Forbidden', names)
                    names.append('org.foundation.Forbidden')
                elif mutation == 'missing':
                    names.remove(matrix.OBSERVER)
                else:
                    names.append(matrix.BUS)
                value = detail['followups'][step]
                # Keep the valid request, serial and all trusted snapshots intact.
                value['reply'] = matrix.wire.decode_frame(response_frame(
                    value['request_serial'], 'as', [names]))
                with self.subTest(step=step, mutation=mutation), self.assertRaises(AssertionError):
                    matrix.complete(report)

    def test_list_names_baseline_order_variation_accepted(self):
        report = report_fixture()
        detail = report['outcomes']['SEC-14.list-names-signature']['evidence']
        for value in detail['followups']:
            names = list(reversed(detail['before']['state']['names']))
            value['reply'] = matrix.wire.decode_frame(response_frame(
                value['request_serial'], 'as', [names]))
        matrix.complete(report)


import hashlib
import os
import shutil
import tempfile


def candidate_fixture(directory):
    source, frozen = directory / 'source', directory / 'frozen'
    source.mkdir()
    frozen.mkdir()
    manifest = dict(version=1, not_a_release=True, files={}, file_modes={})
    for name, content, source_mode, frozen_mode in (
            ('data', b'candidate-data\n', 0o644, 0o444),
            ('bin/tool', b'#!/bin/sh\nexit 0\n', 0o755, 0o555)):
        original, copied = source / name, frozen / name
        original.parent.mkdir(parents=True, exist_ok=True)
        copied.parent.mkdir(parents=True, exist_ok=True)
        original.write_bytes(content)
        original.chmod(source_mode)
        shutil.copyfile(original, copied)
        copied.chmod(frozen_mode)
        manifest['files'][name] = hashlib.sha256(content).hexdigest()
        manifest['file_modes'][name] = source_mode
    return frozen, manifest


class CandidateModeTests(unittest.TestCase):
    def test_nix_readonly_data_and_executable_accept_with_source_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            frozen, manifest = candidate_fixture(Path(temporary))
            original_manifest = copy.deepcopy(manifest)
            verified = matrix.validate_candidate(frozen, manifest)
            self.assertEqual(manifest, original_manifest)
            self.assertEqual(verified['files']['data']['source_mode'], 0o644)
            self.assertEqual(verified['files']['data']['frozen_mode'], 0o444)
            self.assertEqual(verified['files']['bin/tool']['source_mode'], 0o755)
            self.assertEqual(verified['files']['bin/tool']['frozen_mode'], 0o555)
            for name, row in verified['files'].items():
                self.assertEqual(row['sha256'], manifest['files'][name])
                self.assertEqual(row['frozen_mode'], row['expected_frozen_mode'])
                self.assertEqual(row['file_type'], 'regular')

    def test_writable_or_wrong_executable_modes_rejected(self):
        for name, mode in (('data', 0o644), ('bin/tool', 0o755),
                ('data', 0o555), ('bin/tool', 0o444), ('data', 0o400)):
            with tempfile.TemporaryDirectory() as temporary:
                frozen, manifest = candidate_fixture(Path(temporary))
                (frozen / name).chmod(mode)
                with self.subTest(name=name, mode=oct(mode)), self.assertRaises(AssertionError):
                    matrix.validate_candidate(frozen, manifest)

    def test_changed_bytes_rejected_even_with_correct_readonly_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            frozen, manifest = candidate_fixture(Path(temporary))
            data = frozen / 'data'
            data.chmod(0o644)
            data.write_bytes(b'changed-candidate-data\n')
            data.chmod(0o444)
            with self.assertRaises(AssertionError):
                matrix.validate_candidate(frozen, manifest)

    def test_nonregular_and_symlink_files_or_parents_rejected(self):
        for kind in ('directory', 'fifo', 'file_symlink', 'parent_symlink', 'root_symlink'):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                frozen, manifest = candidate_fixture(directory)
                if kind == 'root_symlink':
                    alias = directory / 'alias'
                    alias.symlink_to(frozen, target_is_directory=True)
                    frozen = alias
                elif kind == 'parent_symlink':
                    (frozen / 'bin').rename(directory / 'original-bin')
                    (frozen / 'bin').symlink_to(directory / 'original-bin', target_is_directory=True)
                else:
                    data = frozen / 'data'
                    data.unlink()
                    if kind == 'directory':
                        data.mkdir()
                    elif kind == 'fifo':
                        os.mkfifo(data, 0o444)
                    else:
                        data.symlink_to(directory / 'source/data')
                with self.subTest(kind=kind), self.assertRaises(AssertionError):
                    matrix.validate_candidate(frozen, manifest)

    def test_incompatible_source_mode_or_incomplete_mode_manifest_rejected(self):
        for kind in ('source_mode', 'missing_mode'):
            with tempfile.TemporaryDirectory() as temporary:
                frozen, manifest = candidate_fixture(Path(temporary))
                if kind == 'source_mode':
                    manifest['file_modes']['data'] = 0o600
                else:
                    del manifest['file_modes']['data']
                with self.subTest(kind=kind), self.assertRaises(AssertionError):
                    matrix.validate_candidate(frozen, manifest)


if __name__ == '__main__':
    unittest.main()
