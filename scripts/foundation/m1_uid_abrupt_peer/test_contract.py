"""Source-prepared controls; synthetic witnesses do not qualify a live kill."""
import copy
import unittest

from contract import validate_abrupt, validate_candidate_binding, validate_kill_selection


def witness():
    # Before/after are independently written examples, not checker-generated output.
    victim, survivor = '#PID<0.2.0>', '#PID<0.3.0>'
    admission = {'uid': 1100, 'monitor': '#Reference<0.2.0>',
                 'counts': {'connections': 1, 'authenticating': 0}}
    cached = {'uid': 1100, 'admission': '#Reference<0.2.0>',
              'monitor': '#Reference<0.20.0>', 'count': 1}
    retained = {'uid': 1100, 'admission': '#Reference<0.3.0>',
                'monitor': '#Reference<0.30.0>', 'count': 1}
    before = {'uid_authorities': {
        'authorities': {'GaoBus.Router': '#PID<0.9.0>'},
        'children': [{'peer': victim}, {'peer': survivor}],
        'supervised': {'active': 2, 'specs': 2, 'workers': 2, 'supervisors': 0},
        'accounting': {'peers': {victim: admission, survivor: {
            'uid': 1100, 'monitor': '#Reference<0.3.0>',
            'counts': {'connections': 1, 'authenticating': 0}}},
            'retired': {}, 'reservations': {}, 'bound_handles': {},
            'reload': None, 'accept_observers': {}},
        'limits': {'global': {'connections': 2, 'authenticating': 0},
                   'peers': {victim: {'connections': 1, 'authenticating': 0},
                             survivor: {'connections': 1, 'authenticating': 0}},
                   'uids': {'1100': {'connections': 2, 'authenticating': 0}},
                   'reservations': 0},
        'names': {'names': [['org.foundation.Uid.Shared', victim, ':1.2', 0,
                             [[survivor, ':1.3', 0]]]],
                  'uniques': [[':1.2', victim], [':1.3', survivor]],
                  'pid_names': [[victim, ':1.2'], [victim, 'org.foundation.Uid.Shared'],
                                [survivor, ':1.3'], [survivor, 'org.foundation.Uid.Shared']],
                  'peers': {victim: cached, survivor: retained},
                  'uid_counts': {'1100': 2}, 'max_names_per_uid': 2},
        'matches': {'entries': [[victim, '#Reference<0.4.0>', {'type': 'signal'}, "type='signal'"]],
                    'peers': {victim: cached}, 'uid_counts': {'1100': 1},
                    'max_matches_per_uid': 2}},
        'peers': [{'peer': victim, 'name': ':1.2'}, {'peer': survivor, 'name': ':1.3'}]}
    after = {'uid_authorities': {
        'authorities': {'GaoBus.Router': '#PID<0.9.0>'},
        'children': [{'peer': survivor}],
        'supervised': {'active': 1, 'specs': 1, 'workers': 1, 'supervisors': 0},
        'accounting': {'peers': {survivor: copy.deepcopy(before['uid_authorities']['accounting']['peers'][survivor])},
                      'retired': {}, 'reservations': {}, 'bound_handles': {},
                      'reload': None, 'accept_observers': {}},
        'limits': {'global': {'connections': 1, 'authenticating': 0},
                   'peers': {survivor: {'connections': 1, 'authenticating': 0}},
                   'uids': {'1100': {'connections': 1, 'authenticating': 0}},
                   'reservations': 0},
        'names': {'names': [['org.foundation.Uid.Shared', survivor, ':1.3', 0, []]],
                  'uniques': [[':1.3', survivor]],
                  'pid_names': [[survivor, ':1.3'], [survivor, 'org.foundation.Uid.Shared']],
                  'peers': {survivor: retained}, 'uid_counts': {'1100': 1},
                  'max_names_per_uid': 2},
        'matches': {'entries': [], 'peers': {}, 'uid_counts': {}, 'max_matches_per_uid': 2}},
        'peers': [{'peer': survivor, 'name': ':1.3'}]}
    join = {'peer': victim, 'unique': ':1.2', 'identity': {'pid': 1202, 'uid': 1100, 'gid': 1100},
            'admission': '#Reference<0.2.0>'}
    event = {'event': 'uid_abrupt_peer_down', 'peer': victim, 'unique': ':1.2',
             'credentials': {'pid': 1202, 'uid': 1100, 'gid': 1100},
             'operation': 'Process.exit(peer, :kill)', 'down': {
                 'peer': victim, 'monitor': '#Reference<0.99.0>', 'reason': 'killed'},
             'explicit_cleanup_calls': [], 'daemon_elapsed_ms': 2}
    return event, before, copy.deepcopy(after), join


class AbruptContract(unittest.TestCase):
    def test_actual_peer_kill_witness_and_exact_automatic_reclamation(self):
        validate_abrupt(*witness(), elapsed_ms=20)

    def test_queued_death_keeps_owner_and_its_admission(self):
        event, before, after, join = witness()
        victim, owner = join['peer'], '#PID<0.3.0>'
        before['uid_authorities']['names']['names'] = [
            ['org.foundation.Uid.Shared', owner, ':1.3', 0, [[victim, ':1.2', 0]]]]
        validate_abrupt(event, before, after, join, elapsed_ms=20)

    def test_rejects_forged_or_missing_kill_and_identity_facts(self):
        mutations = [
            lambda e, b, a, j: e.update(event='peer_closed'),
            lambda e, b, a, j: e.update(operation='actor EOF'),
            lambda e, b, a, j: e['down'].update(reason='normal'),
            lambda e, b, a, j: e['down'].update(peer='#PID<0.8.0>'),
            lambda e, b, a, j: e['down'].update(monitor='missing'),
            lambda e, b, a, j: e.update(unique=':1.9'),
            lambda e, b, a, j: e['credentials'].update(uid=0),
            lambda e, b, a, j: e['credentials'].update(pid=999),
            lambda e, b, a, j: e.update(explicit_cleanup_calls=['peer_disconnected']),
            lambda e, b, a, j: e.update(daemon_elapsed_ms=1001),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                values = witness()
                mutate(*values)
                with self.assertRaises((AssertionError, KeyError)):
                    validate_abrupt(*values, elapsed_ms=20)

    def test_rejects_ledger_leak_extra_free_and_authority_or_survivor_drift(self):
        mutations = [
            lambda e, b, a, j: a['uid_authorities']['authorities'].update({'GaoBus.Router': '#PID<0.99.0>'}),
            lambda e, b, a, j: a['uid_authorities']['names']['uid_counts'].update({'1100': 2}),
            lambda e, b, a, j: a['uid_authorities']['names']['uid_counts'].clear(),
            lambda e, b, a, j: a['uid_authorities']['matches']['entries'].extend(b['uid_authorities']['matches']['entries']),
            lambda e, b, a, j: a['uid_authorities']['names']['names'][0].__setitem__(1, j['peer']),
            lambda e, b, a, j: a['uid_authorities']['names']['names'][0][4].append([j['peer'], j['unique'], 0]),
            lambda e, b, a, j: a['uid_authorities']['names']['peers']['#PID<0.3.0>'].update(monitor='#Reference<0.999.0>'),
            lambda e, b, a, j: a['uid_authorities']['accounting']['peers'].update({j['peer']: b['uid_authorities']['accounting']['peers'][j['peer']]}),
            lambda e, b, a, j: a['uid_authorities']['limits']['global'].update(connections=2),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                values = copy.deepcopy(witness())
                mutate(*values)
                with self.assertRaises((AssertionError, KeyError)):
                    validate_abrupt(*values, elapsed_ms=20)

    def test_fixed_outer_cleanup_deadline(self):
        with self.assertRaises(AssertionError):
            validate_abrupt(*witness(), elapsed_ms=1001)

    def test_requires_exact_future_candidate_binding(self):
        validate_candidate_binding({'source_sha256': 'b' * 64}, 'a' * 64, 'a' * 64, 'b' * 64)
        for actual, expected, source in [('c' * 64, 'a' * 64, 'b' * 64),
                                         ('a' * 64, 'a' * 64, 'c' * 64),
                                         ('a' * 64, None, 'b' * 64),
                                         ('a' * 64, 'a' * 64, 'f5dfe03ced34c9b24e69b780588156330a74d2ee025a07dcf2dd0e5d395eab92')]:
            with self.subTest(binding=(actual, expected, source)):
                with self.assertRaises(AssertionError):
                    validate_candidate_binding({'source_sha256': 'b' * 64}, actual, expected, source)

    def test_missing_duplicate_or_wrong_selected_kill_is_rejected(self):
        event, before, after, join = witness()
        record = dict(label='match_down_reclaims', event=event, before=before,
                      after=after, join=join, elapsed_ms=20)
        report = dict(selected=['uid_matches'], outcomes={'uid_matches': {
            'status': 'passed', 'abrupt_kill_labels': ['match_down_reclaims']}},
            abrupt_kills=[record])
        validate_kill_selection(report)
        mutations = [lambda r: r['abrupt_kills'].clear(),
                     lambda r: r['abrupt_kills'].append(copy.deepcopy(record)),
                     lambda r: r['abrupt_kills'][0].update(label='owner_down_promotes'),
                     lambda r: r['outcomes']['uid_matches'].update(status='blocked'),
                     lambda r: r.update(selected=[])]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaises((AssertionError, KeyError)):
                    validate_kill_selection(changed)


if __name__ == '__main__':
    unittest.main()
