"""FD03 mixed-frame fixture; original wire/client/resource implementation."""
import array
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SHARED = Path(sys.argv[3]) if __name__ == '__main__' and len(sys.argv) == 5 else ROOT / 'scripts/foundation/p08_fd01_singleton_resources'
BUNDLES = Path(sys.argv[4]) if __name__ == '__main__' and len(sys.argv) == 5 else ROOT / 'scripts/foundation/p08_fd03_different_bundles'
BUNDLE_ACTOR_SHA = '78f4850aed6e6d2e946c2ce29de7d367d819136bfd7244a740b1001b8b52a66b'
source = (BUNDLES / 'actor.py').read_text()
assert hashlib.sha256(source.encode()).hexdigest() == BUNDLE_ACTOR_SHA, 'original bundle actor drift'
tree = ast.parse(source)
shared_assign = [n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SHARED' for t in n.targets)]
assert len(shared_assign) == 1, 'original actor shared-path shape drift'
shared_assign[0].value = ast.Name(id='_mixed_shared', ctx=ast.Load())
frozen_ns = {'__file__': str(BUNDLES / 'actor.py'), '__name__': 'fd03_mixed_original_actor', '_mixed_shared': SHARED}
exec(compile(ast.fix_missing_locations(tree), str(BUNDLES / 'actor.py'), 'exec'), frozen_ns)
S = frozen_ns['S']
Client, load_wire = frozen_ns['Client'], frozen_ns['load_wire']
fd_record, fd_state, identity = frozen_ns['fd_record'], frozen_ns['fd_state'], frozen_ns['identity']
close_descriptor, healthy, digest = frozen_ns['close_descriptor'], frozen_ns['healthy'], frozen_ns['digest']

validator = copy.deepcopy(next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'validate_transfer'))
old_serial = ast.dump(ast.parse('100+ordinal', mode='eval').body, include_attributes=False)
matches = []
class ResourceSerial(ast.NodeTransformer):
    def visit_BinOp(self, node):
        if ast.dump(node, include_attributes=False) == old_serial:
            matches.append(node)
            return ast.parse('100+2*ordinal', mode='eval').body
        return self.generic_visit(node)
validator = ResourceSerial().visit(validator)
assert len(matches) == 1, 'original resource serial shape drift'
exec(compile(ast.fix_missing_locations(ast.Module(body=[validator], type_ignores=[])), str(HERE / 'actor.py'), 'exec'), frozen_ns)
validate_transfer = frozen_ns['validate_transfer']
ACTOR_ADAPTATION = dict(original_sha256=BUNDLE_ACTOR_SHA,
                       executed_ast_sha256=hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest(),
                       validator_ast_sha256=hashlib.sha256(ast.dump(validator, include_attributes=False).encode()).hexdigest())

def marker_packet(wire, target):
    return wire.frame(4, 101, [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
                              (3, 's', 'Marker'), (6, 's', target), (8, 'g', '')], b'')

def validate_marker(client, message, sender):
    event = client.events[-1]
    assert bytes.fromhex(event['wire_hex'])[:4] == b'l\x04\x00\x01', 'invalid Marker fixed header'
    assert message['type'] == 4 and message['serial'] == 101, 'unexpected middle frame'
    assert message['fields'] == {1: '/foundation', 2: 'org.foundation.Transport', 3: 'Marker',
                                 6: client.name, 7: sender, 8: ''}, 'marker identity/header mismatch'
    assert message['body'] == b'' and message['fds'] == [], 'marker must have no body/right'
    assert event['rights'] == 0 and event['fd_targets'] == [], 'marker ancillary mismatch'
    return event.copy()

class Workload(frozen_ns['Workload']):
    def exercise(self):
        assert self.state == 'open' and set(self.clients) == {'source', 'target'}
        assert not self.original_fds and not self.received_fds
        source_client, target = self.clients['source'], self.clients['target']
        prepared, sends, transfers = [], [], []
        for content in (b'FD-A', b'FD-B'):
            original, writer = os.pipe()
            self.original_fds.append(original)
            try:
                os.set_blocking(writer, False)
                written = os.write(writer, content)
                assert written == 4, 'short pipe write'
            finally:
                closed = close_descriptor('writer', writer, lambda: os.close(writer))
            prepared.append(dict(written_bytes=written, writer_close=closed))
        originals = [fd_record(fd) for fd in self.original_fds]
        assert len({(r['dev'], r['ino']) for r in originals}) == 2, 'same pipe for different bundles'
        middle_sent = None
        for i, original in enumerate(self.original_fds):
            serial = 100 + 2*i
            packet = self.wire.signal(serial, target.name, 1, self.wire.u32(0), 'h')
            with source_client.deadline(S.WRITER_MS):
                count = source_client.sock.sendmsg([packet], [(S.socket.SOL_SOCKET, S.socket.SCM_RIGHTS, array.array('i', [original]))])
                assert 0 < count <= len(packet), 'invalid actual send byte count'
                source_client.sock.sendall(packet[count:])
            sends.append(dict(role='source', phase='active', direction='sent', type=4, serial=serial,
                              fields={'1': '/foundation', '2': 'org.foundation.Transport', '3': 'Resource',
                                      '6': target.name, '8': 'h', '9': 1}, body_hex=self.wire.u32(0).hex(),
                              wire_hex=packet.hex(), wire_sha256=digest(packet), wire_bytes=len(packet), rights=1,
                              sendmsg_bytes=count, completed_bytes=len(packet), right_fd=originals[i]))
            if i == 0:
                marker = marker_packet(self.wire, target.name)
                with source_client.deadline(S.WRITER_MS):
                    source_client.sock.sendall(marker)
                middle_sent = dict(role='source', phase='active', direction='sent', type=4, serial=101,
                                   fields={'1': '/foundation', '2': 'org.foundation.Transport', '3': 'Marker',
                                           '6': target.name, '8': ''}, body_hex='', rights=0,
                                   wire_hex=marker.hex(), wire_sha256=digest(marker), wire_bytes=len(marker),
                                   completed_bytes=len(marker), send_operation='sendall')
        middle_received = None
        for position in range(3):
            message = target.receive()  # No frame filter or skipped marker.
            self.received_fds.extend(message['fds'])  # Own unexpected rights before validation.
            if position == 1:
                middle_received = validate_marker(target, message, source_client.name)
            else:
                i = position // 2
                transfer = validate_transfer(target, message, source_client.name, self.original_fds[i], i)
                transfer.update(prepared[i], sent=sends[i])
                transfers.append(transfer)
        assert len(set(self.original_fds + self.received_fds)) == 4, 'four actual readers required'
        health = [healthy(source_client, 110), healthy(target, 111)]
        self.state = 'checked'
        return dict(op='exercise', **identity(), transfers=transfers,
                    marker=dict(sent=middle_sent, received=middle_received), health=health, held=True,
                    connections=[c.receipt() for c in self.clients.values()], fd_state=fd_state())

def main():
    assert len(sys.argv) == 5
    path, wire, shared, bundles = sys.argv[1:]
    assert Path(shared) == SHARED and Path(bundles) == BUNDLES
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert path == '/run/osbus-fd-quotas/bus' and os.getuid() == 1100
    worker = Workload(path, load_wire(wire))
    print(json.dumps(dict(ok=True, result=dict(**identity(), op='ready', fd_state=worker.baseline,
                                              connections=[], actor_adaptation=ACTOR_ADAPTATION))), flush=True)
    S.serve(worker, sys.stdin, sys.stdout)

if __name__ == '__main__':
    main()
