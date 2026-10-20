"""Buffered same-clock packaged diagnostic receipts; no workload acceptance changes."""
import json
from itertools import chain
import re
import time

SAVE_BUFFER_CHARACTERS = 64 * 1024


class Diagnostics:
    def __init__(self, nonce):
        assert re.fullmatch('[0-9a-f]{32}', nonce), 'diagnostic nonce'
        self.nonce = nonce
        self.rows = []
        self.persisted = 0
        self.save_id = 0

    def record(self, row):
        self.rows.append(dict(schema=1, nonce=self.nonce, **row))

    def save_report(self, report, destination, operation_index):
        self.save_id += 1
        phases = dict(save_started_ns=time.monotonic_ns())
        row = dict(owner='save', save_id=self.save_id, operation_index=operation_index, phases=phases,
                   phase_schema=2, algorithm='bounded-iterencode-v2',
                   buffer_characters=SAVE_BUFFER_CHARACTERS, payload_characters=0,
                   write_chunks=0, max_write_characters=0,
                   boundary='encoding and UTF-8 open/write/close interleave; single encoder chunks may be larger')
        try:
            phases['encode_write_started_ns'] = time.monotonic_ns()
            # The live report remains shared; this does not make saves atomic.
            encoder = json.JSONEncoder(indent=2, sort_keys=True)
            with destination.open('w', encoding='utf-8') as output:
                parts, buffered = [], 0
                def flush():
                    payload = ''.join(parts)
                    output.write(payload)
                    row['payload_characters'] += len(payload)
                    row['write_chunks'] += 1
                    row['max_write_characters'] = max(row['max_write_characters'], len(payload))
                    parts.clear()
                for chunk in chain(encoder.iterencode(report), ('\n',)):
                    offset = 0
                    while offset < len(chunk):
                        length = min(SAVE_BUFFER_CHARACTERS - buffered, len(chunk) - offset)
                        parts.append(chunk[offset:offset + length])
                        offset += length
                        buffered += length
                        if buffered == SAVE_BUFFER_CHARACTERS:
                            flush()
                            buffered = 0
                if buffered:
                    flush()
            phases['encode_write_finished_ns'] = time.monotonic_ns()
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            phases['save_finished_ns'] = time.monotonic_ns()
            self.record(row)

    def persist(self, destination):
        # Only completed immutable receipts are appended. Marks themselves do
        # no I/O; this is called at the existing main-thread save opportunities.
        rows = self.rows[self.persisted:]
        with destination.open('a') as output:
            for row in rows:
                output.write(json.dumps(row, sort_keys=True) + '\n')
        self.persisted += len(rows)
