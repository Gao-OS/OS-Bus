# Independent FD02/core partial-body fixture

Offline implementation only. Runtime and index are NOT RUN; full qualification is false/L0.

Resource100 has a complete independently decoded header and a four-byte h/index0 body.
The prefix contains the full header, alignment padding and exactly three body bytes;
only its final byte remains withheld. Actor and oracle independently derive the boundary
from wire lengths and assert offset=body_start+3=len(packet)-1. Prefix-right attaches
one PIPE reader to that prefix; last-byte-right sends all but its final byte plainly,
then that byte with one right. Both modes run on Gao/reference: two combinations,
four observations. No broker recvmsg coalescing is claimed.

The unchanged FD01 singleton lifecycle and full oracle remain imported read-only;
the accepted hash/20-node AST adaptation replaces only the active range. Explicit
prefix -> externally retained FIFO -> strict target health112 -> externally retained
again -> finish barriers prevent premature suffix/resource/rights and source health.
Finish adds exactly one byte, zero rights. Full Resource100 wire/header/body/sender/
destination, PIPE+EOF, writer/readers/socket EBADF, held inventories, warmed numeric
recovery, Gao scalar/configuration recovery and finite teardown remain strict.
Gao Peer read_socket trims frame credits to actual buffered bytes plus incoming_fds;
process_frame incomplete arms read without routing. Therefore retained source buffer
and global/UID1100/source-peer frame_bytes equal the parsed prefix extent (139 for
current :1.2 fixture); frame_fds=1. All other scalar fields match connected baseline.
Reference uses only kernel inventories. No telemetry is skipped or fabricated.

New seven-file fixture and seven read-only singleton inputs are packaged separately.
Bound FD02_PIPE_FIXTURES and --reuse-fixtures agree. Nix fixture/export/runtime names
use partial-body; candidate16 remains 80 artifacts/71 sources, not a release.
Input/provenance freezing and executable resolution must precede parent runtime.
Native offline socketpair/SCM_RIGHTS tests are local unit relays; complete synthetic
oracle controls are offline only. Independent specification then quality acceptance,
parent freeze/evaluation and serialized VM/runtime review remain required.
No each-boundary/network/FD03/fullP08/M1-M4 or existing blocker coverage is added.
