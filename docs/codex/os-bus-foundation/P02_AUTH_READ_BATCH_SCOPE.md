# P02: bounded auth reads while preserving native ancillary ownership

The original complete SEC07 native run and the later nonqualifying diagnostic
both preserve the same700ms complete-line failure. The diagnostic shows partial
progress, not a measured dominant operation. The narrow hypothesis is that
reducing the repeated per-byte Peer/native/accounting/Auth/timer/readiness
sequence lets the existing bounded auth state machine process the offered line
within its original criterion. Do not attribute the cost to a specific stage.

Root executed the raw API feasibility tests with pinned Elixir1.17.3/OTP27.3.4.6
and candidate18:2tests/0failures, seed1703. Repeated timeout-zero data-only peeks
across BEGIN and a later rights-bearing write leave bytes/FDs unchanged; native
recvmsg consumes through LF without rights, then receives one usable pipe once.
Pure Auth baseline:33tests/0failures. Exact commands/logs/95input pins are under
environment/m1-res01-measurement1/sec07-auth-read-work1. These passes establish
API feasibility, not performance or complete SEC07 qualification.

Own only apps/gao_bus/lib/gao_bus/peer.ex; new focused Peer auth-boundary test
and independent fixture files; and fresh sec07-auth-read-work1 evidence. Existing
raw preview tests are preserved. Other workers are active. Candidate18, old
source/evidence, corpus/policy/deadlines and their recorded failures stay frozen.
No Auth parser rewrite, timer change, native-adapter change, global limit change,
new configuration knob, policy change or unrelated cleanup.

Keep initial NUL consumption at1byte. For subsequent auth phases preview at most
min(65536, remaining line bytes+1, remaining cumulative bytes+1). A preview never
consumes input. Handle both complete and partial-timeout prefixes from timeout0;
choose actual native read size only through the first LF, or the available
prefix when no LF exists. Empty availability uses the existing readiness path;
other/closed errors retain terminal handling. Feed only actual native bytes.
Preserve credit reservation before native consumption, resource-bearing-auth
rejection/closure, short-read behavior and the original binary frame budgets.
No asynchronous widened peek or new socket/resource owner.

Accounting decision: the data-only preview is temporary bounded scratch, outside
the frame-byte reservation, like the existing one-byte readiness preview. Its
per-callback ceiling is65536bytes and is additionally clamped by the configured
auth line/cumulative limits. With default limits the ceiling is4097bytes per
authenticating peer. Admission/authentication connection limits bound the number
of such peers. Do not claim that this scratch is charged to global frame credits
or that focused tests complete RES qualification. After preview returns only a
size is retained; existing credits must still precede consuming recvmsg. Record
this tradeoff and measure full resource qualification separately.

Before production edits, prepare real Peer regressions for every split around
NUL and BEGIN CR/LF, pipelined auth/Hello/binary tails containing LF, auth N/N+1
and cumulative boundaries, and real rights at auth/BEGIN boundaries versus
rights on the first binary frame. Healthy incumbent traffic and exact descriptor
reclamation are required. Reuse existing actor/wire helpers where practical;
no mocks or production test hooks. Keep the original failed VM evidence as the
performance RED; do not invent a new relaxed timing test or native-call quota.

Root serializes actual tests and authorizes the small production edit after
reviewing new tests. Run focused Auth/Peer/auth-preview/truncation and existing
all-frame-split regressions, then build a fresh immutable candidate and execute
the unchanged full17case SEC07 corpus in a fresh disposable VM. Old source2
and diagnostic outputs may not be retried. Root SPEC/distinct QUALITY apply
to the new complete VM source, not extra approval layers for ordinary edits.
Stop at first unexpected target failure and diagnose before repair. A focused
pass does not qualify SEC07/M1. Any changed production source makes candidate18
evidence historical for that change until affected current evidence is rerun.
Keep STATUS explicit. No host live bus/account, Git/remote/publication/release
or memory mutation. ReadinessL0/product_qualified=false.
