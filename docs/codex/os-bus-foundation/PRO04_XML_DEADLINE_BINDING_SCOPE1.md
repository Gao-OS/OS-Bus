# PRO-04 XML startup frame deadline binding

This separate slice implements TEST_PLAN PRO-04 eventual deadline closure and
REQUIREMENTS R-05/R-06/R-09 at the configured startup boundary. It does not
change the blocked fixed-header length RED scope or repeat its build/runtime.

Decision: Config.Runtime.compile supplies frame_timeout_ms: 5000 in the existing
peer options shared by the plan and listener. This reuses the existing embedded
peer default as a finite Foundation safety budget. XML limits retain their
values. No new XML element, runtime setting, timer mechanism, native read cap,
Peer default, or explicit peer-option behavior is introduced or changed.

Compatibility effect: configured XML peers previously had no general frame
deadline. They now use an absolute five-second bound from first incomplete
nonempty input; further fragments do not renew it. A valid slow/large message
can therefore close earlier, including before XML pending_fd_timeout. This is
not evidence of reference-daemon timeout equivalence. Raw XML Peer.init options
still permit nil and are outside this compiled-plan correction.

Regression first: extend only config/runtime_test.exs to compile ordinary
system/session XML plans, initialize Peer from each listener's actual options
with an unused socket sentinel, assert the finite deadline and unchanged XML
limits, and cancel caller-local registration timers. Root runs that scoped
ExUnit file with the pinned local runtime and no application startup. Observe
and preserve the missing-binding RED before the one-line production correction;
then run GREEN and exact formatting/compiler diagnostics. No sockets, native
identity/resource operations, VM, actors, downloads or external APIs are needed.
This is a socket-free configuration/callback unit regression, not a wholly pure
computation: Peer.init allocates a caller-local registration timer.

Root owns this scope, execution, source correction and ledger. A source worker
owns only the new regression; a separate worker reviews it. Workers do not run
checks/builds/tests and do not revert other edits. Preserve all previous failed
evidence and frozen inputs. No automatic retry, deadline increase, paused or
completed target, FD suite, optional audit, penetration/exploit work, fuzzing,
host live-bus/system/account change, Git publication or memory write is included.

Affected startup/socket integration and timer initiation, actual closure,
cleanup, healthy observer and reference equivalence need a future fresh
candidate and disposable VM. They remain BLOCKED_ENV here. The old candidate
remains frozen and does not represent the changed Runtime source. Full PRO-04,
M1 and M2-M4 remain incomplete; readiness stays L0/product_qualified=false.
