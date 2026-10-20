# P04 fixed-header source correction with socket-free regression

This slice advances REQUIREMENTS R-05/R-06 and IMPLEMENTATION_PLAN P04 using
the actual Peer framing callback. It explicitly revises our own workflow in
PRO04_FIXED_HEADER_LENGTH_SCOPE1.md: observed native RED is no longer a
prerequisite to this source correction when an actual socket-free callback RED
reproduces the same defect. The user's goal authorizes implementation and
requires continuing independent useful work. Our earlier workflow restriction
was not an external approval requirement.

Preserve the original scope, frozen native inputs, failed build and unobserved
native RED. None becomes passing evidence. The two native tests, automatic
socket/process closure, real receive-budget behavior, resource recovery and
observer health remain BLOCKED_ENV pending the valid pinned VM closure.

Add exactly two unit tests (little/big endian). Each initializes Peer with
actual XML options, uses supervised Limits and its admission/auth/Hello credit
transitions with explicitly identified unit-fixture credentials, and sends no
traffic. Exercise the real :continue_messages callback with only a fixed
16-byte prefix: valid header-array maximum remains incomplete; maximum+1 must
return normal stop. read_scheduled prevents socket I/O. Verify accounting is
unchanged; release unit credit and cancel caller-local registration timers even
on RED failure. Do not invoke Peer.terminate, native identity/resources, actors,
listeners, application startup, VM, network or external APIs. Fixture identities
and callback state are not proof of authentication or kernel credentials.

After observed/diagnosed unit RED, expose the existing pure Message length
validator internally (@doc false), and use it in Peer's single checked size
gate for both framing and receive budgeting. Preserve configured size limits,
transport error shape, native read cap, endian behavior and valid incomplete
frames. Do not add a test-only API, new parser, auth/read redesign, or generic
invalid-term handling for internal unsigned32 lengths.

Root owns scope, checks, execution, production correction and ledger. A source
worker owns only apps/gao_bus/test/peer_frame_length_unit_test.exs; an independent
worker reviews source. Workers do not run commands or revert other edits. Root
uses the pinned local Elixir/OTP runtime and source compilation with unchanged
dependencies, without loading stale compiled versions of edited modules. Run
new tests once for RED, then new tests plus the directly affected existing
apps/ex_d_bus/test/wire/input_containment_test.exs for GREEN. Preserve raw
failures. Do not automatically retry an unchanged failure or increase bounds.

All prior completed/paused/excluded native targets, SEC03/06/08 restrictions,
SEC09-12 pause and FD04 exclusion remain. No optional audit, penetration/exploit
work, broad fuzzing, host live-bus/system/account change, Git publication or
memory write. New evidence stays separate from frozen native attempts. A
passing source regression does not complete PRO04/05, M1 or M2-M4; readiness
remains L0/product_qualified=false until required gates actually pass.
