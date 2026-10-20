# ADR-003: Compatibility policy is authoritative

## Status

Amended by the Security & Compatibility Foundation. Ordered policy evaluation is
implemented; XML loading and system-profile qualification remain pending P09.
This supersedes the earlier capability-first decision.

## Context and decision

Unmodified Linux services depend on the effective dbus-daemon policy. Replacing
that authority with implicit root/service-UID capabilities would broaden access
and require service policy changes. Compatibility configuration therefore owns
admission, ownership, send, receive, control, activation, and monitor decisions.
Credentials originate from the accepted Unix socket, never from claimed names.

`GaoBus.Policy` holds a validated immutable generation. Rules are ordered, last
matching rule wins, and the default is deny. Routing resolves a destination and
its owned aliases together; related send/receive/ownership checks use the same
policy generation. Missing initial policy prevents startup, missing live policy
denies, and invalid reload retains the previous complete snapshot. P09 must
compile the exact supported XML ordering/semantics into this boundary and verify
it against the pinned reference configuration; the current native rule format
alone is not XML compatibility.

The capability module remains available as an explicitly enabled additional
restriction (`capability_restrictions`). It cannot override a compatibility
policy denial. UID 0 and low service UIDs receive no automatic native grants.
Development and test environments explicitly choose a permissive session fixture;
production has no implicit policy. Restrictive system fixtures must supply their
own policy and are recorded separately from session conformance.

## Effects and remaining work

Denied ownership cannot mutate the registry. Send and recipient receive checks
apply to calls, returns/errors, unicast signals, and matched broadcasts. Bus
controls and eavesdropping have explicit checks; monitoring and activation remain
unsupported until their full implementations, even if policy grants admission.
Router no longer publishes full payloads to the optional in-process UI.

A fixed, payload-free AccessDenied response to the originating caller may be sent
when policy is unavailable. It grants neither routing nor authority and respects
NO_REPLY_EXPECTED. Other bus replies/signals pass recipient authorization. Requested
peer-reply correlation and full pending-request lifecycle remain P07 work.

Evidence and exact scope are in `docs/codex/os-bus-foundation/STATUS.md`; focused
policy/socket tests do not establish Linux system-bus replacement readiness.
