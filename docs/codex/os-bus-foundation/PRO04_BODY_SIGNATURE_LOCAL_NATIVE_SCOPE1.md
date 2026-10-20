# P04 missing body signatures on a private Linux socket

Complete the distinct native missing-body-signature subset required by
TEST_PLAN PRO-04 and R-05/R-06. Existing input_containment_test.exs covers absent
and explicitly empty header8 with a nonempty body as pure terminal errors.
Current production already rejects both; this slice verifies actual Peer
containment and does not change production or manufacture a pre-fix artifact.
Native pre-fix RED is unobserved. Do not rerun accepted PRO03/trailing-body,
fixed-header or completed AUTH/BEGIN/Hello/GetId split targets.

Add only peer_body_signature_test.exs and its dedicated Python actor. Use two
fixed cases: the same independently built nonempty RequestName body, with
signature header8 absent and then explicitly empty. Use unchanged independent
Hello/transport helpers for setup and ordinary valid empty-body GetId health.
One registered source sends one complete frame per case; one unrelated observer
keeps its unique name, owned sentinel and bus ID. Require automatic normal Peer
DOWN before permitting the actor to check exact EOF on its still-open source
socket. No target name may remain owned/queued and authority/accounting state
must restore exactly; observer/core identities and health must survive. Preserve
raw target bytes, outcomes and health receipts. Require actor exit0, no peers,
zero accounting and listener/socket cleanup. No extra malformed corpus or burst.

Run in a separate Linux daemon process, actual nonroot real/effective UID/GID
and kernel actor PID, an owned short mode0700 directory and mode0600 socket.
Use start_supervised! for core fixture processes, actual policy admission and
current source-bound app-directory/native artifacts. Explicit private address
only. No production identity override, default bus, live bus, service manager,
host account/system modification or privileged operation.

Keep existing socket/reply/actor-exit3s, state/DOWN1500ms, actor alarm30s,
ExUnit60s and unchanged host_lifecycle.py outer900s/cleanup5s bounds. Success
requires child0 and graceful_success=true. Preserve failures; diagnose before
a changed retry, with no automatic unchanged rerun or deadline increase.

Source worker owns only the new test/actor. Reviewers read source only; root
owns checks, driver/artifact binding, execution and ledger. All preserve other
edits. No optional security audit, penetration/exploit work, broad fuzzing,
external API probe, network, Nix build/fetch, VM execution, publication or memory
write. Required VM/full PRO04/05/profile gates remain incomplete; frozen index
and all paused/excluded/restricted targets stay unchanged. This is local partial
functional evidence only, M1 unpassed, readiness L0/product_qualified=false.
