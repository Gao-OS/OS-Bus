# P04/PRO05 native dynamic-variant boundary

Verify the distinct native dynamic-container subset of TEST_PLAN PRO-05 and
R-05/R-06/R-09. The existing independent_corpus_test.exs already checks the
pure decoder's legal64/terminal65 boundary. Current production enforces it;
do not change production or rerun that completed pure target. Native pre-fix
RED is unobserved. This finite local subset cannot qualify the full PRO05 row.

Add only peer_variant_depth_test.exs and fixtures/peer_variant_depth_actor.py.
Use one registered source and an unrelated registered observer on a private
socket. Use unchanged independent Hello/transport helpers for setup. Send
RequestName with signature v and exactly64 dynamic variants (63 v signatures
then a y signature containing42). Expect the controlled InvalidArgs reply and
ordinary same-source GetNameOwner/GetId health with the unique name unchanged.
Then send exactly65 variants on that same source; require automatic normal
Peer DOWN before the actor checks exact EOF with its source socket still open.
No name/queue/match/policy/accounting mutation may remain. Observer unique name,
owned sentinel, bus ID and core process identities must survive, with health
after each boundary. Preserve exact bytes, ordered replies and receipts.
Require actor exit0, empty peer/authority/accounting cleanup and socket removal.

Record bounded endpoint observations before64, after its reply/health at
quiescence, immediately before65, after source departure/restoration, after
observer health, and at final empty cleanup. For live source/observer/core
processes record reductions, memory, total_heap_size, stack_size and queue_len;
departed sources are absent, not assigned zero. Record VM reductions, memory
(total, processes_used, binary, ets, atom_used), atom/process/port counts. Use
the existing local resource envelope of total sampled BEAM memory<=256MiB
and atom growth<=16 from the registered-source baseline. Record raw reductions
and memory deltas without invented per-process work or GC-equality limits.
These are endpoint observations, not peaks, a leak test, a soak, or proof of
resource bounds for other PRO05 inputs. Initialize measurement helpers before
the baseline without executing a target as warmup. Do not add bursts or a corpus.

Run a separate pinned headless Linux process using current source-bound app
directories/native artifact, actual nonroot real/effective UID/GID and kernel
actor PID. start_supervised! owns core fixtures; real policy admission applies.
Use a short owned mode0700 directory and mode0600 socket, explicit private
address only. No identity override, default/live bus or privileged operation.

Keep existing state/DOWN1500ms, actor socket/reply/exit3s, ExUnit60s, actor
alarm30s and unchanged host_lifecycle.py outer900s/cleanup5s bounds. Measure
each observer health exchange against the existing1000ms healthy-traffic
envelope. Success requires child0 and graceful_success=true. Preserve failures
and diagnose before a changed retry; no unchanged rerun or deadline increase.

Source worker owns only the new test/actor; source reviewers read only. Root
owns the driver, checks, execution, artifact binding and ledger. All preserve
others' edits. No optional audit, penetration/exploit work, broad fuzzing,
external API probe, network, Nix build/fetch, VM execution, publication or memory
write. Completed targets and all paused/excluded/restricted cases remain so.
Frozen index and product gates remain unchanged; required VM/profile gates
remain blocked. M1 unpassed, readinessL0/product_qualified=false.
