# Canonical system-bus implementation entrypoint

`nix/tests/system_replacement.nix` imports one common VM module for the reference
and candidate. Both install the complete NixOS D-Bus/polkit policies, the same
accounts and the same GLib service. The candidate overrides the canonical
`dbus.service` executable and adopts `dbus.socket`; there is no private substitute
endpoint. The default profile retains its existing reference package and helper.
The candidate's explicit systemd activation mode requires every selected service
to use systemd (with the PID1 bootstrap exception).

These files are **implemented source awaiting evaluation and acceptance**. No VM,
build, security test or host-bus operation was executed for this addition.

After acceptance is separately resumed, use a fresh production release and the
existing source-fresh `scripts/foundation/p11_lifecycle/capture.py` capture. The
capture must include the current Runtime, Policy, Router and release configuration;
old frozen releases do not contain the activation integration. The entrypoint
requires `releasePath` and the exact SHA256 of its `release.json`, and verifies the
same nixpkgs pin as `devenv.lock`. It also compares captured source hashes with
the current core, native, build, configuration and release sources. Before any
client connects, the guest compares every frozen release entry's path, type,
size/hash or symlink target with the manifest's exact inventory. The explicitly
bound `nix-nar-readonly-v1` import mapping expects directories `0555`, symlinks
`0777`, and regular files `0444`/`0555` from the captured owner-executable flag;
it rejects privileged captured modes. This accounts for Nix store import while
retaining the original manifest and executable/content bindings. Its deferred
evaluation/build invocation is:

```sh
nix-build nix/tests/system_replacement.nix --no-out-link \
  --argstr releasePath /absolute/path/to/new-capture \
  --argstr manifestSha256 ACTUAL_RELEASE_JSON_SHA256
```

This command is documentation for the deferred acceptance phase. It has not been
run or authorized as a retry of any closed execution route. Required new inputs,
artifact availability, NixOS options and bootloader behavior remain unverified.

`workload.py` requires an immutable guest input record, an explicit disposable-VM
marker and QEMU/KVM DMI identity before importing the independent dbus-python
client. Both `workload.py` and `vm05.py` are hash-bound in that record; every actor,
including the PAM unit, checks the guard before connecting or changing state.
Every connection uses `unix:path=/run/dbus/system_bus_socket`. It records
the unit MainPID, executable, actual listener inode and bus ID, and exercises:

- PID1's real GetUnit/property API and logind's ListSessions;
- a real `User=foundationA`, `PAMName=login` systemd session actor: kernel-backed
  bus UID/PID must match its MainPID, logind GetSessionByPID/Id/User/Leader and
  the corresponding User object's UID/Name must identify that same actor;
- the same action-specific polkit YES/NO decisions for two OS users;
- automatic activation under the fixture's expected UID;
- GLib descriptor consumption/return and actual file readback;
- acquisition and release of a real logind inhibitor FIFO.

The normal FD and inhibitor rows warm those real services, record external bus
resource baselines, then require bounded post-quiescence recovery after their
own operations. Each row performs four operations against one retained baseline,
exceeding the two-FD observation allowance so a repeatable single-FD leak cannot
pass a row. Session-unit startup and PAM/logind integration are source only;
an absent real session fails the row rather than falling back to an empty list.

The same eleven-row suite runs on reference, candidate, candidate after core
restart, and reference after rollback. Four required VM-05 rows supplement the
seven normal rows; their exact selected/executed/passed/failed/unrun counts and
partial evidence survive failures. No zero-execution or missing actor is a pass.

| VM-05 source row | Finite operation and required recovery |
| --- | --- |
| `vm05-policy-reload` | One live UID-B actor continuously calls GetId. Echo changes allow → AccessDenied after valid reload, remains denied after an invalid XML reload returns Failed, and returns to allow after restoration. The actor's unique name, kernel UID/PID and bus ID remain identical. The original complete XML/service inventory must match afterward. This proves observable policy-generation effect; it does not invent an internal generation counter. |
| `vm05-faulty-clients` | One ordinary client owns an isolated name and is killed as an owned process group. Both unique and well-known names must disappear. Another ordinary client registers a fixture signal match and does not dispatch while 32 signals of 4096 payload bytes are sent. Closing it must release its unique name; the independent healthy connection survives. |
| `vm05-service-failure` | Stop the real installed GLib service, add one owned runtime ExecStart=false drop-in, then attempt automatic activation. Record the exact D-Bus error, require failed unit state, actual exit status1 and no owner. Remove the drop-in, reload systemd, reset failure, and automatically reactivate with its original UID and a new PID. Cleanup runs on failure too. |
| `vm05-bounded-overload` | UID-B independently opens exactly16 authenticated connections; attempt17 must be rejected with the recorded admission/disconnect error. An existing UID-A connection keeps making bounded-latency calls throughout. After load clients close, a fresh UID-B actor must connect and make progress. |

The complete shared profile adds the same explicit limits on both backends:
16 connections per UID, 262144 incoming bytes and 262144 outgoing bytes per
connection. These are finite functional qualification settings, with all installed
policies, services and accounts retained. Invalid-input/exploit/security campaigns
are separate blocked routes and are not introduced by these actors.

Every VM-05 row records a fixed `fixed-vm05-v1` workload seed, actor argv, elapsed
time, numeric bounds and before/during-where-applicable/recovery samples. The
external sampler records the canonical unit's cgroup OS processes, descriptors,
RSS and `ss` Unix socket queues. Connected-socket queues use bytes; listener
pending/backlog values use connections. Within10 seconds of quiescence it requires
FD growth ≤2, OS process growth0, RSS growth ≤67108864 bytes, connected queue
growth0 bytes and listener pending growth0. Healthy GetId latency must stay below
2 seconds. These are declared, uncalibrated acceptance thresholds, not observed
results. They do **not** prove zero FD growth or internal BEAM mailbox, port,
pending-call or quota-accounting recovery; those remain unobserved here and retain
their separate gates. Queue capacity is declared in shared XML, while actual
external queue occupancy is sampled without fabricating internal counters.

Actors have a60-second lifetime, finite call/control/subprocess deadlines and
owned-process-group cleanup with bounded TERM/KILL/reap. The root orchestrator
restores its optional reload include and runtime failure drop-in in `finally`.
No production daemon test hook, bypass or alternate socket is added.

The module supplies a reference boot specialisation on the candidate's disposable
disk. The serial-console test driver selects its boot generation, crashes the VM
and boots it again. It reruns the same workload, checks the reference executable
owns the canonical listener, and compares the complete XML/service inventory. The
restore command does not call the candidate bus. Candidate evidence is copied
before reboot; final guest evidence and journals are collected on failure too.
Only the release's runtime directory belongs to the candidate service;
`dbus.socket` retains the canonical socket directory across service restarts.

All eleven rows, real PAM/session integration, numeric resource thresholds, Nix
evaluation/build, core restart and rollback are **UNRUN** for this source slice.
Source declarations cannot pass VM-05 or M4. Separate malformed-input/security,
internal-resource, sustained-load and prior mandatory gates retain their original
results and blockers. NetworkManager is outside this core profile. Full readiness
remains **L0**; no aggregate VM readiness report is fabricated here.
