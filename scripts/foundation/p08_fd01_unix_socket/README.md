# Independent FD-01 Unix-socket fixture

Preparation selects only the core Unix-socket subcase against sequential private
Gao and reference brokers in a disposable Linux VM. Runtime is NOT RUN. This
uses one real socket descriptor and one negotiated recipient, below the unchanged
quota daemon caps. It preserves the original three-resource actor and tests.

The native fixture is Python Linux socket/SCM_RIGHTS; both client sockets share
its actual PID. The root controller independently observes held descriptors and
actual identities, then exact resource reclamation and owned shutdown. Candidate16
is a frozen development capture, not a release or installed policy qualification.

After complete reviewed offline controls and a fresh immutable-input freeze:

```sh
nix-build scripts/foundation/p08_fd01_unix_socket/test.nix \
  --argstr candidatePath /absolute/path/to/frozen/candidate16 \
  --argstr scopePath /absolute/path/to/fd01-unix-socket-core1/SCOPE.md \
  --no-out-link --keep-failed --max-jobs 2 --cores 4
```

Use the pinned development environment and strip inherited DBUS_* selectors.
Only the disposable guest is authorized to start brokers. Guest poweroff does not
substitute for observed workload cleanup. Missing inputs, failed assertions and
reference disagreements remain failed or blocked. Pipe/file/network rows, full
FD01/P08 and all complete M1-M4 gates remain separate and unqualified at L0.
