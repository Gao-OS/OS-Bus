# Headless release lifecycle

The `os_bus` release contains GaoBus, ExDBus, phoenix_pubsub and their
OTP/Elixir runtime dependencies. Phoenix, GaoConfig, the test application and
cluster startup are excluded. This implemented packaging surface is not yet an
installed-system replacement claim; see STATUS.md for the executed boundary.

Build with the pinned development environment, `MIX_ENV=prod mix release os_bus`.
For isolated evidence use a fresh `MIX_BUILD_PATH` and `--path` so shared test
artifacts and previous packages remain intact. The release uses its dedicated
`rel/os_bus/runtime.exs`, requires no web secret and forces distribution off.
Its generated `start` command is foreground and uses an exec-only launcher.

Every start requires `OS_BUS_CONFIG` to name an absolute, valid system-profile
XML configuration. Runtime checks bind the configured daemon user to the real
process identity: kernel real/effective UID and GID must agree before loading
configuration or starting the authority. A mismatch returns
`invalid_configuration/daemon_identity_mismatch` without READY. The XML user
must match that UID; the service manager performs any identity transition.
Invocation explicitly selects nofork, nopidfile and stderr logging. Cluster
startup is disabled. Unsupported policy/configuration remains a startup error.
Activation is still refused by Config.Runtime until its installed-helper,
canonical-address and containment prerequisites are qualified.

Set `OS_BUS_INHERITED_LISTENER=true` for a manager handoff. The actual foreground
BEAM PID must match LISTEN_PID; exactly one descriptor is handed off as fd3,
LISTEN_FDS must equal `1` and LISTEN_FDNAMES must equal `dbus`. Its local stream
listener address must exactly match the compiled configuration. No PID rewrite,
extra descriptor, ambiguous path or fallback is accepted. A required
NOTIFY_SOCKET can be a pathname or Linux abstract address beginning with `@`.

Pinned OTP27 borrows descriptors in `dup: false` mode and does not set
FD_CLOEXEC in either adoption mode. The release therefore creates a public owned
duplicate and uses the narrow identity-checked handoff in ADR-006 to prove
close-on-exec and release raw fd3. The public owner closes the duplicate on
normal stop or abnormal owner death. Failed permanent startup exits the VM,
including any raw fd3 retained before successful handoff. The manager's socket
path, inode, mode and independent listening descriptor are never removed,
chmodded, rebound or shut down by this daemon.

For documented standalone mode set OS_BUS_INHERITED_LISTENER to `false` or omit
it, and supply a private pathname in the configuration. Only the created inode
is removed on shutdown; an existing endpoint or unsafe parent prevents startup.
Without a manager, NOTIFY_SOCKET is optional. When supplied, notification failure
tears down the complete core and fails startup.

READY=1 is a bounded Unix datagram sent by the main BEAM process after valid
configuration/policy publication and synchronous startup of Limits, authority
and Listener. No activated service, PID1 name acquisition, shell notification
process or self-connection is required to become ready. The packaged probe
verifies the sender's kernel SCM_CREDENTIALS and immediately performs independent
EXTERNAL, Hello and GetId operations through the handed-off listener.

A release authority failure stops the core with no in-place restart. Its
permanent application ends the VM so the manager can clear the service cgroup
and supply a fresh handoff. Use Type=notify, NotifyAccess=main, finite start/stop
timeouts and KillMode=control-group. Use SIGTERM or the service manager for a
graceful stop; generated remote/rpc/stop commands require distribution and are
unsupported in this headless mode. Reconnect after restart: names, connections
and bus-instance IDs belong to the previous epoch and do not survive.

Private process verification is:

```sh
python3 -B scripts/foundation/p11_lifecycle/probe.py \
  /absolute/path/to/fresh/release /absolute/path/to/new/evidence
```

It never uses a default bus. Its17 cases verify the actual packaged exec chain,
owned and inherited modes, pathname/abstract readiness, malformed/missing
handoffs/configuration, descriptor identities/flags, manager endpoint survival,
SIGTERM shutdown and absence of a main-process TCP listener. Complete package
hashes/modes remain unchanged before and after the run. This does not qualify
installed service activation, full SYS/VM gates, a packaged600s soak or rollback.
