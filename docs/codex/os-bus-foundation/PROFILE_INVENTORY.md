# P09 pinned core profile inventory

This is configuration/build evidence for the NixOS core profile, prepared for
P09/P10. It does not qualify XML loading, policy equivalence, activation,
socket-inherited startup, MAC enforcement, or system-bus replacement. Readiness
remains L0; the existing native security fixture is a separate declared fixture.
No installed policy or service was removed to simplify the target.

## Reproducible profile and provenance

Inventory checkout: `codex/os-bus-foundation`, baseline
`7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`, shared dirty worktree
`.trees/os-bus-foundation`. The outputs below come from the current `devenv.lock`,
not the host's running configuration. Evidence lives in ignored
`test/reports/foundation/p09-profile/`.

The evaluated module has exactly these explicit settings:

```nix
system = "x86_64-linux"; # eval-config argument
system.stateVersion = "25.11";
services.dbus.implementation = "dbus";
security.polkit.enable = true;
users.users.foundationA = { isNormalUser = true; uid = 1100; };
users.users.foundationB = { isNormalUser = true; uid = 1101; };
```

All other settings use this pinned NixOS module tree's defaults. The small
activation/FD fixture is not yet packaged into this evaluated profile. Any later
VM module additions must produce a new inventory and hashes before qualification.

| Item | Immutable value |
| --- | --- |
| nixpkgs revision | `207d15f1a6603226e1e223dc79ac29c7846da32e` |
| nixpkgs narHash | `sha256-H3AfG4ObMDTkTJYkd8cz1/RbY9LatN5Mk4UF48VuSXc=` |
| nixpkgs source | `/nix/store/p4l9q189cgldga9f1051fhfllfzmk4c5-source` |
| Generated `/etc/dbus-1` source | `/nix/store/93x9acwacry3mmpcmzr18yyys8dv2pxs-dbus-1` |
| Generated system units | `/nix/store/n72sxlf5yjmajm2fxf4aml29b6kwbrvy-system-units` |
| DBus 1.14.10 (`DBUS`) | `/nix/store/pb9dhpk6qxjybb8p7prvs18ls2vxk51a-dbus-1.14.10` |
| systemd 258.3 (`SYSTEMD`) | `/nix/store/5j9cg6adv3d2l403fcfklz4lmf9fd0l8-systemd-258.3` |
| polkit 127 (`POLKIT`) | `/nix/store/j43m1hd4drq0p5k3hfq05hhm64kn9x5i-polkit-127` |
| Profile system path (`SYSTEM_PATH`) | `/nix/store/61vdmpsc2py3bms2wmysbppqv8v582w5-system-path` |
| Coreutils (`COREUTILS`) | `/nix/store/i2vmgx46q9hd3z6rigaiman3wl3i2gc4-coreutils-9.9` |
| DBus manual output | `/nix/store/n4bsj4zrp2psnhw77mcc5v36nyiwxrbm-dbus-1.14.10-man` |
| Evaluated kernel | `6.12.68`; no boot claim |
| AppArmor / NetworkManager | disabled / disabled |
| Suppressed system units | empty list; no pruning |

From the inventory checkout, the completed evaluation/build commands were:

```sh
nix-instantiate --eval --strict --json test/reports/foundation/p09-profile/profile.nix -A metadata
nix-build test/reports/foundation/p09-profile/profile.nix -A config --no-out-link --max-jobs 2 --cores 4
nix-build test/reports/foundation/p09-profile/profile.nix -A units --no-out-link --max-jobs 2 --cores 4
nix-build --expr '(import /nix/store/p4l9q189cgldga9f1051fhfllfzmk4c5-source { system = "x86_64-linux"; }).dbus.man' --no-out-link --max-jobs 2 --cores 4
```

`config-build.log`, `units-build.log`, and `dbus-man-build.log` retain the build
results. `metadata.json` retains full evaluated users/groups, packages, wrapper
settings, and core unit overrides. The earlier `p09-profile-eval-initial.json`
outside this directory lacked the foundation users and is not this inventory.

## Effective root and discovery

The effective root is generated `system.conf`, SHA256
`52d461d22a50e8629e329fbf90a56b00a4816fe0be2b9c7151d70b6425532c4f`.
It selects `type=system`, `user=messagebus`, `auth=EXTERNAL`,
`listen=unix:path=/run/dbus/system_bus_socket`, `fork`, `pidfile=/run/dbus/pid`,
and `syslog`. The unit overrides fork/pid/listen behavior with its CLI arguments
listed below. AppArmor is explicitly `mode=disabled`.

Pinned `make-system-conf.xsl` removes upstream `include`, `includedir`,
`servicedir`, `standard_system_servicedirs`, and `servicehelper` nodes, then
appends the helper, AppArmor setting, and package paths. Thus the upstream
`system-local.conf`, SELinux include and standard system service directories are
not effective includes for this generated profile.

Each package contributes `share/dbus-1/system-services`, then
`etc/dbus-1/system.d`, then `share/dbus-1/system.d`, in this order:

| Package order | Service directory | `etc` policy directory | `share` policy directory |
| --- | --- | --- | --- |
| 1. `DBUS` | absent | absent | absent |
| 2. `SYSTEM_PATH` | 15 entries | absent | 15 `.conf` entries |
| 3. `POLKIT` | 1 entry (duplicate PolicyKit1) | absent | 1 `.conf` (duplicate PolicyKit1) |

Paths and symlink-resolved paths are recorded in `inventory.json`. XML expands
to **17 file occurrences / 16 distinct contents**: root, 15 system-path policies,
and the repeated PolicyKit1 policy. Service discovery has **16 occurrences / 15
distinct names**. The repeated polkit files have identical bytes; do not silently
discard their provenance or the policy occurrence.

The DBus 1.14.10 manual specifies that `includedir` loads only `.conf` files in
**undefined order**. Sorted evidence listings are not a reference evaluation
order. Across `servicedir` entries the **first listed directory wins**; duplicate
names within one directory have arbitrary selection. PolicyKit1 therefore
resolves from `SYSTEM_PATH` before the explicit `POLKIT` entry.

## Loader-facing syntax and policy semantics

These active elements occur: `busconfig`, `type`, `user`, `fork`, `pidfile`,
`syslog`, `auth`, `listen`, `policy`, `allow`, `deny`, `apparmor`, `servicehelper`,
`servicedir`, `includedir`. The commented limit examples are not active nodes.

| Element | Actual attributes |
| --- | --- |
| `policy` | `context="default"`; `user="root\|polkituser\|systemd-network\|systemd-resolve\|systemd-timesync\|systemd-oom"` (separate values) |
| `allow` | `own`, `user`, `send_destination`, `send_interface`, `send_member`, `send_type`, `send_requested_reply="true"`, `receive_sender`, `receive_interface`, `receive_member`, `receive_type` |
| `deny` | `own`, `send_type`, `send_destination`, `send_interface`, `send_member` |
| `apparmor` | `mode="disabled"` |

`inventory.json` contains every parsed element, attribute, value and text. There
are no effective `group`, `at_console`, mandatory-context, `include`, active
`limit`, or SELinux directives in this profile. Their absence is not a claim
that another profile using them is supported. P09 must identify unsupported
configuration explicitly rather than silently ignoring security semantics.

Reference semantics required by these files:

- Policy classes apply default → group → user → at_console true → false →
  mandatory. Later overlapping decisions override earlier decisions; multiple
  policies with the same user/group/context retain configuration order. This
  profile exercises default and user classes; do not apply all classes as one
  undifferentiated sequence.
- Send and receive are separate decisions, with the last matching rule winning
  in each. Multiple attributes within one rule are AND; separate rules provide
  alternatives. Identity rules govern connection admission; `own` governs names.
- `send_destination` and `receive_sender` match the connection owning a name,
  including its other ownership aliases; matching only the literal addressed
  string is insufficient. Text header matches, wildcard handling and absent
  interface behavior must follow the reference.
- Allow rules default to requested replies only; explicit
  `send_requested_reply="true"` allows expected returns/errors. Allow false
  permits unexpected replies. Deny false (default) matches unexpected replies;
  deny true matches all replies. The modifier is ignored for other message
  types. Receive-type allows also inherit requested-reply/eavesdrop semantics.
- The root configuration permits all users to connect, denies ownership/method calls by default,
  allows signals and requested replies, permits receives, punches bus-interface
  holes, and denies privileged controls. Root user policies permit Activator,
  Monitoring and Stats interfaces. Service policies add ownership/call/receive
  holes, method-specific rules, and privileged denials; preserve every rule.

The extracted pinned `dbus-daemon.1` is the semantic source, particularly lines
253 (includedir), 428 (service precedence), 724–742 (policy classes), 806/813
(send/receive), 827 onward (owner alias matching), 869 onward (requested replies),
and 916 (combined attributes). XML load/reload/reference-decision tests remain
P09 implementation work; this inventory does not mark any field implemented.

## Identities and activation

Policy usernames must resolve in the target VM: root UID 0, polkituser UID 28,
systemd-network UID 152, systemd-resolve UID 153, systemd-timesync UID 154.
`systemd-oom` has an evaluated `uid=null`; its runtime numeric UID is not
invented here. Daemon user/group `messagebus` is UID/GID 4. The two actor users
are UID 1100/1101 in group `users` (GID 100). These are target-evaluated values,
not credentials supplied by a client or host account assumptions.

All installed D-Bus service files have `User=root`. PolicyKit1 has
`Exec=POLKIT/lib/polkit-1/polkitd --no-debug`; every systemd entry has
`Exec=COREUTILS/bin/false`. The latter are deliberately systemd-backed metadata,
not usable traditional launch commands. `org.freedesktop.systemd1` has no
`SystemdService`; its file comments require PID1 to acquire the name itself.
An absent owner must not turn `Exec=false` into successful activation.

The table below retains the complete installed set. Bus-name prefix is
`org.freedesktop.`; `dbus-*` denotes the full alias
`dbus-org.freedesktop.<name>.service`. A missing target means absence from the
generated units output, not a runtime result or a policy-file omission.

| Bus name suffix | SystemdService / resolved unit | Present | Unit Type / User | Ownership policy user / total rules |
| --- | --- | --- | --- | --- |
| `PolicyKit1` | `polkit.service` | yes | notify-reload / polkituser | polkituser / 3 |
| `home1` | `dbus-* / absent` | no | — | root / 60 |
| `hostname1` | `dbus-* / systemd-hostnamed.service` | yes | notify / root (default) | root / 5 |
| `import1` | `dbus-* / systemd-importd.service` | yes | notify / root (default) | root / 28 |
| `locale1` | `dbus-* / systemd-localed.service` | yes | notify / root (default) | root / 5 |
| `login1` | `dbus-* / systemd-logind.service` | yes | notify-reload / root (default) | root / 93 |
| `machine1` | `dbus-* / systemd-machined.service` | yes | omitted / root (default) | root / 73 |
| `network1` | `dbus-* / absent` | no | — | systemd-network / 5 |
| `oom1` | `dbus-* / absent` | no | — | systemd-oom / 11 |
| `portable1` | `dbus-* / systemd-portabled.service` | yes | omitted / root (default) | root / 39 |
| `resolve1` | `dbus-* / absent` | no | — | systemd-resolve / 5 |
| `systemd1` | `none (PID1)` | no | PID1 / root | root / 112 |
| `sysupdate1` | `dbus-* / absent` | no | — | root / 23 |
| `timedate1` | `dbus-* / systemd-timedated.service` | yes | notify / root (default) | root / 5 |
| `timesync1` | `dbus-* / systemd-timesyncd.service` | yes | notify / systemd-timesync | systemd-timesync / 10 |

Every policy filename is `org.freedesktop.<suffix>.conf`; every service filename
is `org.freedesktop.<suffix>.service`. Both occur under the system-path share
directories. PolicyKit1 repeats under the explicit polkit package. These are
exact byte hashes (the repeated files retain the same hashes):

| Suffix | Policy SHA256 | Service SHA256 |
| --- | --- | --- |
| `PolicyKit1` | `a5dd80a4f1baa58a849115bca6ca83ecf8db4aabfb1171967b5fa4701a14d98e` | `e459a5558e32af990a36e7e1adc55786e5269f4f359dbc3912da004694e49f92` |
| `home1` | `9876ecac51836f7b4b56afde08832c5ae96010151372218e6da43960fa8aae68` | `d6f780a022af2f75ebee2f91d50261ff9d9923826247a8d2b762e2fe25021f55` |
| `hostname1` | `98e7eb579288791e01081e75b577baf904ff7eb921afa6738158b86e97d034a7` | `c6e0dab73dbd6ebb5b66d7a05d61011df1da6897388d8b5071dcf424718a3e7c` |
| `import1` | `5206628f4ac36e69a8a34680edc3ab93370ecc3458d181cdc8f5baabee2322f3` | `486f4478a71de6eabff98ad38b07e70c504ec8ae92f2baa0c0272efbba4f3cdd` |
| `locale1` | `9702f64ef33e68a78d9d1cf852b37c1e64cbde16d2eda96ecbf950c03865e6b3` | `60a348167b52e2f18dfa6871b037b11ff00c803912781b669b00d0f03d7d7b5a` |
| `login1` | `8c12da23940f6ea80495e47a4d0bf9eece02374ed3a9d1e663932afd0271d46d` | `05822f9cce83a87ddaa6adcf9f9d8dcd6c72f028e1e1b93fe34aca288fe87d14` |
| `machine1` | `ca4279bf67016e6e9cb13e89d3f1ebcc4f3551cb72d618804728f7695df58878` | `3a47ea887d5c36e92792ccad36cb7a15131053faf1e67384317d8d2ea48390bb` |
| `network1` | `3517cb15b466c8e6826c4f4261477ab61ea11c23cbd10c69bfb2f54ef97357cc` | `38fb464f1f9b19671c56bd10c4ed596e9f47443b15b937e8ea3547f94fc898a0` |
| `oom1` | `6b899035d7f957d63c211cdb72e7d32cd64fcd3cb39c1735413d65d24cad1de2` | `659e4470e95cdea711ce596ccd5942b82a0406a5d0794f00ea37111b0cd48867` |
| `portable1` | `d903868a2d7226a4ae545e8dad5aedee3a576a308ee330586910a8963030735a` | `aa1faf88961961334e56e897e1988a82e1d0eb1a7d4889f1c6275308bd61d98b` |
| `resolve1` | `1586cbabf4977b1e43d858373f2128b641e920fd6b995b0b231986cab53b3a7f` | `3e12e85bda427ff67c529fb285b13ce9406680e8fd820760f8366f5aca9937ac` |
| `systemd1` | `42529cc9b571a23e0e28ec96c7855bb8c2ccb277e626c3dd305bc5b5bd485af5` | `79244df32d45ef79bfd3bd16da2d2c06fd7e7eb7e568074c86524ed588cb9a74` |
| `sysupdate1` | `a6b26e2538bb68986127ad8a4b8bfd2597ca3f2ef4ecc018b6c707059d6213a0` | `a47bfe5be929b9d577b9deb347f8bf67af95ef015863fbdabe3611829e7f8a2b` |
| `timedate1` | `f34b0a017d95991ea8f1409e9abc53346664612982c5d2349b481d471c7de9d7` | `19602e6eeaef9a6f05079d858607286834e5cb563de1aeba3ec74c201e2340d4` |
| `timesync1` | `a584cde247521c0ba6cec45082ba2552cecfc82d777c0e8d4d2fd81475b75601` | `4f00c1124dbc8f6a4a96b27c58cfbc9c48f683b7c4e30a3fa6bc4e14866af116` |

The generated units have no mask for any present activation target. File/alias
presence alone does not establish successful startup or feature coverage. In
particular, extra home/network/oom/resolve/sysupdate entries remain installed
even though their aliases are absent in this evaluated module set.

Core startup requirements from actual generated units and drop-ins:

- `dbus.socket`: `ListenStream=/run/dbus/system_bus_socket`.
- `dbus.service`: `Requires=dbus.socket`, `Type=notify`; starts
  `DBUS/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile
  --systemd-activation --syslog-only`. Configuration drops to `messagebus` after
  initialization. The Nix drop-in sets environments/reload triggers; no User
  field overrides root startup. `ExecReload` invokes real
  `org.freedesktop.DBus.ReloadConfig` with `dbus-send --system`.
- `systemd-logind.service`: `BusName=org.freedesktop.login1`,
  `Type=notify-reload`, no User override (root),
  `ExecStart=SYSTEMD/lib/systemd/systemd-logind`; wants/starts after `dbus.socket`.
  Nix sets `X-RestartIfChanged=false`, `X-StopIfChanged=false`.
- `polkit.service`: `BusName=org.freedesktop.PolicyKit1`, `Type=notify-reload`,
  `User=polkituser`. Its Nix drop-in resets/replaces upstream ExecStart with
  `POLKIT/lib/polkit-1/polkitd --no-debug`. The systemd path must honor this
  identity rather than copying the D-Bus file's traditional-launch `User=root`.
- Traditional helper path is `/run/wrappers/bin/dbus-daemon-launch-helper`.
  Evaluated wrapper: root-owned, group messagebus, setuid true, setgid false,
  permissions `u+rx,g+rx,o-rx`, source `DBUS/libexec/dbus-daemon-launch-helper`.
  Evaluation does not prove the wrapper exists in a booted VM.

`units-inventory.json` records 24 unit/alias entries, original/resolved paths,
absence/masks, unit/drop-in snapshots and selected service/socket fields. Full
raw bytes are authoritative; the selected fields are not a general systemd
unit interpreter. Nine pinned Nix module/package/XSL source files are also
hashed and snapshotted there.

## Small fixture and qualification gaps

The existing GLib fixture owns `com.test.ExternalFixture` and now exposes
`ReadAndReturnFD(h)->(hs)` for actual received-descriptor consumption and return.
It currently uses the session-bus API with an explicit address mapped through
`DBUS_SESSION_BUS_ADDRESS`. This can connect to an explicitly chosen VM system
bus, but neither its default session endpoint nor current actor UID qualifies
the target profile.

P10 must provide a packaged executable, dedicated fixture UID, exact service
entry/launch identity, narrow ownership/call policy, and explicit VM system-bus
address. None of that metadata exists in this evaluated inventory; no fixture
UID or `.service` contents are proposed as established facts here. Independent
GLib FD product tests do not by themselves prove automatic activation.

For the full target, required evidence still includes same-file reference
allow/deny/ownership decisions, transactional reload/failed reload, OS-verified
credential APIs, PID1 activation bootstrap without circular startup, core
service restart/reconnection, polkit allow/deny decisions, and an actual FD use
case such as logind Inhibit plus the packaged fixture. The native security
fixture's policies are not substitutions for these XML files. Polkit's own
authorization rules/actions are separate from bus admission policy; this
document inventories the bus XML/service/unit boundary and does not qualify
polkit authorization behavior. NetworkManager and enabled MAC profiles require
separate inventory/runtime evidence.

## Evidence checksums

Snapshots use `files/<sha256>` under the evidence directory. Rehashing must match
both the immutable source and snapshot; paths/symlinks are retained separately.
The two JSON inventory hashes cover file-level hashes, full parsed XML/service
metadata, discovery paths and unit/source records.

| Evidence file | SHA256 |
| --- | --- |
| `profile.nix` | `22da8fdd76dd745d406ca18ab2fc0f14c5e5e6b1b51c2874a91c7729a12ed90c` |
| `metadata.json` | `44a6bdc4d72355b16e9a0deee1d37fe1d292be4807b8bf9400c752a2c35e36c5` |
| `inventory.json` | `bef4786ba7d3d79cbe505f2f29a3947dd76e4a7899a04f1a244661505f476d73` |
| `units-inventory.json` | `17a8fc061e61718f8baf38b41b59fd78c49e4fe36cfc9d1b02d6eec739d5deaa` |
| `dbus-daemon.1` | `68673555f887939b33d8909f21d952f300a9b30cdd00ec30295470fa37616c5f` |

Inventory validation is limited to JSON syntax, all source/snapshot hashes,
counts, name-set equality, directory listings and activation-target availability.
No production Mix tests, VM boot, host bus access or replacement was performed
for this preparation task.
