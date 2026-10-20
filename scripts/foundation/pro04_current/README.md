# Current native PRO04 regressions

XML-candidate source preparation and saved failure evidence. File-only metadata checks and existing
pure controls are recorded in `test/reports/foundation/resume-20261019/xml-remaining-rebind1/`.
XML build2 succeeded, but saved VM2 failed at the runner's stale pre-XML artifact
literal before loading any tests (`test/reports/foundation/resume-20261019/runtime-pro04/vm2/`).
The exact literal correction and pure source-pin regression are frozen in
`test/reports/foundation/resume-20261019/pro04-xml-pin-repair1/`; rebuild and VM
execution of this corrected runner are NOT RUN. Earlier pre-XML runtime
observations cannot qualify these pins. Existing fixture repairs, assertions,
policies, vectors and bounds remain unchanged. Root owns builds, serialized
VMs, independent runtime review and adoption; L0/product_qualified=false remain.

`test.nix` accepts `artifactPath` and `runtimeManifestPath`. Supply the current
`/nix/store/1x1d03jmlk0crx84v21iy3xwd4b8hgda-osbus-authorization-artifact` artifact, manifest
SHA256 `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`, and
the frozen runtime manifest SHA256
`6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.
The recipe checks all 71 production source hashes against this artifact and
the runner verifies all 80 runnable files, exact inventory, byte lengths,
hashes and read-only modes. The product and test source files are unchanged.

It adapts the existing `nix/tests/foundation_peer.nix` and
`scripts/foundation/peer_regression_runner.exs` entrypoint for exactly four
existing files, without filters, skips or exclusions:

| Existing test | Cases | Requirement contribution |
| --- | ---: | --- |
| `peer_fixed_header_lengths_test.exs` | 2 | Both endians: valid header-array maximum remains incomplete; maximum+1 closes from the fixed prefix |
| `peer_body_signature_test.exs` | 2 | Nonempty body with absent/empty signature closes only its source |
| `peer_xml_message_size_test.exs` | 1 | Compiled XML 4096-byte acceptance and 4097-byte advertised-size rejection |
| `peer_xml_frame_deadline_test.exs` | 1 | Compiled XML absolute deadline survives prefix growth and closes naturally |

The fixture closure contains these four unchanged tests and six unchanged
Python helpers. Existing test assertions retain real actor credentials,
normal Peer DOWN/EOF, exact authority/accounting recovery, healthy observers,
actor exits and supervised teardown. No test-only dependency is needed.
The runner requires all six tests to pass with zero skipped/excluded, all
selected authorities absent and the private directory empty afterward.

The disposable guest runs as UID/GID 1101 using a private mode0700 directory,
mode0600 sockets created by the tests and explicit private bus addresses.
Elixir 1.17.3/OTP 27.3.4.6, seed1703/max_cases1, unchanged test/actor deadlines,
the Peer recipe's 240-second worker bound and 900-second host VM bound remain.
Raw test output, bindings, verified inputs, exit status and runner result are
exported under `pro04-current-evidence`. The sibling
`pro04-current-vmoff.json` records VMoff/private-directory cleanup.
Use a fresh host output path and the existing parent host lifecycle wrapper.

A successful fresh runtime would provide native partial PRO04 functional evidence only. It does
not execute the reference backend, qualify the complete PRO04 catalogue row,
replace historical failures or promote milestone/readiness status. The older
fixed-header build block and XML-deadline fixture failure remain historical.
