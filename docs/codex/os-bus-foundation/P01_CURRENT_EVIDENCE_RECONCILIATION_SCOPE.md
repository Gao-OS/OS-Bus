# P01: withdraw stale current mappings without changing runtime evidence

The unchanged required-evidence consumer rejected the first SEC13-inclusive
map with exit2: current binding drift in `bus_interface.ex`. Root file-data
investigation found the same five candidate16-to-candidate18 source changes
in all twelve previously mapped FD observations. The new SEC13 receipt binds
the current sources. Previous reported 12-pass totals describe an older map
and cannot be claimed as current candidate18 qualification.

Root may create a fresh map under `environment/m1-sec13-complete1/index2/`.
For exactly those twelve stale combinations, remove the qualifying record
reference, add an explicit source-drift blocker, and retain the original
receipt and selected observation as historical evidence with its exact hash,
run ID and structured value. Preserve every existing retained observation.
Keep the new complete SEC13/core/GaoBus mapping. All other 413 combinations,
catalogue requirements, consumer source, receipt bytes, assertion witnesses,
runtime artifacts, production source and candidate18 remain unchanged.

Save exact expected/current hashes and the first failed consumer command.
Run the unchanged consumer separately for core/network in normal and
require-qualified modes, using fresh output paths. Normal integrity success
does not qualify the product; strict qualification must remain failed while
required rows are blocked or failed. No runtime rerun or new passing FD
claim is authorized by this accounting correction. Root owns SPEC, serialized
consumer execution and ledger; a distinct file-data review checks the map
delta and retained evidence. Readiness remains L0 and P00-P12 incomplete.
