# Import the byte-preserved RES02 recipe after metadata-only materialization.
let
  prepared = ../../../test/reports/foundation/resume-20261019/res02-current-slow-egress1/materialized;
in
import (prepared + "/fixture1/test.nix") {
  candidatePath = toString (prepared + "/candidate");
  candidateManifestSha256 = "e4b26b031c0a70a330dbafe9285c605dd3c15d291894ddc33d8b15e71125f06c";
  candidateSourceSha256 = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c";
  selection = "slow_egress_count";
}
