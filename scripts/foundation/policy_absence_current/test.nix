# Exact previously executed complete corpus, rebound to current immutable bytes.
{ candidatePath, artifactPath, runtimeManifestPath }:
let
  historical = ../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec13-complete1/source3;
  fixtures = builtins.path { path = historical + "/fixture2"; name = "osbus-policy-absence-original-fixtures"; };
  corpus = builtins.path { path = historical + "/SOURCE_MANIFEST2.json"; name = "osbus-policy-absence-corpus.json"; };
  pinned = (builtins.fromJSON (builtins.readFile (fixtures + "/inherited/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  candidate = builtins.path { path = builtins.toPath candidatePath; name = "osbus-policy-absence-candidate"; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-policy-absence-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-policy-absence-runtime.json"; };
  adapter = pkgs.runCommand "osbus-policy-absence-current-inputs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 -B ${./normalize.py} ${candidate} ${artifact} ${runtime} ${fixtures} ${corpus} "$out"
  '';
in
assert pkgs.dbus.version == "1.14.10";
assert (pkgs.dbus.patches or []) == [];
assert builtins.hashFile "sha256" (candidate + "/candidate.json") == "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert builtins.hashFile "sha256" corpus == "7cca46b15337e01485482092bc6ed8ae70880baa1f75955a9cce9004119dcdbe";
import (adapter + "/fixtures/test.nix") {
  candidatePath = candidate;
  candidateManifestSha256 = "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
  candidateSourceSha256 = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c";
  selection = "complete_core";
}
