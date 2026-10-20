# Exact previously executed complete corpus, rebound to current immutable bytes.
{ candidatePath, artifactPath, runtimeManifestPath }:
let
  historical = ../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec14-complete1/source5;
  fixtures = builtins.path { path = historical + "/fixture1"; name = "osbus-method-boundary-original-fixtures"; };
  corpus = builtins.path { path = historical + "/SOURCE_MANIFEST1.json"; name = "osbus-method-boundary-corpus.json"; };
  pinned = (builtins.fromJSON (builtins.readFile (fixtures + "/inherited/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  candidate = builtins.path { path = builtins.toPath candidatePath; name = "osbus-method-boundary-candidate"; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-method-boundary-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-method-boundary-runtime.json"; };
  adapter = pkgs.runCommand "osbus-method-boundary-current-inputs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 -B ${./normalize.py} ${candidate} ${artifact} ${runtime} ${fixtures} ${corpus} "$out"
  '';
in
assert pkgs.dbus.version == "1.14.10";
assert (pkgs.dbus.patches or []) == [];
assert builtins.hashFile "sha256" (candidate + "/candidate.json") == "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert builtins.hashFile "sha256" corpus == "8fe87a9f8bfbb182f095f243f32cae01f48d0b04b7f61b22d5ec7af5736ba590";
import (adapter + "/fixtures/test.nix") {
  candidatePath = candidate;
  candidateManifestSha256 = "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
  candidateSourceSha256 = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c";
  selection = "complete_core";
}
