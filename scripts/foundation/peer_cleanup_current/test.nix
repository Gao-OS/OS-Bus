# Existing SEC17 pending subset; only candidate metadata and load paths are rebound.
{ artifactPath, runtimeManifestPath }:
let
  root = ../../..;
  historical = ../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec17-pending-cleanup1/source1;
  fixtures = builtins.path { path = historical + "/fixture1"; name = "osbus-peer-cleanup-original-fixtures"; };
  corpus = builtins.path { path = historical + "/SOURCE_MANIFEST1.json"; name = "osbus-peer-cleanup-corpus.json"; };
  pinned = (builtins.fromJSON (builtins.readFile (fixtures + "/inherited/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-peer-cleanup-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-peer-cleanup-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile (artifact + "/artifact.json"));
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "osbus-peer-cleanup-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  adapter = pkgs.runCommand "osbus-peer-cleanup-current-inputs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 -B ${./normalize.py} ${artifact} ${runtime} ${fixtures} ${corpus} "$out"
  '';
  frozen = adapter + "/candidate";
  currentFixtures = adapter + "/fixtures";
  original = currentFixtures + "/inherited/security";
  selection = "pending_cleanup";
  candidateManifestSha256 = "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
  candidateSourceSha256 = "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c";
in
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert builtins.hashFile "sha256" corpus == "a96cbae0d5e7a58894770502874e80134dff2910c0483b5adc8d42087779737a";
assert builtins.all (name: builtins.hashFile "sha256" (root + "/${name}") == manifest.sources.${name}.sha256)
  (builtins.attrNames manifest.sources);
pkgs.testers.nixosTest {
  name = "os-bus-foundation-peer-cleanup-current";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.groups.foundationA.gid = 1100;
    users.groups.foundationB.gid = 1101;
    users.users.foundationA = { isNormalUser = true; uid = 1100; group = "foundationA"; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils ];
    environment.etc."osbus-candidate-runtime".source = anchors;
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    shutdown = {"VMoff": False, "socket_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-security/uid-abrupt-peer")
        machine.succeed("cp ${adapter}/bindings.json /run/osbus-security/uid-abrupt-peer/current-bindings.json")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH UID_ABRUPT_CANDIDATE_MANIFEST_SHA256=${candidateManifestSha256} UID_ABRUPT_CANDIDATE_SOURCE_SHA256=${candidateSourceSha256} timeout --signal=TERM --kill-after=3s 120s python3 ${currentFixtures}/run.py ${frozen} ${original} /run/osbus-security/uid-abrupt-peer ${selection}"))
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-security/uid-abrupt-peer/bus")[0] == 0
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-security/uid-abrupt-peer\"); target=Path(\"/run/uid-abrupt-peer-export\"); target.mkdir(); [shutil.copyfile(path, target/path.name) for path in source.iterdir() if path.is_file()]'")
            machine.copy_from_vm("/run/uid-abrupt-peer-export", "uid-abrupt-peer-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "uid-abrupt-peer-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
