# Existing SEC09–12 functional corpus, rebound only to the current immutable product.
{ artifactPath, runtimeManifestPath }:
let
  historical = ../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec09-sec12-complete1/source1;
  fixtures = builtins.path { path = historical + "/fixture1"; name = "osbus-authorization-original-fixtures"; };
  corpus = builtins.path { path = historical + "/SOURCE_MANIFEST1.json"; name = "osbus-authorization-corpus.json"; };
  pinned = (builtins.fromJSON (builtins.readFile (fixtures + "/inherited/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-authorization-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-authorization-runtime.json"; };
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "osbus-authorization-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  adapter = pkgs.runCommand "osbus-authorization-current-inputs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 -B ${./normalize.py} ${artifact} ${runtime} ${fixtures} ${corpus} "$out"
  '';
in
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert builtins.hashFile "sha256" corpus == "992aa6dec8b021a68398757886e7173110cde28bd6c3cf54daf3a6e7b7fe88e5";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-authorization-current";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 8192;
    virtualisation.cores = 2;
    virtualisation.emptyDiskImages = [ 16384 ];
    users.groups.foundationA.gid = 1100;
    users.groups.foundationB.gid = 1101;
    users.groups.foundationC.gid = 1102;
    users.groups.foundationDenied.gid = 1103;
    users.groups.foundationReload.gid = 1104;
    users.users.foundationA = { isNormalUser = true; uid = 1100; group = "foundationA"; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    users.users.foundationC = { isNormalUser = true; uid = 1102; group = "foundationC"; };
    users.users.foundationDenied = { isNormalUser = true; uid = 1103; group = "foundationDenied"; };
    users.users.foundationReload = { isNormalUser = true; uid = 1104; group = "foundationReload"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils pkgs.e2fsprogs ];
    environment.etc."osbus-candidate-runtime".source = anchors;
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-security/sec09-sec12-complete"
    shutdown = {"VMoff": False, "socket_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        # Keep retained transcripts off /run's small RAM filesystem. This disk
        # exists only in the disposable VM; daemon/workload bounds are unchanged.
        machine.succeed("test $(blockdev --getsize64 /dev/vdb) -eq 17179869184")
        machine.succeed("mkfs.ext4 -F /dev/vdb")
        machine.succeed("install -d -m 0755 /run/osbus-security")
        machine.succeed("mount /dev/vdb /run/osbus-security")
        machine.succeed("install -d -m 0755 " + evidence)
        machine.succeed("cp ${adapter}/bindings.json " + evidence + "/current-bindings.json")
        command = "PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 SEC09_SEC12_CANDIDATE_MANIFEST_SHA256=$(cat ${adapter}/manifest-sha256) SEC09_SEC12_CANDIDATE_SOURCE_SHA256=$(cat ${adapter}/source-sha256) timeout --signal=TERM --kill-after=3s 480s python3 -B ${adapter}/fixtures/collect.py ${adapter}/candidate ${adapter}/fixtures/inherited/security " + evidence + " complete_core ${pkgs.dbus}/bin/dbus-daemon > " + evidence + "/collector.log 2>&1"
        status, output = machine.execute(command, timeout=490)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/collector.log")
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e " + evidence + "/bus")[0] == 0
            machine.copy_from_vm(evidence, "authorization-current-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "authorization-current-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
