# Accepted complete SEC04 corpus with current immutable candidate metadata.
{ candidatePath, artifactPath, runtimeManifestPath }:
let
  historical = ../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec04-complete1/source1;
  fixtures = builtins.path { path = historical + "/fixture1"; name = "osbus-auth-bypass-original-fixtures"; };
  corpus = builtins.path { path = historical + "/SOURCE_MANIFEST1.json"; name = "osbus-auth-bypass-corpus.json"; };
  pinned = (builtins.fromJSON (builtins.readFile (fixtures + "/inherited/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  candidate = builtins.path { path = builtins.toPath candidatePath; name = "osbus-auth-bypass-candidate"; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-auth-bypass-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-auth-bypass-runtime.json"; };
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "osbus-auth-bypass-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  adapter = pkgs.runCommand "osbus-auth-bypass-current-inputs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 -B ${./normalize.py} ${candidate} ${artifact} ${runtime} ${fixtures} ${corpus} "$out"
  '';
in
assert pkgs.dbus.version == "1.14.10";
assert (pkgs.dbus.patches or []) == [];
assert builtins.hashFile "sha256" (candidate + "/candidate.json") == "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert builtins.hashFile "sha256" corpus == "d574c6b62b7c6fa3005b1170286bbc2d0dd619457c22f7a50eb131cf6757c206";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-auth-bypass-current";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    virtualisation.emptyDiskImages = [ 16384 ];
    users.groups.foundationA.gid = 1100;
    users.groups.foundationB.gid = 1101;
    users.users.foundationA = { isNormalUser = true; uid = 1100; group = "foundationA"; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils pkgs.e2fsprogs ];
    environment.etc."osbus-candidate-runtime".source = anchors;
    environment.etc."osbus-security-guest" = { text = "isolated-vm\n"; mode = "0444"; };
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-security/sec04-complete"
    shutdown = {"VMoff": False, "socket_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("test -f /etc/osbus-security-guest && test ! -L /etc/osbus-security-guest && test $(stat -c %a /etc/osbus-security-guest) = 444")
        # Retain transcripts on the disposable guest disk, outside /run tmpfs.
        machine.succeed("test $(blockdev --getsize64 /dev/vdb) -eq 17179869184")
        machine.succeed("mkfs.ext4 -F /dev/vdb")
        machine.succeed("install -d -m 0755 /run/osbus-security")
        machine.succeed("mount /dev/vdb /run/osbus-security")
        machine.succeed("install -d -m 0755 " + evidence)
        machine.succeed("cp ${adapter}/bindings.json " + evidence + "/current-bindings.json")
        command = "PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 SEC04_CANDIDATE_MANIFEST_SHA256=fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82 SEC04_CANDIDATE_SOURCE_SHA256=f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c timeout --signal=TERM --kill-after=3s 120s python3 -B ${adapter}/fixtures/run.py ${candidate} ${adapter}/fixtures/inherited/security " + evidence + " complete_core ${pkgs.dbus}/bin/dbus-daemon > " + evidence + "/runner.log 2>&1"
        status, output = machine.execute(command, timeout=130)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/runner.log")
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e " + evidence + "/reference/bus && test ! -e " + evidence + "/gao_bus/bus")[0] == 0
            machine.copy_from_vm(evidence, "auth-bypass-current-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "auth-bypass-current-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
