# Source-prepared standalone guest; root binds a post-correction candidate.
{ candidatePath ? null, candidateManifestSha256 ? null, candidateSourceSha256 ? null,
  selection ? "all" }:
let
  pinned = (builtins.fromJSON (builtins.readFile ./inherited/devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "UID abrupt VM requires a root-frozen post-correction candidatePath"
    else builtins.path { path = builtins.toPath candidatePath; name = "os-bus-uid-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-uid-runtime" (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  original = builtins.path { path = ./inherited/security; name = "os-bus-security-original"; };
  fixtures = builtins.path { path = ./.; name = "os-bus-uid-fixtures"; };
in
assert builtins.elem selection [ "all" "uid_names" "uid_matches" ];
assert candidateManifestSha256 != null && candidateSourceSha256 != null;
assert builtins.match "[0-9a-f]{64}" candidateManifestSha256 != null;
assert builtins.match "[0-9a-f]{64}" candidateSourceSha256 != null;
assert builtins.hashFile "sha256" (frozen + "/candidate.json") == candidateManifestSha256;
assert manifest.source_sha256 == candidateSourceSha256;
assert candidateSourceSha256 != "f5dfe03ced34c9b24e69b780588156330a74d2ee025a07dcf2dd0e5d395eab92";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-uid-abrupt-peer";
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
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH UID_ABRUPT_CANDIDATE_MANIFEST_SHA256=${candidateManifestSha256} UID_ABRUPT_CANDIDATE_SOURCE_SHA256=${candidateSourceSha256} timeout --signal=TERM --kill-after=3s 120s python3 ${fixtures}/run.py ${frozen} ${original} /run/osbus-security/uid-abrupt-peer ${selection}"))
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
