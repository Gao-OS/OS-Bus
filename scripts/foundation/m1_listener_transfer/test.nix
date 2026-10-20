# Source-prepared standalone guest; root binds a post-correction candidate.
{ candidatePath ? null, candidateManifestSha256 ? null, candidateSourceSha256 ? null,
  selection ? "transfer_failure" }:
let
  pinned = (builtins.fromJSON (builtins.readFile ./inherited/devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "Listener transfer VM requires a root-frozen post-correction candidatePath"
    else builtins.path { path = builtins.toPath candidatePath; name = "os-bus-listener-transfer-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-listener-transfer-runtime" (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  original = builtins.path { path = ./inherited/security; name = "os-bus-security-original"; };
  fixtures = builtins.path { path = ./.; name = "os-bus-listener-transfer-fixtures"; };
in
assert selection == "transfer_failure";
assert candidateManifestSha256 != null && candidateSourceSha256 != null;
assert builtins.match "[0-9a-f]{64}" candidateManifestSha256 != null;
assert builtins.match "[0-9a-f]{64}" candidateSourceSha256 != null;
assert builtins.hashFile "sha256" (frozen + "/candidate.json") == candidateManifestSha256;
assert manifest.source_sha256 == candidateSourceSha256;
assert candidateManifestSha256 == "372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7";
assert candidateSourceSha256 == "efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-listener-transfer";
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
    shutdown = {"VMoff": False, "socket_removed": False, "fault_path_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-security/listener-transfer")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH LISTENER_TRANSFER_CANDIDATE_MANIFEST_SHA256=${candidateManifestSha256} LISTENER_TRANSFER_CANDIDATE_SOURCE_SHA256=${candidateSourceSha256} timeout --signal=TERM --kill-after=3s 120s python3 ${fixtures}/run.py ${frozen} ${original} /run/osbus-security/listener-transfer ${selection}"))
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-security/listener-transfer/bus")[0] == 0
            shutdown["fault_path_removed"] = machine.execute("test ! -e /run/osbus-security/listener-transfer/transfer")[0] == 0
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-security/listener-transfer\"); target=Path(\"/run/listener-transfer-export\"); target.mkdir(); [shutil.copyfile(path, target/path.name) for path in source.iterdir() if path.is_file()]'")
            machine.copy_from_vm("/run/listener-transfer-export", "listener-transfer-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "listener-transfer-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True, "fault_path_removed": True}
  '';
}
