# Frozen capture.py contract and original fixtures are reused unchanged.
{ candidatePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "RES01 requires a root-frozen compiled candidatePath"
    else builtins.path { path = builtins.toPath candidatePath; name = "os-bus-res01-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-res01-runtime" (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  original = builtins.path { path = ../vm_security; name = "os-bus-security-original"; };
  base = builtins.path { path = ../vm_security_res01; name = "os-bus-res01-measurement-base"; };
  measurement = builtins.path { path = ../vm_security_res01_measurement1; name = "os-bus-res01-measurement-fixtures"; };
  compiledMapping = builtins.path { path = ./.; name = "os-bus-res01-compiled-mapping-source"; };
  # Only the new output directory and launcher are made writable; source/candidate inputs stay immutable.
  fixtures = pkgs.runCommand "os-bus-res01-compiled-mapping-fixtures" {} ''
    mkdir "$out"
    cp -a ${measurement}/. "$out/"
    chmod u+w "$out" "$out/launcher.exs"
    cp ${compiledMapping}/launcher.exs "$out/launcher.exs"
    cp ${compiledMapping}/mapper-helper.exs "$out/mapper-helper.exs"
    cp ${compiledMapping}/MAPPING_BINDINGS1.json "$out/MAPPING_BINDINGS1.json"
  '';
in
assert builtins.hashFile "sha256" (frozen + "/candidate.json") == "372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7";
assert manifest.source_sha256 == "efe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9";
pkgs.testers.nixosTest {
  name = "os-bus-res01-compiled-mapping-diagnostic";
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
        machine.succeed("install -d -m 0755 /run/osbus-security/res01")
        print(machine.succeed("RES01_MEASUREMENT_BASE=${base} PATH=${elixir}/bin:${otp}/bin:$PATH timeout --signal=TERM --kill-after=3s 120s python3 ${fixtures}/run.py ${frozen} ${original} /run/osbus-security/res01"))
        machine.succeed("test ! -e /run/osbus-security/res01/bus")
        shutdown["socket_removed"] = True
    finally:
        try:
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-security/res01\"); target=Path(\"/run/res01-export\"); target.mkdir(); [shutil.copyfile(path, target/path.name) for path in source.iterdir() if path.is_file()]'")
            machine.copy_from_vm("/run/res01-export", "res01-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "res01-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
