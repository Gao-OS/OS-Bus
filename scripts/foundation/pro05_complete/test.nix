# Disposable core PRO05 runtime; requires explicit frozen artifact/runtime inputs.
{ artifactPath ? null, runtimeManifestPath ? null, selection ? "complete_core" }:
let
  bindings = builtins.fromJSON (builtins.readFile ./bindings.json);
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if artifactPath == null then throw "PRO05 requires the current root-frozen artifactPath"
    else builtins.path { path = builtins.toPath artifactPath; name = "os-bus-pro05-current-artifact"; };
  runtimeFile = if runtimeManifestPath == null then throw "PRO05 requires the pinned runtimeManifestPath"
    else builtins.path { path = builtins.toPath runtimeManifestPath; name = "os-bus-pro05-runtime-manifest.json"; };
  artifact = builtins.fromJSON (builtins.readFile (frozen + "/artifact.json"));
  runtimeManifest = builtins.fromJSON (builtins.readFile runtimeFile);
  # Only runtime store roots come from this older manifest. Runnable/source
  # identity belongs exclusively to the current artifact, never its origin.
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-pro05-runtime" (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  repositoryRoot = toString ../../..;
  helperNames = builtins.attrNames bindings.helpers;
  helperPaths = map (name: repositoryRoot + "/" + name) helperNames;
  startsWith = prefix: value: builtins.substring 0 (builtins.stringLength prefix) value == prefix;
  repository = builtins.path {
    path = ../../..;
    name = "os-bus-pro05-inherited-helpers";
    filter = path: type:
      builtins.elem path helperPaths ||
      (type == "directory" && builtins.any (name: startsWith (path + "/") name) helperPaths);
  };
  fixtures = builtins.path { path = ./.; name = "os-bus-pro05-fixtures"; };
  referenceExecutable = "${pkgs.dbus}/bin/dbus-daemon";
in
assert selection == "complete_core";
assert builtins.hashFile "sha256" (frozen + "/artifact.json") == bindings.artifact_sha256;
assert builtins.hashFile "sha256" runtimeFile == bindings.runtime_manifest_sha256;
assert builtins.hashFile "sha256" ../../../devenv.lock == bindings.nixpkgs_lock_sha256;
assert artifact.not_a_release && runtimeManifest.not_a_release;
assert artifact.origin_pin.sha256 == bindings.runtime_manifest_sha256;
assert builtins.length (builtins.attrNames artifact.sources) == bindings.production_sources;
assert builtins.length (builtins.attrNames artifact.files) == bindings.artifact_files;
pkgs.testers.nixosTest {
  name = "os-bus-foundation-pro05-complete-core";
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
    environment.etc."osbus-security-guest".mode = "0444";
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
        machine.succeed("install -d -m 0755 /run/osbus-security/pro05-complete")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH timeout --signal=TERM --kill-after=3s 260s python3 ${fixtures}/run.py ${frozen} ${repository} /run/osbus-security/pro05-complete ${selection} ${referenceExecutable}"))
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-security/pro05-complete/reference/bus && test ! -e /run/osbus-security/pro05-complete/gao_bus/bus")[0] == 0
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-security/pro05-complete\"); target=Path(\"/run/pro05-complete-export\"); shutil.copytree(source, target)'")
            machine.copy_from_vm("/run/pro05-complete-export", "pro05-complete-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "pro05-complete-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
