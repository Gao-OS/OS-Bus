# Ten native dimensions in two independent, originally bounded daemon phases.
{ candidatePath, artifactPath, runtimeManifestPath }:
let
  root = ../../..;
  pinned = (builtins.fromJSON (builtins.readFile (root + "/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  pins = builtins.fromJSON (builtins.readFile ./inputs.json);
  sourceFiles = map (pin: pin.path) (builtins.attrValues pins);
  inputs = builtins.path {
    path = root;
    name = "osbus-resources-accepted-sources";
    filter = path: type:
      let relative = pkgs.lib.removePrefix ((toString root) + "/") (toString path);
      in toString path == toString root || builtins.any
        (name: relative == name || (type == "directory" && pkgs.lib.hasPrefix (relative + "/") name)) sourceFiles;
  };
  local = builtins.path { path = ./.; name = "osbus-resources-current-source"; };
  candidate = builtins.path { path = builtins.toPath candidatePath; name = "osbus-resources-candidate"; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-resources-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-resources-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  # The pristine reference is retained in the closure; this native fixture does
  # not execute it or infer reference conformance from its presence.
  anchors = pkgs.writeText "osbus-resources-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp pkgs.dbus] ++ nativeRoots));
  adapter = pkgs.runCommand "osbus-resources-current-inputs" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 -B ${local}/normalize.py ${candidate} ${artifact} ${runtime} ${inputs} "$out"
  '';
in
assert pkgs.dbus.version == "1.14.10";
assert (pkgs.dbus.patches or []) == [];
assert builtins.hashFile "sha256" (candidate + "/candidate.json") == "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-resources-current";
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
    evidence = "/run/osbus-security/resources-current"
    directories = {"res01": "/run/osbus-security/res01", "uid": "/run/osbus-security/uid-authorities"}
    shutdown = {"VMoff": False, "socket_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("test -f /etc/osbus-security-guest && test ! -L /etc/osbus-security-guest && test $(stat -c %a /etc/osbus-security-guest) = 444")
        machine.succeed("test $(blockdev --getsize64 /dev/vdb) -eq 17179869184")
        machine.succeed("mkfs.ext4 -F /dev/vdb")
        machine.succeed("install -d -m 0755 /run/osbus-security")
        machine.succeed("mount /dev/vdb /run/osbus-security")
        machine.succeed("install -d -m 0755 " + evidence + " " + " ".join(directories.values()))
        machine.succeed("cp ${adapter}/bindings.json " + evidence + "/current-bindings.json")
        contract = "python3 -B ${adapter}/contract.py "
        arguments = " ${adapter} ${candidate} " + evidence
        machine.succeed(contract + "init" + arguments)
        for phase, directory in directories.items():
            command = "PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 timeout --signal=TERM --kill-after=3s 120s python3 -B ${adapter}/" + phase + "/run.py ${candidate} ${adapter}/original " + directory
            if phase == "uid":
                command += " all"
            status, output = machine.execute(command + " > " + directory + "/runner.log 2>&1", timeout=130)
            machine.succeed("printf '%s\\n' " + str(status) + " > " + directory + "/exit-status")
            checker_status, checker_output = machine.execute(contract + "record" + arguments + " " + phase + " " + str(status) + " > " + directory + "/integration-check.log 2>&1", timeout=130)
            machine.succeed("printf '%s\\n' " + str(checker_status) + " > " + directory + "/integration-check-status")
        machine.succeed(contract + "final" + arguments)
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-security/res01/bus && test ! -e /run/osbus-security/uid-authorities/bus")[0] == 0
            for directory in [evidence] + list(directories.values()):
                machine.copy_from_vm(directory, "resources-current-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "resources-current-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
