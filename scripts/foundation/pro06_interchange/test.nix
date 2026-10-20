# PRO06 normal nested interchange only; no descriptor or full-gate claim.
{ candidatePath, artifactPath, runtimeManifestPath, jasonPath }:
let
  root = ../../..;
  historical = root + "/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec01-complete1/source4/fixture1";
  donor = builtins.path { path = historical; name = "osbus-pro06-sec01-donor"; };
  pinned = (builtins.fromJSON (builtins.readFile (donor + "/inherited/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  candidate = builtins.storePath candidatePath;
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-pro06-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-pro06-runtime.json"; };
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  jason = builtins.path { path = builtins.toPath jasonPath; name = "osbus-pro06-jason"; };
  testRoot = root + "/apps/gao_bus_test/test";
  names = [
    "fixture/process_guard" "fixture/process_guard.c" "fixture/pro06_interchange.c"
    "support/e2e/child_process.ex" "support/e2e/command.ex" "support/e2e/result.ex"
    "support/e2e/qualification.ex" "support/e2e/selection.ex"
    "support/e2e/fixtures/h04_system_daemon.exs"
    "harness/pro06_interchange_test.exs"
  ];
  allowed = map (name: toString (testRoot + ("/" + name))) names;
  testTree = builtins.path {
    path = testRoot;
    name = "osbus-pro06-test-sources";
    filter = path: type: type == "directory" || builtins.elem (toString path) allowed;
  };
  inputs = pkgs.runCommand "osbus-pro06-normal-inputs" {
    nativeBuildInputs = [ pkgs.stdenv.cc pkgs.pkg-config ];
    buildInputs = [ pkgs.glib ];
  } ''
    mkdir -p "$out/tree" "$out/ebin" "$out/bin"
    cp -R ${testTree}/. "$out/tree/"
    ${pkgs.stdenv.cc}/bin/cc -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O2 \
      "$out/tree/fixture/pro06_interchange.c" \
      $(pkg-config --cflags --libs gio-2.0) -o "$out/bin/pro06_interchange"
    export PATH=${elixir}/bin:${otp}/bin:$PATH
    export ERL_FLAGS='+S 2:2 +SDcpu 1 +SDio 1'
    elixirc --warnings-as-errors -pa ${jason}/ebin -o "$out/ebin" \
      "$out/tree/support/e2e/child_process.ex" "$out/tree/support/e2e/command.ex" \
      "$out/tree/support/e2e/result.ex" "$out/tree/support/e2e/qualification.ex" \
      "$out/tree/support/e2e/selection.ex"
    cp ${./run_suite.exs} "$out/run_suite.exs"
    ${pkgs.python3}/bin/python3 -B ${./package.py} "$out" ${donor} ${candidate} ${artifact} ${runtime} \
      ${pkgs.dbus}/bin/dbus-daemon ${elixir}/bin/elixir ${pkgs.python3}/bin/python3 \
      ${pkgs.util-linux}/bin/runuser ${jason} ${pkgs.glib.version}
  '';
  anchors = pkgs.writeText "osbus-pro06-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
in
assert pkgs.dbus.version == "1.14.10";
assert (pkgs.dbus.patches or []) == [];
assert pkgs.glib.version == "2.86.3";
assert builtins.hashFile "sha256" (candidate + "/candidate.json") == "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-pro06-normal";
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
    environment.etc."osbus-security-guest" = { text = "isolated-vm\n"; mode = "0444"; };
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-security/pro06-normal-interchange1"
    shutdown = {"VMoff": False, "private_endpoints_absent": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 " + evidence)
        machine.succeed("cp ${inputs}/bindings.json ${inputs}/provenance.json " + evidence)
        command = "cd " + evidence + " && PATH=${elixir}/bin:${otp}/bin:${pkgs.python3}/bin:${pkgs.util-linux}/bin:${pkgs.coreutils}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PRO06_BINDINGS=${inputs}/bindings.json timeout --signal=TERM --kill-after=3s 160s ${elixir}/bin/elixir --erl '+S 2:2' -pa ${inputs}/ebin -pa ${jason}/ebin ${inputs}/run_suite.exs ${inputs}/tree/harness/pro06_interchange_test.exs " + evidence + " > " + evidence + "/suite.log 2>&1"
        status, output = machine.execute(command, timeout=170)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/suite.log")
    finally:
        try:
            shutdown["private_endpoints_absent"] = machine.execute("test ! -e /run/osbus-security/sec01-complete/reference/bus && test ! -e /run/osbus-security/sec01-complete/gao_bus/bus")[0] == 0
            machine.copy_from_vm(evidence, "pro06-normal-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "pro06-normal-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "private_endpoints_absent": True}
  '';
}
