# One positive PRO01 whole-stream case, frozen product and test-only Jason.
{ artifactPath, runtimeManifestPath, testDependencyPath, nixpkgsPath }:
let
  # Caller verifies the cached tree's NAR hash against devenv.lock before selection.
  # An explicit store path keeps read-only preparation free of network fallbacks.
  source = builtins.storePath nixpkgsPath;
  pkgs = import source { system = "x86_64-linux"; config = {}; overlays = []; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "os-bus-whole-stream-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "os-bus-whole-stream-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile (artifact + "/artifact.json"));
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  runtimeSha256 = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-whole-stream-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  tests = [ "apps/gao_bus/test/peer_whole_stream_test.exs" ];
  helpers = map (name: "apps/gao_bus/test/fixtures/${name}.py") [
    "peer_whole_stream_actor" "peer_hello_split_boundaries_actor" "transport_actor"
  ];
  root = toString ../..;
  paths = tests ++ helpers;
  fullPaths = map (name: root + "/" + name) paths;
  prefix = start: value: builtins.substring 0 (builtins.stringLength start) value == start;
  fixtures = builtins.path {
    path = ../..;
    name = "os-bus-whole-stream-fixtures";
    filter = path: type: builtins.elem path fullPaths ||
      (type == "directory" && builtins.any (name: prefix (path + "/") name) fullPaths);
  };
  dependency = builtins.path {
    path = builtins.toPath (testDependencyPath + "/ebin");
    name = "os-bus-whole-stream-test-jason-ebin";
  };
  dependencyEntries = builtins.readDir dependency;
  hashFiles = base: names: builtins.listToAttrs (map (name: {
    inherit name;
    value = builtins.hashFile "sha256" (base + "/${name}");
  }) names);
  runner = builtins.path {
    path = ../../scripts/foundation/pro01_whole_stream_runner.exs;
    name = "os-bus-whole-stream-runner.exs";
  };
  bindings = pkgs.writeText "os-bus-whole-stream-bindings.json" (builtins.toJSON {
    selection = "pro01-whole-stream";
    expected_tests = 1;
    artifact_store = toString artifact;
    artifact_sha256 = builtins.hashFile "sha256" (artifact + "/artifact.json");
    runtime_sha256 = runtimeSha256;
    runtime_store = toString runtime;
    nixpkgs_lock_sha256 = builtins.hashFile "sha256" ../../devenv.lock;
    fixtures_store = toString fixtures;
    fixture_hashes = hashFiles fixtures paths;
    tests = tests;
    dependency_store = toString dependency;
    dependency_hashes = hashFiles dependency (builtins.attrNames dependencyEntries);
    runner_sha256 = builtins.hashFile "sha256" runner;
    not_a_release = true;
  });
in
assert builtins.hashFile "sha256" runtime == runtimeSha256;
assert manifest.not_a_release && runtimeManifest.not_a_release;
assert manifest.origin_pin.sha256 == runtimeSha256;
assert builtins.length (builtins.attrNames manifest.files) == 80;
assert builtins.length (builtins.attrNames manifest.sources) == 71;
assert runtimeManifest.runtime.elixir_store == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert runtimeManifest.runtime.otp_store == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
assert builtins.hasAttr "Elixir.Jason.beam" dependencyEntries && builtins.hasAttr "jason.app" dependencyEntries;
assert builtins.all (kind: kind == "regular") (builtins.attrValues dependencyEntries);
pkgs.testers.nixosTest {
  name = "os-bus-foundation-pro01-whole-stream";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.groups.foundationB.gid = 1101;
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils ];
    environment.etc."osbus-whole-stream-runtime-roots".source = anchors;
    environment.etc."osbus-pro01-whole-stream-guest" = { text = "isolated-vm\n"; mode = "0444"; };
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-pro01-whole-stream"
    shutdown = {"VMoff": False, "private_directory_empty": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 -o 1101 -g 1101 " + evidence)
        machine.succeed("install -d -m 0700 -o 1101 -g 1101 " + evidence + "/private")
        machine.succeed("cp ${bindings} " + evidence + "/bindings.json")
        command = "timeout --signal=TERM --kill-after=3s 240s runuser -u foundationB -- env PATH=${elixir}/bin:${otp}/bin:$PATH TMPDIR=" + evidence + "/private PYTHONDONTWRITEBYTECODE=1 DBUS_SYSTEM_BUS_ADDRESS=unix:path=" + evidence + "/private/unused-system DBUS_SESSION_BUS_ADDRESS=unix:path=" + evidence + "/private/unused-session ${elixir}/bin/elixir --erl '+S 2:2' -pa ${artifact}/lib/ex_d_bus/ebin -pa ${artifact}/lib/gao_bus/ebin -pa ${artifact}/lib/phoenix_pubsub/ebin -pa ${dependency} ${runner} ${bindings} " + evidence + " > " + evidence + "/output.log 2>&1"
        status, output = machine.execute(command, timeout=250)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/output.log")
    finally:
        try:
            shutdown["private_directory_empty"] = machine.execute("test -d " + evidence + "/private && test -z \"$(find " + evidence + "/private -mindepth 1 -print -quit)\"")[0] == 0
            machine.copy_from_vm(evidence, "whole-stream-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "whole-stream-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "private_directory_empty": True}
  '';
}
