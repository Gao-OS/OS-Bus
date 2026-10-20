# Six unchanged native PRO04 regressions; partial functional evidence only.
{ artifactPath, runtimeManifestPath }:
let
  root = ../../..;
  pinned = (builtins.fromJSON (builtins.readFile (root + "/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "osbus-pro04-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-pro04-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile (artifact + "/artifact.json"));
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  artifactSha256 = "b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1";
  runtimeSha256 = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "osbus-pro04-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  tests = map (name: "apps/gao_bus/test/peer_${name}_test.exs") [
    "fixed_header_lengths" "body_signature" "xml_message_size" "xml_frame_deadline"
  ];
  helpers = map (name: "apps/gao_bus/test/fixtures/${name}.py") [
    "peer_fixed_header_lengths_actor" "peer_body_signature_actor"
    "peer_xml_message_size_actor" "peer_xml_frame_deadline_actor"
    "peer_hello_split_boundaries_actor" "transport_actor"
  ];
  paths = tests ++ helpers;
  fullPaths = map (name: toString root + "/" + name) paths;
  prefix = start: value: builtins.substring 0 (builtins.stringLength start) value == start;
  fixtures = builtins.path {
    path = root;
    name = "osbus-pro04-fixtures";
    filter = path: type: builtins.elem path fullPaths ||
      (type == "directory" && builtins.any (name: prefix (path + "/") name) fullPaths);
  };
  runner = builtins.path { path = ./runner.exs; name = "osbus-pro04-runner.exs"; };
  bindings = pkgs.writeText "osbus-pro04-bindings.json" (builtins.toJSON {
    selection = "pro04-native";
    expected_tests = 6;
    artifact_store = toString artifact;
    artifact_sha256 = artifactSha256;
    runtime_store = toString runtime;
    runtime_sha256 = runtimeSha256;
    nixpkgs_lock_sha256 = builtins.hashFile "sha256" (root + "/devenv.lock");
    fixtures_store = toString fixtures;
    fixture_hashes = builtins.listToAttrs (map (name: {
      inherit name;
      value = builtins.hashFile "sha256" (fixtures + "/${name}");
    }) paths);
    inherit tests;
    runner_sha256 = builtins.hashFile "sha256" runner;
    not_a_release = true;
  });
in
assert builtins.hashFile "sha256" (artifact + "/artifact.json") == artifactSha256;
assert builtins.hashFile "sha256" runtime == runtimeSha256;
assert manifest.not_a_release && runtimeManifest.not_a_release;
assert manifest.origin_pin.sha256 == runtimeSha256;
assert builtins.length (builtins.attrNames manifest.files) == 80;
assert builtins.length (builtins.attrNames manifest.sources) == 71;
assert builtins.all (name: builtins.hashFile "sha256" (root + "/${name}") == manifest.sources.${name}.sha256)
  (builtins.attrNames manifest.sources);
assert runtimeManifest.runtime.elixir_store == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert runtimeManifest.runtime.otp_store == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-pro04-current";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.groups.foundationB.gid = 1101;
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils ];
    environment.etc."osbus-pro04-runtime-roots".source = anchors;
    environment.etc."osbus-pro04-current-guest" = { text = "isolated-vm\n"; mode = "0444"; };
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-pro04-current"
    shutdown = {"VMoff": False, "private_directory_empty": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 -o 1101 -g 1101 " + evidence)
        machine.succeed("install -d -m 0700 -o 1101 -g 1101 " + evidence + "/private")
        machine.succeed("cp ${bindings} " + evidence + "/bindings.json")
        command = "timeout --signal=TERM --kill-after=3s 240s runuser -u foundationB -- env PATH=${elixir}/bin:${otp}/bin:$PATH TMPDIR=" + evidence + "/private PYTHONDONTWRITEBYTECODE=1 OS_BUS_FIXED_HEADER_UID=1101 OS_BUS_FIXED_HEADER_GID=1101 DBUS_SYSTEM_BUS_ADDRESS=unix:path=" + evidence + "/private/unused-system DBUS_SESSION_BUS_ADDRESS=unix:path=" + evidence + "/private/unused-session ${elixir}/bin/elixir --erl '+S 2:2' -pa ${artifact}/lib/ex_d_bus/ebin -pa ${artifact}/lib/gao_bus/ebin -pa ${artifact}/lib/phoenix_pubsub/ebin ${runner} ${bindings} " + evidence + " > " + evidence + "/output.log 2>&1"
        status, output = machine.execute(command, timeout=250)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/output.log")
    finally:
        try:
            shutdown["private_directory_empty"] = machine.execute("test -d " + evidence + "/private && test -z \"$(find " + evidence + "/private -mindepth 1 -print -quit)\"")[0] == 0
            machine.copy_from_vm(evidence, "pro04-current-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "pro04-current-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "private_directory_empty": True}
  '';
}
