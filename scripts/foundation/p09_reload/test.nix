# Disposable three-UID reload, alias and Properties.Set/GetAll evidence against immutable development artifacts.
{ candidatePath ? null, expectedTests ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "candidatePath must identify a frozen capture"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-reload-candidate"; };
  selected = if builtins.isInt expectedTests && expectedTests == 6 then expectedTests
    else throw "expectedTests must freeze exactly 6 reload, alias and Properties.Set/GetAll tests";
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-reload-runtime" (builtins.concatStringsSep "\n"
    ([ elixir otp ] ++ map builtins.storePath manifest.runtime.native_store_roots));
  fixtures = pkgs.runCommand "osbus-reload-fixtures" {} ''
    install -D ${./run.py} $out/run.py
    install -D ${../../../apps/gao_bus/test/test_helper.exs} $out/apps/gao_bus/test/test_helper.exs
    install -D ${../../../apps/gao_bus/test/policy/file_reload_socket_test.exs} $out/apps/gao_bus/test/policy/file_reload_socket_test.exs
    install -D ${../../../apps/gao_bus/test/fixtures/reload_actor.py} $out/apps/gao_bus/test/fixtures/reload_actor.py
    install -D ${../../../apps/gao_bus/test/fixtures/api_contract_selection.json} $out/apps/gao_bus/test/fixtures/api_contract_selection.json
    install -D ${../../../apps/gao_bus/test/fixtures/transport_actor.py} $out/apps/gao_bus/test/fixtures/transport_actor.py
  '';
in pkgs.testers.nixosTest {
  name = "osbus-p09-wire-reload";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.dbus ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-reload-runtime".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0755 /run/osbus-p09-reload")
    try:
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 python3 ${fixtures}/run.py ${frozen} ${fixtures} /run/osbus-p09-reload ${toString selected}", timeout=180))
    finally:
        try:
            machine.copy_from_vm("/run/osbus-p09-reload", "p09-reload-evidence")
        finally:
            machine.shutdown()
  '';
}
