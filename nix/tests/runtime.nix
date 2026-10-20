# P01 infrastructure proof only. It does not qualify OS-Bus or replace this VM's bus.
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree {
    type = "github";
    inherit (pinned) owner repo rev narHash;
  };
  pkgs = import source.outPath { system = "x86_64-linux"; config = { }; overlays = [ ]; };
in
pkgs.testers.nixosTest {
  name = "os-bus-foundation-runtime";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1024;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux ];
    system.stateVersion = "25.11";
    environment.etc."foundation-identities.py".text = ''
      import os, pathlib, socket, struct, subprocess, tempfile
      with tempfile.TemporaryDirectory(prefix="osbus-identities-") as directory:
          # All identities must traverse this disposable VM-only fixture directory.
          os.chmod(directory, 0o755)
          path = directory + "/bus"
          listener = socket.socket(socket.AF_UNIX)
          listener.settimeout(5)
          listener.bind(path)
          os.chmod(path, 0o666)
          listener.listen()
          for user, uid in [("foundationA", 1100), ("foundationB", 1101)]:
              code = "import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]); s.sendall(b'probe'); assert s.recv(2)==b'ok'"
              actor = subprocess.Popen(["runuser", "-u", user, "--", "python3", "-c", code, path])
              try:
                  peer, _ = listener.accept()
                  peer.settimeout(5)
                  pid, actual_uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                  assert actual_uid == uid, (user, actual_uid)
                  status = pathlib.Path(f"/proc/{pid}/status").read_text()
                  assert [int(x) for x in next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1:]] == [uid] * 4, status
                  assert peer.recv(5) == b"probe"
                  peer.sendall(b"ok")
                  peer.close()
                  assert actor.wait(timeout=5) == 0
                  print(f"H-03 actor={user} pid={pid} uid={actual_uid} gid={gid} passed", flush=True)
              finally:
                  if actor.poll() is None:
                      actor.kill()
                      actor.wait(timeout=5)
          listener.close()
    '';
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    print(machine.succeed("uname -a; python3 /etc/foundation-identities.py"))
    machine.shutdown()
  '';
}
