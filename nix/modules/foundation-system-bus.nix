# Disposable VM profile only. Imported by tests/system_replacement.nix.
{ config, lib, pkgs, ... }:
let
  cfg = config.osBusFoundation;
  address = "unix:path=/run/dbus/system_bus_socket";
  python = pkgs.python3.withPackages (python: [ python.dbus-python ]);
  fixture = pkgs.runCommand "osbus-foundation-service" {
    nativeBuildInputs = [ pkgs.stdenv.cc pkgs.pkg-config ];
    buildInputs = [ pkgs.glib ];
  } ''
    mkdir -p $out/bin $out/share/dbus-1/system-services $out/share/dbus-1/system.d $out/share/polkit-1/actions
    cc -O2 -Wall -Wextra -Werror -fstack-protector-strong \
      ${../../apps/gao_bus_test/test/fixture/external_fixture.c} \
      $(pkg-config --cflags --libs gio-2.0 gio-unix-2.0) \
      -Wl,-z,relro,-z,now -o $out/bin/osbus-fixture
    cat > $out/share/dbus-1/system-services/com.test.ExternalFixture.service <<EOF
    [D-BUS Service]
    Name=com.test.ExternalFixture
    Exec=$out/bin/osbus-fixture --bus-address=${address}
    User=foundationSvc
    SystemdService=osbus-foundation-fixture.service
    EOF
    cat > $out/share/dbus-1/system.d/com.test.ExternalFixture.conf <<EOF
    <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
    <busconfig>
      <!-- Same finite VM-05 admission bound and reload input on both backends. -->
      <limit name="max_connections_per_user">16</limit>
      <limit name="max_incoming_bytes">262144</limit>
      <limit name="max_outgoing_bytes">262144</limit>
      <include ignore_missing="yes">/run/osbus-system/reload.conf</include>
      <policy user="foundationSvc"><allow own="com.test.ExternalFixture"/></policy>
      <policy user="foundationA"><allow own_prefix="org.foundation.VM05"/></policy>
      <policy context="default"><allow send_destination="com.test.ExternalFixture" send_interface="com.test.ExternalFixture"/></policy>
    </busconfig>
    EOF
    cat > $out/share/polkit-1/actions/org.foundation.OSBus.policy <<EOF
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
    <policyconfig><action id="org.foundation.OSBus.accept">
      <description>OS-Bus qualification actor</description>
      <message>Check the qualification actor identity</message>
      <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>no</allow_active></defaults>
    </action></policyconfig>
    EOF
  '';
in
{
  options.osBusFoundation = {
    backend = lib.mkOption {
      type = lib.types.enum [ "reference" "candidate" ];
      default = "reference";
      description = "Exclusive canonical system-bus owner in this disposable VM.";
    };
    release = lib.mkOption {
      type = lib.types.path;
      description = "Immutable captured headless release directory.";
    };
  };

  config = lib.mkMerge [
    {
      services.dbus.enable = true;
      services.dbus.implementation = "dbus";
      services.dbus.packages = [ fixture ];
      security.polkit.enable = true;
      users.users.foundationA = { isNormalUser = true; uid = 1100; };
      users.users.foundationB = { isNormalUser = true; uid = 1101; };
      # The QEMU module disables timesyncd startup. Keep its installed policy's
      # account and service alias available, as in the existing P10 profile.
      users.users.systemd-timesync = {
        uid = config.ids.uids.systemd-timesync;
        group = "systemd-timesync";
      };
      users.groups.systemd-timesync.gid = config.ids.gids.systemd-timesync;
      systemd.additionalUpstreamSystemUnits = [ "systemd-timesyncd.service" ];
      systemd.services.systemd-timesyncd.aliases = [ "dbus-org.freedesktop.timesync1.service" ];
      users.groups.foundationSvc.gid = 1102;
      users.users.foundationSvc = {
        isSystemUser = true;
        uid = 1102;
        group = "foundationSvc";
      };
      systemd.services.osbus-foundation-fixture = {
        description = "OS-Bus independent GLib activation/FD fixture";
        requires = [ "dbus.socket" ];
        after = [ "dbus.socket" ];
        serviceConfig = {
          Type = "dbus";
          BusName = "com.test.ExternalFixture";
          User = "foundationSvc";
          Group = "foundationSvc";
          ExecStart = "${fixture}/bin/osbus-fixture --bus-address=${address}";
          TimeoutStartSec = 15;
          TimeoutStopSec = 5;
          KillMode = "control-group";
        };
      };
      # A real PAM-managed login session, observed through logind over the same
      # canonical bus. This unit is started/stopped only by the guarded workload.
      systemd.services.osbus-foundation-session = {
        description = "OS-Bus real PAM/logind session actor";
        requires = [ "dbus.socket" "systemd-logind.service" ];
        after = [ "dbus.socket" "systemd-logind.service" ];
        serviceConfig = {
          Type = "simple";
          User = "foundationA";
          PAMName = "login";
          ExecStart = "${python}/bin/python3 -B ${../../scripts/foundation/p12_system}/vm05.py session";
          RuntimeMaxSec = 60;
          TimeoutStopSec = 5;
          KillMode = "control-group";
        };
      };
      security.polkit.extraConfig = ''
        polkit.addRule(function(action, subject) {
          if (action.id == "org.foundation.OSBus.accept") {
            if (subject.user == "foundationA") return polkit.Result.YES;
            return polkit.Result.NO;
          }
        });
      '';
      environment.etc."osbus-system-guest".text = "isolated-vm\n";
      environment.etc."osbus-system-backend".text = cfg.backend + "\n";
      environment.systemPackages = [
        python
        fixture pkgs.util-linux pkgs.systemd pkgs.dbus pkgs.coreutils pkgs.iproute2
      ];
      environment.pathsToLink = [ "/share/polkit-1/actions" ];
      systemd.tmpfiles.rules = [ "d /run/osbus-system 0755 root root -" ];
      system.stateVersion = "25.11";
    }
    (lib.mkIf (cfg.backend == "candidate") {
      # The normal reference package/policies remain installed. Only this unit's
      # executable changes; no second unit competes for the canonical socket.
      systemd.services.dbus = {
        overrideStrategy = "asDropin";
        environment = {
          OS_BUS_CONFIG = "/etc/dbus-1/system.conf";
          OS_BUS_INHERITED_LISTENER = "true";
          OS_BUS_ACTIVATION = "systemd";
          RELEASE_TMP = "/run/osbus-system/release";
          PATH = lib.mkForce "/run/current-system/sw/bin";
        };
        serviceConfig = {
          Type = lib.mkForce "notify";
          NotifyAccess = lib.mkForce "main";
          User = lib.mkForce "messagebus";
          Group = lib.mkForce "messagebus";
          ExecStart = lib.mkForce [ "" "${cfg.release}/bin/os_bus start" ];
          ExecReload = lib.mkForce [ "" "${pkgs.systemd}/bin/busctl --address=${address} call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig" ];
          Restart = lib.mkForce "on-failure";
          RestartSec = 1;
          KillMode = lib.mkForce "control-group";
          TimeoutStartSec = lib.mkForce 45;
          TimeoutStopSec = lib.mkForce 10;
          # dbus.socket owns the canonical endpoint's parent across restarts.
          RuntimeDirectory = lib.mkForce [ "osbus-system/release" ];
        };
      };
      systemd.sockets.dbus.socketConfig.FileDescriptorName = "dbus";
    })
  ];
}
