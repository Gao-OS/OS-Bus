{ pkgs, lib, inputs, ... }:

let
  pkgs-stable = import inputs.nixpkgs-stable { system = pkgs.stdenv.system; };
in
{
  # Elixir / Erlang
  languages.elixir = {
    enable = true;
    package = pkgs-stable.beam28Packages.elixir_1_18;
  };

  languages.erlang = {
    enable = true;
    package = pkgs-stable.erlang_28;
  };

  # Node.js for Phoenix assets
  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_22;
  };

  # System packages for D-Bus interop testing
  packages = with pkgs; [
    dbus          # dbus-send, dbus-monitor, dbus-daemon
    systemdMinimal # busctl
    glib          # gdbus
    glib.dev      # GLib/GIO headers for C fixture compilation
    pkg-config    # for fixture compilation
    gcc           # C compiler for fixture
    socat         # unix socket debugging
    inotify-tools # Phoenix live reload
  ];

  # Environment variables
  env = {
    ERL_AFLAGS = "-kernel shell_history enabled";
    MIX_ENV = "dev";
  };

  # Process management
  processes = {
    phoenix.exec = "mix phx.server";
  };

  # Scripts
  scripts = {
    test-all.exec = "mix test";
    test-compliance.exec = "mix test --only compliance";
    test-interop.exec = "mix test --only interop";
    bus-start.exec = "mix run --no-halt";
    fmt.exec = "mix format";
    lint.exec = "mix credo --strict";

    # E2E test suite — runs 27 scenarios against a real dbus-daemon
    e2e-build.exec = "make -C apps/gao_bus_test/test/fixture";
    e2e-test.exec = ''
      # Build fixture if not present
      if [ ! -f apps/gao_bus_test/test/fixture/external_fixture ]; then
        echo "Building C fixture binary..."
        make -C apps/gao_bus_test/test/fixture
      fi
      mix test --only e2e
    '';
    e2e-gate.exec = ''
      if [ ! -f apps/gao_bus_test/test/fixture/external_fixture ]; then
        make -C apps/gao_bus_test/test/fixture
      fi
      mix test --only e2e --only gate:release
    '';
    e2e-group.exec = ''
      if [ -z "$1" ]; then
        echo "Usage: e2e-group <group>"
        echo "Groups: methods, signals, introspection, properties, bus_semantics, errors, concurrency"
        exit 1
      fi
      if [ ! -f apps/gao_bus_test/test/fixture/external_fixture ]; then
        make -C apps/gao_bus_test/test/fixture
      fi
      mix test --only e2e --only "group:$1"
    '';
  };

  enterShell = ''
    echo "🚌 gao_bus development environment"
    echo "  mix test       — run all tests"
    echo "  bus-start      — start the bus daemon"
    echo "  mix phx.server — start web monitor"
    echo ""
    echo "  E2E test suite (27 scenarios against real dbus-daemon):"
    echo "  e2e-build      — compile C fixture binary"
    echo "  e2e-test       — run full E2E suite"
    echo "  e2e-gate       — run release-gate E2E tests only"
    echo "  e2e-group NAME — run one group (methods|signals|introspection|"
    echo "                   properties|bus_semantics|errors|concurrency)"
    echo ""
    mix deps.get --quiet 2>/dev/null || true
  '';
}
