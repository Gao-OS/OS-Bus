defmodule GaoBus.Activation.HelperTest do
  use ExUnit.Case, async: true

  @helper "/nix/store/trusted-dbus/libexec/dbus-daemon-launch-helper"
  @name "org.example.Activated"
  @prefix "org.freedesktop.DBus.Error."

  defp command(path, name), do: apply(GaoBus.Activation.Helper, :command, [path, name])
  defp status(code), do: apply(GaoBus.Activation.Helper, :status, [code])

  test "command builds spawn_executable with exactly one name argument and no shell" do
    assert {:ok, %{command: {:spawn_executable, helper}, options: options} = plan} =
             command(@helper, @name)

    assert helper == String.to_charlist(@helper)
    assert Enum.sort(Map.keys(plan)) == [:command, :options]
    assert [:binary, :exit_status, {:args, [name]}, {:env, _environment}] = options
    assert name == String.to_charlist(@name)
  end

  test "command removes manager and D-Bus activation address overrides without setting replacements" do
    assert {:ok, %{options: options}} = command(@helper, @name)
    assert [:binary, :exit_status, {:args, [_name]}, {:env, environment}] = options
    expected = ~w(NOTIFY_SOCKET LISTEN_PID LISTEN_FDS LISTEN_FDNAMES DBUS_STARTER_ADDRESS
      DBUS_STARTER_BUS_TYPE DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS
      DBUS_ACTIVATION_ADDRESS DBUS_ACTIVATION_BUS_TYPE TEST_LAUNCH_HELPER_CONFIG)

    assert Enum.sort(environment) ==
             Enum.sort(Enum.map(expected, &{String.to_charlist(&1), false}))
  end

  test "absolute configured helper paths are preserved literally rather than shell parsed" do
    path = "/configured/helper with spaces;literal"
    assert {:ok, %{command: {:spawn_executable, helper}}} = command(path, @name)
    assert helper == String.to_charlist(path)
    path = "/" <> String.duplicate("a", 4095)
    assert {:ok, %{command: {:spawn_executable, helper}}} = command(path, @name)
    assert helper == String.to_charlist(path)
  end

  test "command rejects absent relative malformed and oversized helper paths" do
    for path <- [
          nil,
          :helper,
          "",
          "dbus-daemon-launch-helper",
          "./helper",
          "../helper",
          "relative/helper",
          "/helper\0",
          <<47, 255>>,
          "/" <> String.duplicate("a", 4096)
        ] do
      assert {:error, :invalid_helper_path} = command(path, @name)
    end
  end

  test "command requires a bounded validated well-known destination rather than arbitrary arguments" do
    for name <- [
          nil,
          :service,
          "",
          ":1.5",
          "org.freedesktop.DBus",
          "NoDot",
          "org.1Invalid",
          "org.example;id",
          "org.example --uid=0",
          "org.example\0",
          <<255>>,
          "org." <> String.duplicate("a", 252)
        ] do
      assert {:error, :invalid_name} = command(@helper, name)
    end

    for name <- ["org.example-name.Activated", "org." <> String.duplicate("a", 251)] do
      assert {:ok, %{options: [:binary, :exit_status, {:args, [argument]}, {:env, _}]}} =
               command(@helper, name)

      assert argument == String.to_charlist(name)
    end
  end

  test "status zero waits for authorized name acquisition instead of declaring readiness" do
    assert :waiting = status(0)
  end

  test "known helper exit codes preserve pinned dbus1.14 error names and exact texts" do
    # ADR-006's pinned archive: bus/activation-exit-codes.h and activation.c1409–1458.
    cases = [
      {1, "Spawn.ChildExited", "Launch helper exited with unknown return code 1"},
      {2, "NoMemory", "Launcher could not run (out of memory)"},
      {3, "Spawn.ConfigInvalid", "Invalid configuration (missing or empty <user>?)"},
      {4, "Spawn.FailedToSetup", "Failed to setup environment correctly"},
      {5, "Spawn.ServiceNotValid", "Bus name is not valid or missing"},
      {6, "Spawn.ServiceNotFound", "Bus name not found in system service directory"},
      {7, "Spawn.PermissionsInvalid", "The permission of the setuid helper is not correct"},
      {8, "Spawn.PermissionsInvalid",
       "The service file is incorrect or does not have all required attributes"},
      {9, "Spawn.ExecFailed", "Cannot launch daemon, file not found or permissions invalid"},
      {10, "InvalidArgs", "Invalid arguments to command line"},
      {11, "Spawn.ChildSignaled", "Launched child was signaled, it probably crashed"}
    ]

    for {code, suffix, text} <- cases do
      name = @prefix <> suffix
      assert {:error, %{error_name: ^name, error_text: ^text}} = status(code)
    end
  end

  test "unknown numeric exit statuses retain reference ChildExited correlation with bounded code text" do
    for code <- [12, 127, 255] do
      text = "Launch helper exited with unknown return code #{code}"

      assert {:error,
              %{error_name: "org.freedesktop.DBus.Error.Spawn.ChildExited", error_text: ^text}} =
               status(code)
    end
  end

  test "non-exit values cannot become unbounded diagnostics or claimed helper outcomes" do
    for invalid <- [nil, :eacces, -1, 256, 1.5, "0", String.duplicate("x", 4097)] do
      assert {:error, :invalid_status} = status(invalid)
    end
  end
end
