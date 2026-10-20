defmodule GaoBus.Activation.Helper do
  @moduledoc """
  Pure command planning for the already-configured traditional launch helper.
  The caller supplies a trusted absolute helper path and an authorized service
  name; this module neither probes executable ownership nor invokes a Port.

  Reference: dbus1.14.10 archive
  `/nix/store/3b2k3qfri9kiq7lvjyvg9n2vbdl7ickc-dbus-1.14.10.tar.xz`, SHA256
  `ba1f21d2bd9d339da2d4aa8780c09df32fea87998b73da24f49ab9df1e36a50f`.
  `bus/activation-helper-bin.c:75–101` accepts exactly one name argument;
  `bus/activation-exit-codes.h` and `bus/activation.c:1409–1458` define exit
  mappings. Exit0 continues waiting for name acquisition (`activation.c:1472`).

  The plan removes manager and D-Bus activation/address overrides. The production
  helper independently clears its environment, selects its fixed system config
  and checks the real daemon UID/effective root identity before service lookup.
  The plan does not prove environment or FD isolation across actual exec; that
  requires the monitored worker and canonical-address disposable-VM evidence.
  No caller-selected UID, Exec, argv, configuration or environment is accepted.
  """

  @error_prefix "org.freedesktop.DBus.Error."
  @removed_environment ~w(NOTIFY_SOCKET LISTEN_PID LISTEN_FDS LISTEN_FDNAMES
    DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE DBUS_SESSION_BUS_ADDRESS
    DBUS_SYSTEM_BUS_ADDRESS DBUS_ACTIVATION_ADDRESS DBUS_ACTIVATION_BUS_TYPE
    TEST_LAUNCH_HELPER_CONFIG)
  @exit_errors %{
    2 => {"NoMemory", "Launcher could not run (out of memory)"},
    3 => {"Spawn.ConfigInvalid", "Invalid configuration (missing or empty <user>?)"},
    4 => {"Spawn.FailedToSetup", "Failed to setup environment correctly"},
    5 => {"Spawn.ServiceNotValid", "Bus name is not valid or missing"},
    6 => {"Spawn.ServiceNotFound", "Bus name not found in system service directory"},
    7 => {"Spawn.PermissionsInvalid", "The permission of the setuid helper is not correct"},
    8 =>
      {"Spawn.PermissionsInvalid",
       "The service file is incorrect or does not have all required attributes"},
    9 => {"Spawn.ExecFailed", "Cannot launch daemon, file not found or permissions invalid"},
    10 => {"InvalidArgs", "Invalid arguments to command line"},
    11 => {"Spawn.ChildSignaled", "Launched child was signaled, it probably crashed"}
  }

  def command(path, name) do
    cond do
      not valid_path?(path) ->
        {:error, :invalid_helper_path}

      not valid_name?(name) ->
        {:error, :invalid_name}

      true ->
        environment = Enum.map(@removed_environment, &{String.to_charlist(&1), false})

        {:ok,
         %{
           command: {:spawn_executable, String.to_charlist(path)},
           options: [
             :binary,
             :exit_status,
             {:args, [String.to_charlist(name)]},
             {:env, environment}
           ]
         }}
    end
  end

  def status(0), do: :waiting

  def status(code) when is_integer(code) and code > 0 and code <= 255 do
    {suffix, text} =
      Map.get(@exit_errors, code, {
        "Spawn.ChildExited",
        "Launch helper exited with unknown return code #{code}"
      })

    {:error, %{error_name: @error_prefix <> suffix, error_text: text}}
  end

  def status(_code), do: {:error, :invalid_status}

  defp valid_path?(path) when is_binary(path) do
    byte_size(path) <= 4096 and String.valid?(path) and
      :binary.match(path, <<0>>) == :nomatch and Path.type(path) == :absolute
  end

  defp valid_path?(_path), do: false

  defp valid_name?(name) when is_binary(name) do
    byte_size(name) <= 255 and GaoBus.NameRegistry.requestable_name?(name)
  end

  defp valid_name?(_name), do: false
end
