defmodule GaoBus.BusMethod do
  @moduledoc "Pure validation of calls to the bus object before authority effects."

  @bus "org.freedesktop.DBus"
  @schemas %{
    {@bus, "Hello"} => {"", []},
    {@bus, "RequestName"} => {"su", [:well_known_name, :uint32]},
    {@bus, "ReleaseName"} => {"s", [:well_known_name]},
    {@bus, "GetNameOwner"} => {"s", [:string]},
    {@bus, "ListQueuedOwners"} => {"s", [:string]},
    {@bus, "NameHasOwner"} => {"s", [:string]},
    {@bus, "ListNames"} => {"", []},
    {@bus, "ListActivatableNames"} => {"", []},
    {@bus, "GetId"} => {"", []},
    {@bus, "GetConnectionUnixUser"} => {"s", [:bus_name]},
    {@bus, "GetConnectionUnixProcessID"} => {"s", [:bus_name]},
    {@bus, "GetConnectionCredentials"} => {"s", [:bus_name]},
    {@bus, "AddMatch"} => {"s", [:string]},
    {@bus, "RemoveMatch"} => {"s", [:string]},
    {@bus, "ReloadConfig"} => {"", []},
    {@bus, "StartServiceByName"} => {"su", [:string, :uint32]},
    {@bus, "UpdateActivationEnvironment"} => {"a{ss}", [:string_dictionary]},
    {"org.freedesktop.DBus.Monitoring", "BecomeMonitor"} => {"asu", [:strings, :uint32]},
    {"org.freedesktop.DBus.Introspectable", "Introspect"} => {"", []},
    {"org.freedesktop.DBus.Peer", "Ping"} => {"", []},
    {"org.freedesktop.DBus.Peer", "GetMachineId"} => {"", []},
    {"org.freedesktop.DBus.Properties", "Get"} => {"ss", [:string, :string]},
    {"org.freedesktop.DBus.Properties", "Set"} => {"ssv", [:string, :string, :variant]},
    {"org.freedesktop.DBus.Properties", "GetAll"} => {"s", [:string]}
  }

  def validate(%ExDBus.Message{} = message) do
    with {:ok, resolved} <- resolve(message) do
      validate_arguments(resolved)
    end
  end

  # Resolve interface/member before privileged control authorization. The driver
  # checks UpdateActivationEnvironment privilege before its path and arguments.
  def resolve(%ExDBus.Message{} = message) do
    interface = message.interface || infer_interface(message.member)

    cond do
      not ExDBus.Wire.Types.valid?(:object_path, message.path) ->
        {:error, "UnknownObject", "Unknown bus object"}

      not applicable_interface?(message.path, interface) ->
        name = if message.interface, do: "UnknownInterface", else: "UnknownMethod"
        {:error, name, "Unknown bus interface or method"}

      not Map.has_key?(@schemas, {interface, message.member}) ->
        {:error, "UnknownMethod", "Unknown bus method"}

      true ->
        {:ok, %{message | interface: interface}}
    end
  end

  defp applicable_interface?(_path, interface)
       when interface in [
              @bus,
              "org.freedesktop.DBus.Peer",
              "org.freedesktop.DBus.Introspectable"
            ],
       do: true

  defp applicable_interface?("/org/freedesktop/DBus", interface)
       when interface in ["org.freedesktop.DBus.Properties", "org.freedesktop.DBus.Monitoring"],
       do: true

  defp applicable_interface?(_path, _interface), do: false

  def validate_arguments(%ExDBus.Message{
        interface: @bus,
        member: "UpdateActivationEnvironment",
        path: path
      })
      when path != "/org/freedesktop/DBus",
      do: {:error, "AccessDenied", "Method is only available at the canonical bus path"}

  def validate_arguments(%ExDBus.Message{} = message) do
    case @schemas[{message.interface, message.member}] do
      {signature, arguments} ->
        if (message.signature || "") == signature and arguments?(arguments, message.body) do
          {:ok, message}
        else
          {:error, "InvalidArgs", "Arguments do not match the bus method signature"}
        end

      nil ->
        {:error, "UnknownMethod", "Unknown bus method"}
    end
  end

  defp infer_interface(member) do
    Enum.find_value(@schemas, fn {{interface, name}, _schema} ->
      if name == member, do: interface
    end)
  end

  defp arguments?([], []), do: true

  defp arguments?([type | types], [value | values]),
    do: value?(type, value) and arguments?(types, values)

  defp arguments?(_types, _values), do: false

  defp value?(:string, value),
    do: is_binary(value) and String.valid?(value) and not String.contains?(value, <<0>>)

  defp value?(:well_known_name, value), do: GaoBus.NameRegistry.requestable_name?(value)

  defp value?(:bus_name, value) do
    value?(:string, value) and byte_size(value) <= 255 and
      (value == @bus or GaoBus.NameRegistry.requestable_name?(value) or
         Regex.match?(~r/\A:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\z/, value))
  end

  defp value?(:uint32, value), do: is_integer(value) and value in 0..0xFFFFFFFF

  # The wire decoder validates variant contents before this method boundary.
  defp value?(:variant, {signature, _value}) when is_binary(signature),
    do: match?({:ok, _type}, ExDBus.Wire.Types.parse_signature(signature))

  defp value?(:strings, values) when is_list(values), do: Enum.all?(values, &value?(:string, &1))

  defp value?(:string_dictionary, values) when is_list(values) do
    Enum.all?(values, fn
      {key, value} -> value?(:string, key) and value?(:string, value)
      _ -> false
    end)
  end

  defp value?(_type, _value), do: false
end
