defmodule GaoBus.Ids do
  @moduledoc """
  Unique identifiers for one coherent bus epoch.

  Generates a 32-hex-char GUID for auth and a bus instance ID,
  cached in persistent_term so they stay constant until the core restarts.
  The bus instance ID is independent of the host's machine identity.
  """

  use GenServer

  @guid_key :gao_bus_auth_guid
  @bus_id_key :gao_bus_instance_id
  @machine_id_key :gao_bus_machine_id

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    :persistent_term.put(@guid_key, generate_hex(16))
    :persistent_term.put(@bus_id_key, generate_hex(16))
    paths = Keyword.get(opts, :machine_id_paths, ["/etc/machine-id", "/var/lib/dbus/machine-id"])
    :persistent_term.put(@machine_id_key, read_machine_id(paths))
    {:ok, nil}
  end

  @impl true
  def terminate(_reason, _state) do
    :persistent_term.erase(@guid_key)
    :persistent_term.erase(@bus_id_key)
    :persistent_term.erase(@machine_id_key)
    :ok
  end

  @doc "Returns the server GUID (32 lowercase hex chars), stable within an epoch."
  @spec auth_guid() :: String.t()
  def auth_guid do
    case :persistent_term.get(@guid_key, nil) do
      nil ->
        guid = generate_hex(16)
        :persistent_term.put(@guid_key, guid)
        guid

      guid ->
        guid
    end
  end

  @doc """
  Returns the bus instance ID (32 lowercase hex chars), stable within an epoch.
  """
  @spec bus_id() :: String.t()
  def bus_id do
    case :persistent_term.get(@bus_id_key, nil) do
      nil ->
        id = generate_hex(16)
        :persistent_term.put(@bus_id_key, id)
        id

      id ->
        id
    end
  end

  @doc "Returns the trusted machine identity captured at epoch start, or an explicit error."
  @spec machine_id() :: {:ok, String.t()} | {:error, :machine_id_unavailable}
  def machine_id,
    do: :persistent_term.get(@machine_id_key, {:error, :machine_id_unavailable})

  defp read_machine_id(paths) do
    Enum.find_value(paths, {:error, :machine_id_unavailable}, fn path ->
      case File.read(path) do
        {:ok, content} ->
          id = String.trim(content)

          if Regex.match?(~r/\A[0-9a-f]{32}\z/, id) and id != String.duplicate("0", 32),
            do: {:ok, id}

        {:error, _reason} ->
          nil
      end
    end)
  end

  defp generate_hex(bytes) do
    bytes
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end
end
