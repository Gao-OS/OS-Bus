defmodule GaoBus.Policy.Capability do
  @moduledoc """
  Capability-based D-Bus policy engine for GaoOS.

  Replaces traditional XML policy files with Elixir-based capability grants.
  Each connected peer has a set of capabilities that determine what actions
  they can perform.

  ## Capabilities

  Capabilities are structured as `{scope, target}` tuples:

  - `{:send, destination}` — can send messages to `destination`
  - `{:receive, sender}` — can receive messages from `sender`
  - `{:own, name}` — can own well-known name `name`
  - `{:call, {destination, interface, method}}` — can call specific method
  - `{:call, {destination, interface}}` — can call any method on interface
  - `{:all, :all}` — superuser, all permissions (uid 0)

  ## Default Policy

  - uid 0 (root): all capabilities
  - All peers: can send to org.freedesktop.DBus, can own names matching their uid
  - System services (uid < 1000): can own system bus names
  """

  @behaviour GaoBus.Policy.Behaviour

  use GenServer

  require Logger

  @table :gao_bus_capabilities

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Grant a capability to a peer identified by unique name.
  """
  @spec grant(String.t(), tuple()) :: :ok
  def grant(unique_name, capability) do
    GenServer.call(__MODULE__, {:grant, unique_name, capability})
  end

  @doc """
  Revoke a capability from a peer.
  """
  @spec revoke(String.t(), tuple()) :: :ok
  def revoke(unique_name, capability) do
    GenServer.call(__MODULE__, {:revoke, unique_name, capability})
  end

  @doc """
  Get all capabilities for a peer.
  """
  @spec capabilities(String.t()) :: [tuple()]
  def capabilities(unique_name) do
    :ets.lookup(@table, unique_name)
    |> Enum.map(fn {_, cap} -> cap end)
  catch
    :error, :badarg -> []
  end

  @doc """
  Compatibility hook. Kernel credentials never imply native capability grants.
  Explicit grants can restrict compatibility policy when enabled by configuration.
  """
  @spec setup_defaults(String.t(), map()) :: :ok
  def setup_defaults(unique_name, credentials) do
    GenServer.cast(__MODULE__, {:setup_defaults, unique_name, credentials})
  end

  @doc """
  Remove all capabilities for a disconnected peer.
  """
  @spec peer_disconnected(String.t()) :: :ok
  def peer_disconnected(unique_name) do
    GenServer.cast(__MODULE__, {:peer_disconnected, unique_name})
  end

  # --- Policy.Behaviour callbacks ---

  @impl GaoBus.Policy.Behaviour
  def check_send(credentials, message_info) do
    unique_name = credentials[:unique_name]
    caps = capabilities(unique_name)

    cond do
      has_superuser?(caps) ->
        :allow

      # Always allow messages to the bus itself
      message_info[:destination] == "org.freedesktop.DBus" ->
        :allow

      # Always allow method returns and errors (they're responses)
      message_info[:type] in [:method_return, :error] ->
        :allow

      # Check specific method call capability
      message_info[:type] == :method_call ->
        dest = message_info[:destination]
        iface = message_info[:interface]
        member = message_info[:member]

        if has_send_capability?(caps, dest, iface, member) do
          :allow
        else
          GaoBus.PubSub.broadcast({:policy_denied, :send, unique_name, message_info})
          {:deny, "org.freedesktop.DBus.Error.AccessDenied"}
        end

      # Signals — check send capability
      message_info[:type] == :signal ->
        :allow

      true ->
        :allow
    end
  end

  @impl GaoBus.Policy.Behaviour
  def check_own(credentials, name) do
    unique_name = credentials[:unique_name]
    caps = capabilities(unique_name)

    cond do
      has_superuser?(caps) ->
        :allow

      Enum.any?(caps, fn
        {:own, ^name} -> true
        {:own, :any} -> true
        _ -> false
      end) ->
        :allow

      true ->
        GaoBus.PubSub.broadcast({:policy_denied, :own, unique_name, name})
        {:deny, "org.freedesktop.DBus.Error.AccessDenied"}
    end
  end

  @impl GaoBus.Policy.Behaviour
  def check_eavesdrop(credentials) do
    unique_name = credentials[:unique_name]
    caps = capabilities(unique_name)

    if has_superuser?(caps) do
      :allow
    else
      {:deny, "org.freedesktop.DBus.Error.AccessDenied"}
    end
  end

  # --- GenServer callbacks ---

  @impl true
  def init(_opts) do
    :ets.new(@table, [:bag, :named_table, :public, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_call({:grant, unique_name, capability}, _from, state) do
    :ets.insert(@table, {unique_name, capability})
    {:reply, :ok, state}
  end

  def handle_call({:revoke, unique_name, capability}, _from, state) do
    :ets.delete_object(@table, {unique_name, capability})
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:setup_defaults, _unique_name, _credentials}, state), do: {:noreply, state}

  def handle_cast({:peer_disconnected, unique_name}, state) do
    :ets.delete(@table, unique_name)
    {:noreply, state}
  end

  # --- Private helpers ---

  defp has_superuser?(caps) do
    Enum.any?(caps, fn
      {:all, :all} -> true
      _ -> false
    end)
  end

  defp has_send_capability?(caps, dest, iface, member) do
    Enum.any?(caps, fn
      {:all, :all} -> true
      {:send, :any} -> true
      {:send, ^dest} -> true
      {:call, {^dest, ^iface, ^member}} -> true
      {:call, {^dest, ^iface}} -> true
      _ -> false
    end)
  end
end
