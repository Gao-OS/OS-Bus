defmodule GaoBus.PeerSupervisor do
  @moduledoc """
  DynamicSupervisor for connected D-Bus peers.

  Each accepted connection gets a supervised `GaoBus.Peer` process.
  """

  use DynamicSupervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    limit = Keyword.get(opts, :max_children, Application.get_env(:gao_bus, :max_connections, 256))

    if is_integer(limit) and limit > 0 do
      DynamicSupervisor.init(strategy: :one_for_one, max_children: limit)
    else
      {:stop, :invalid_connection_limit}
    end
  end

  @doc """
  Start a new Peer process under this supervisor.
  """
  @spec start_peer(:socket.socket(), keyword()) :: DynamicSupervisor.on_start_child()
  def start_peer(socket, peer_options \\ []) do
    DynamicSupervisor.start_child(
      __MODULE__,
      {GaoBus.Peer, Keyword.put(peer_options, :socket, socket)}
    )
  end
end
