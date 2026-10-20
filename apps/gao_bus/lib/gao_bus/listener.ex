defmodule GaoBus.Listener do
  @moduledoc """
  Owns a private filesystem listener or adopts a trusted manager listener.
  Existing endpoints are never unlinked;
  clean shutdown removes only the exact socket inode created by this instance.
  Each turn accepts at most one connection and transfers sole socket ownership.
  """
  use GenServer
  alias GaoBus.Unix.{InheritedListener, SocketPath}
  require Logger

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc false
  def transfer_ownership(socket, peer) do
    case :socket.setopt(socket, {:otp, :controlling_process}, peer) do
      :ok ->
        send(peer, :socket_ready)
        :ok

      {:error, _reason} = error ->
        :socket.close(socket)
        DynamicSupervisor.terminate_child(GaoBus.PeerSupervisor, peer)
        error
    end
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    path = Keyword.fetch!(opts, :socket_path)
    mode = Keyword.get(opts, :socket_mode, socket_mode())

    result =
      if Keyword.get(opts, :inherited, false) do
        case InheritedListener.adopt(path) do
          {:ok, socket} -> {:ok, socket, :inherited}
          error -> error
        end
      else
        open_owned(path, mode)
      end

    case result do
      {:ok, socket, identity} ->
        send(self(), :accept)

        {:ok,
         %{
           listen_socket: socket,
           socket_path: path,
           identity: identity,
           accept_ref: nil,
           peer_options: Keyword.get(opts, :peer_options, []),
           pending_peer: nil
         }}

      {:error, reason} ->
        {:stop, {:listen_failed, reason, path}}
    end
  end

  @impl true
  def handle_info(:accept, %{pending_peer: nil, accept_ref: nil} = state), do: accept(state)

  def handle_info(:incomplete_capacity, %{pending_peer: nil, accept_ref: nil} = state),
    do: accept(state)

  def handle_info({:peer_admitted, peer}, %{pending_peer: {peer, monitor}} = state) do
    Process.demonitor(monitor, [:flush])
    send(self(), :accept)
    {:noreply, %{state | pending_peer: nil}}
  end

  def handle_info(
        {:DOWN, monitor, :process, peer, _reason},
        %{pending_peer: {peer, monitor}} = state
      ) do
    send(self(), :accept)
    {:noreply, %{state | pending_peer: nil}}
  end

  def handle_info(
        {:"$socket", socket, :select, reference},
        %{listen_socket: socket, accept_ref: reference} = state
      ),
      do: accept(%{state | accept_ref: nil})

  def handle_info(
        {:"$socket", socket, :abort, {reference, reason}},
        %{listen_socket: socket, accept_ref: reference} = state
      ),
      do: {:stop, {:accept_failed, reason}, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.peer_options[:xml_limits], do: GaoBus.Limits.unsubscribe_accept(self())
    :socket.close(state.listen_socket)

    cleanup =
      if state.identity == :inherited,
        do: :ok,
        else: SocketPath.remove(state.socket_path, state.identity)

    case cleanup do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("GaoBus.Listener: socket cleanup refused: #{inspect(reason)}")
    end
  end

  defp open_owned(path, mode) do
    with :ok <- SocketPath.prepare(path),
         {:ok, socket} <- :socket.open(:local, :stream, :default) do
      case bind(socket, path, mode) do
        {:ok, identity} ->
          {:ok, socket, identity}

        {:error, _reason} = error ->
          :socket.close(socket)
          error
      end
    end
  end

  defp bind(socket, path, mode) do
    with :ok <- :socket.bind(socket, %{family: :local, path: path}),
         {:ok, identity} <- SocketPath.capture(path) do
      with :ok <- File.chmod(path, mode),
           :ok <- :socket.listen(socket) do
        {:ok, identity}
      else
        {:error, _reason} = error ->
          SocketPath.remove(path, identity)
          error
      end
    end
  end

  defp accept(state) do
    readiness =
      if state.peer_options[:xml_limits], do: GaoBus.Limits.accept_ready(self()), else: :ok

    case readiness do
      :ok -> accept_socket(state)
      {:error, {:xml_limit_exceeded, "max_incomplete_connections"}} -> {:noreply, state}
      {:error, reason} -> {:stop, {:admission_unavailable, reason}, state}
    end
  end

  defp accept_socket(state) do
    case :socket.accept(state.listen_socket, :nowait) do
      {:ok, client} ->
        options =
          state.peer_options
          |> Keyword.put(:accepted_at, System.monotonic_time(:millisecond))
          |> Keyword.put(:admission_observer, self())

        case hand_off(client, options) do
          {:ok, peer} ->
            {:noreply, %{state | pending_peer: {peer, Process.monitor(peer)}}}

          {:error, _reason} ->
            send(self(), :accept)
            {:noreply, state}
        end

      {:select, {:select_info, _operation, reference}} ->
        {:noreply, %{state | accept_ref: reference}}

      {:error, reason} ->
        {:stop, {:accept_failed, reason}, state}
    end
  end

  defp hand_off(socket, peer_options) do
    case GaoBus.PeerSupervisor.start_peer(socket, peer_options) do
      {:ok, peer} ->
        case transfer_ownership(socket, peer) do
          :ok -> {:ok, peer}
          error -> error
        end

      {:error, _reason} = error ->
        :socket.close(socket)
        error
    end
  end

  defp socket_mode do
    case Application.get_env(:gao_bus, :profile, :system) do
      :session -> 0o600
      :system -> 0o666
    end
  end
end
