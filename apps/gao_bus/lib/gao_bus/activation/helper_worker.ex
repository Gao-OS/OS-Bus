defmodule GaoBus.Activation.HelperWorker do
  @moduledoc """
  One temporary observer for the fixed, packaged traditional-helper bridge.

  Initialization is effect-free. The owning coordinator must reserve the launch
  credit and register/monitor this worker before calling `launch/2`. Only that
  owner may launch its immutable token. The worker reports one correlated fact
  and exits normally; it neither owns State credits nor calls Router.

  A normal bridge lifecycle and its complete GHB v1 record are both required to
  prove a child result. Any lost observation is conservative: closing a Port is
  not proof that a helper or daemonized service terminated. Production activation
  remains gated on the packaged cgroup shutdown and installed-helper checks.
  """

  use GenServer, restart: :temporary
  alias GaoBus.Activation.HelperBinding

  @settlement_ms 1_000
  @stages %{
    1 => :argument,
    2 => :binding,
    3 => :hardening,
    4 => :stdio,
    5 => :close_fds,
    6 => :error_pipe,
    7 => :fork,
    8 => :signals,
    9 => :exec,
    10 => :wait,
    11 => :error_read
  }

  def start_link(options) do
    case worker_options(options) do
      {:ok, identity} -> GenServer.start_link(__MODULE__, identity)
      :error -> {:error, :invalid_worker_options}
    end
  end

  def launch(worker, token), do: GenServer.call(worker, {:launch, token})

  @impl true
  def init(%{owner: owner, epoch: epoch, attempt: attempt, token: token, name: name} = identity) do
    Process.flag(:trap_exit, true)

    {:ok,
     %{
       owner: owner,
       owner_monitor: Process.monitor(owner),
       epoch: epoch,
       attempt: attempt,
       token: token,
       name: name,
       binding: identity.binding,
       phase: :reserved,
       port: nil,
       port_monitor: nil,
       bytes: <<>>,
       exit_status: nil,
       link_exit: nil,
       port_down: nil,
       settlement: nil
     }}
  end

  defp worker_options(options) do
    with true <- is_list(options) and Keyword.keyword?(options),
         true <- length(options) in [5, 6],
         true <- length(options) == map_size(Map.new(options)),
         true <-
           Keyword.keys(options) -- [:owner, :epoch, :attempt, :token, :name, :binding] == [],
         %{owner: owner, epoch: epoch, attempt: attempt, token: token, name: name} <-
           Map.new(options),
         true <-
           is_pid(owner) and not is_nil(epoch) and not is_nil(attempt) and not is_nil(token),
         true <- GaoBus.NameRegistry.requestable_name?(name),
         binding = Keyword.get(options, :binding),
         true <- is_nil(binding) or is_struct(binding, HelperBinding) do
      {:ok,
       %{owner: owner, epoch: epoch, attempt: attempt, token: token, name: name, binding: binding}}
    else
      _ -> :error
    end
  end

  @impl true
  def handle_call({:launch, _token}, {caller, _}, %{owner: owner} = state)
      when caller != owner,
      do: {:reply, {:error, :not_owner}, state}

  def handle_call({:launch, token}, _from, %{token: expected} = state)
      when token != expected,
      do: {:reply, {:error, :invalid_token}, state}

  def handle_call({:launch, _token}, _from, %{phase: :reserved} = state) do
    {:reply, :ok, %{state | phase: :launching}, {:continue, :open_bridge}}
  end

  def handle_call({:launch, _token}, _from, state),
    do: {:reply, {:error, :already_launched}, state}

  @impl true
  def handle_continue(:open_bridge, state) do
    # This bounded installation/configuration reread occurs off Router and after
    # the coordinator has reserved/monitored the worker. No Port exists on refusal.
    case HelperBinding.revalidate(state.binding) do
      :ok ->
        launch_bridge(state)

      {:error, _reason} ->
        report(state, {:error, :backend_unavailable})
        {:stop, :normal, state}
    end
  end

  defp launch_bridge(state) do
    case open_bridge(state.name) do
      {:ok, port} ->
        {:noreply,
         %{state | phase: :observing, port: port, port_monitor: :erlang.monitor(:port, port)}}

      {:error, reason} ->
        report(state, {:error, {:observation_lost, reason}})
        {:stop, :normal, state}
    end
  end

  @impl true
  def handle_info({port, {:data, bytes}}, %{port: port} = state) when is_binary(bytes) do
    if byte_size(state.bytes) + byte_size(bytes) <= 16 do
      settle(%{state | bytes: state.bytes <> bytes})
    else
      lost(state, :extra_record_bytes)
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port, exit_status: nil} = state),
    do: settle(%{state | exit_status: status})

  def handle_info({:EXIT, port, reason}, %{port: port, link_exit: nil} = state),
    do: settle(%{state | link_exit: reason})

  def handle_info(
        {:DOWN, monitor, :port, port, reason},
        %{port_monitor: monitor, port: port, port_down: nil} = state
      ),
      do: settle(%{state | port_down: reason})

  def handle_info(
        {:DOWN, monitor, :process, owner, _reason},
        %{owner_monitor: monitor, owner: owner} = state
      ),
      do: {:stop, :normal, state}

  def handle_info({:settle, token}, %{settlement: {_timer, token}} = state),
    do: lost(state, :incomplete_observation)

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.settlement, do: Process.cancel_timer(elem(state.settlement, 0))

    if state.port do
      try do
        Port.close(state.port)
      catch
        :error, :badarg -> :ok
      end
    end

    :ok
  end

  defp open_bridge(name) do
    try do
      bridge = HelperBinding.bridge_path()

      environment =
        System.get_env()
        |> Map.keys()
        |> Enum.map(&{String.to_charlist(&1), false})

      port =
        Port.open({:spawn_executable, String.to_charlist(bridge)}, [
          :binary,
          :exit_status,
          :use_stdio,
          {:args, [String.to_charlist(name)]},
          {:env, environment}
        ])

      {:ok, port}
    rescue
      ArgumentError -> {:error, :port_open_failed}
    catch
      :error, _reason -> {:error, :port_open_failed}
    end
  end

  defp settle(%{exit_status: status} = state) when not is_nil(status) and status != 0,
    do: lost(state, :bridge_exit)

  defp settle(%{link_exit: reason} = state) when not is_nil(reason) and reason != :normal,
    do: lost(state, :port_exit)

  defp settle(%{port_down: reason} = state)
       when not is_nil(reason) and reason not in [:normal, :noproc],
       do: lost(state, :port_down)

  defp settle(%{exit_status: 0, link_exit: :normal, port_down: down} = state)
       when down in [:normal, :noproc] do
    report(state, decode(state.bytes))
    {:stop, :normal, state}
  end

  defp settle(state) do
    if is_nil(state.settlement) and
         (state.exit_status != nil or state.link_exit != nil or state.port_down != nil) do
      token = make_ref()
      timer = Process.send_after(self(), {:settle, token}, @settlement_ms)
      {:noreply, %{state | settlement: {timer, token}}}
    else
      {:noreply, state}
    end
  end

  defp decode(<<"GHB", 1, 3, 0, 0::16, value::32, 0::32>>) when value <= 255,
    do: {:exited, value}

  defp decode(<<"GHB", 1, 4, 0, 0::16, value::32, 0::32>>) when value in 1..64,
    do: {:signaled, value}

  defp decode(<<"GHB", 1, 1, stage, 0::16, value::32, 0::32>>)
       when stage in 1..8 and value > 0,
       do: {:error, {:not_started, Map.fetch!(@stages, stage), value}}

  defp decode(<<"GHB", 1, 2, stage, 0::16, value::32, 0::32>>)
       when stage in [4, 5, 8, 9] and value > 0,
       do: {:error, {:exec_failed, Map.fetch!(@stages, stage), value}}

  defp decode(<<"GHB", 1, 5, stage, 0::16, value::32, 0::32>>)
       when stage in [10, 11] and value > 0,
       do: {:error, {:observation_lost, :bridge_observation_failed}}

  defp decode(_bytes), do: {:error, {:observation_lost, :invalid_record}}

  defp lost(state, reason) do
    report(state, {:error, {:observation_lost, reason}})
    {:stop, :normal, state}
  end

  defp report(state, result),
    do:
      send(state.owner, {:helper_result, self(), state.epoch, state.attempt, state.token, result})
end
