defmodule GaoBusTest.E2E.ChildProcess do
  @moduledoc "Owns a guarded fixture process; runner death closes the guardian's lifeline."
  use GenServer

  @guard Path.expand("../../fixture/process_guard", __DIR__)
  @output_limit 1_048_576

  def guard_path, do: @guard
  def available?, do: File.exists?(@guard)

  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :temporary}

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
  def start(opts), do: GenServer.start(__MODULE__, Keyword.put_new(opts, :owner, self()))

  def await_ready(pid, predicate, timeout),
    do: GenServer.call(pid, {:ready, predicate, timeout}, timeout + 3_000)

  def await_exit(pid, timeout), do: GenServer.call(pid, {:exit, timeout}, timeout + 3_000)
  def snapshot(pid), do: GenServer.call(pid, :snapshot)

  def stop(pid) do
    GenServer.call(pid, :stop, 4_000)
  catch
    :exit, {:noproc, _} -> :ok
    :exit, {:normal, _} -> :ok
  end

  @impl true
  def init(opts) do
    command = Keyword.fetch!(opts, :command)

    with true <- available?(),
         executable when is_binary(executable) <- System.find_executable(command) do
      Process.flag(:trap_exit, true)

      port_opts = [
        :binary,
        :stderr_to_stdout,
        :exit_status,
        args: [executable | Keyword.get(opts, :args, [])]
      ]

      port_opts =
        if opts[:env],
          do:
            Keyword.put(
              port_opts,
              :env,
              Enum.map(opts[:env], fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)
            ),
          else: port_opts

      port_opts = if opts[:cwd], do: Keyword.put(port_opts, :cd, opts[:cwd]), else: port_opts
      port = Port.open({:spawn_executable, @guard}, port_opts)
      {:os_pid, guard_pid} = Port.info(port, :os_pid)
      owner = Process.monitor(Keyword.fetch!(opts, :owner))

      {:ok,
       %{
         port: port,
         guard_pid: guard_pid,
         owner: owner,
         output: "",
         pid: nil,
         exit_status: nil,
         timed_out?: false,
         ready_waiter: nil,
         exit_waiter: nil
       }}
    else
      false -> {:stop, {:missing_process_guard, @guard}}
      nil -> {:stop, {:missing_executable, command}}
    end
  end

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, result(state), state}

  def handle_call({:ready, predicate, timeout}, from, state) do
    cond do
      state.pid && predicate.(state.output) ->
        {:reply, {:ok, result(state)}, state}

      state.exit_status != nil ->
        {:reply, {:error, {:exited, result(state)}}, state}

      true ->
        timer = Process.send_after(self(), :ready_timeout, timeout)
        {:noreply, %{state | ready_waiter: {from, predicate, timer}}}
    end
  end

  def handle_call({:exit, timeout}, from, state) do
    if state.exit_status != nil do
      {:reply, result(state), state}
    else
      timer = Process.send_after(self(), :command_timeout, timeout)
      {:noreply, %{state | exit_waiter: {from, timer}}}
    end
  end

  def handle_call(:stop, _from, state) do
    state = reap(state)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    output = state.output <> data
    {pid, output} = parse_pid(state.pid, output)
    output = binary_part(output, 0, min(byte_size(output), @output_limit))
    state = %{state | output: output, pid: pid}

    case state.ready_waiter do
      {from, predicate, timer} when not is_nil(pid) ->
        if predicate.(output) do
          Process.cancel_timer(timer)
          GenServer.reply(from, {:ok, result(state)})
          {:noreply, %{state | ready_waiter: nil}}
        else
          {:noreply, state}
        end

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    state = %{state | exit_status: status}

    if state.exit_waiter do
      {from, timer} = state.exit_waiter
      Process.cancel_timer(timer)
      GenServer.reply(from, result(state))
    end

    if state.ready_waiter do
      {from, _predicate, timer} = state.ready_waiter
      Process.cancel_timer(timer)
      GenServer.reply(from, {:error, {:exited, result(state)}})
    end

    {:noreply, %{state | exit_waiter: nil, ready_waiter: nil}}
  end

  def handle_info(:ready_timeout, %{ready_waiter: {from, _predicate, _timer}} = state) do
    GenServer.reply(from, {:error, {:ready_timeout, result(state)}})
    {:noreply, %{state | ready_waiter: nil}}
  end

  def handle_info(:ready_timeout, state), do: {:noreply, state}

  def handle_info(:command_timeout, %{exit_waiter: nil} = state), do: {:noreply, state}

  def handle_info(:command_timeout, state) do
    signal_guard(state)
    {:noreply, %{state | timed_out?: true}}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{owner: ref} = state),
    do: {:stop, :normal, state}

  def handle_info({:EXIT, port, :normal}, %{port: port} = state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    reap(state)
    :ok
  end

  defp reap(%{exit_status: status} = state) when not is_nil(status), do: state

  defp reap(state) do
    signal_guard(state)
    await_reaped(state, System.monotonic_time(:millisecond) + 2_000)
  end

  defp await_reaped(state, deadline) do
    port = state.port
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} -> await_reaped(%{state | output: state.output <> data}, deadline)
      {^port, {:exit_status, status}} -> %{state | exit_status: status}
      {:EXIT, ^port, :normal} -> await_reaped(state, deadline)
    after
      remaining ->
        raise "process guardian did not confirm reaping owned PID #{inspect(state.pid)}"
    end
  end

  defp signal_guard(%{port: port}) do
    Port.command(port, "stop\n")
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp result(state), do: Map.take(state, [:pid, :guard_pid, :output, :exit_status, :timed_out?])

  defp parse_pid(nil, output) do
    case Regex.run(~r/^E2E_CHILD_PID (\d+)\n/, output) do
      [header, pid] ->
        {String.to_integer(pid),
         binary_part(output, byte_size(header), byte_size(output) - byte_size(header))}

      nil ->
        {nil, output}
    end
  end

  defp parse_pid(pid, output), do: {pid, output}
end
