defmodule GaoBus.Activation do
  @moduledoc """
  Supervised ownership of admitted activation bodies, deadlines and ordered
  effects. Router alone commits launch and delivery decisions. This coordinator
  does not establish backend readiness or enable activation configuration.
  """

  use GenServer

  alias GaoBus.Activation.State
  alias GaoBus.Activation.HelperWorker
  alias GaoBus.Limits

  @drain 16
  @waiter_fields ~w(caller caller_incarnation request serial kind message_type flags destination generation definition deadline lease)a

  def start_link(opts \\ []) do
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  def epoch(server \\ __MODULE__), do: call(server, :epoch)
  def snapshot(server \\ __MODULE__), do: call(server, :snapshot)

  def admit(waiter, message, definition, server \\ __MODULE__),
    do: call(server, {:admit, waiter, message, definition})

  def view(attempt, server \\ __MODULE__), do: call(server, {:view, attempt})

  def waiter(attempt, request, server \\ __MODULE__),
    do: call(server, {:waiter, attempt, request})

  def systemd_view(unit, issuer, server \\ __MODULE__),
    do: call(server, {:systemd_view, unit, issuer})

  def commit(attempt, generation, server \\ __MODULE__),
    do: call(server, {:event, {:commit_issue, attempt, generation}})

  def commit_systemd(attempt, generation, owner, server \\ __MODULE__),
    do: call(server, {:commit_systemd, attempt, generation, owner})

  def systemd_failure(unit, reason, server \\ __MODULE__),
    do: call(server, {:systemd_failure, unit, reason})

  def defer_systemd(attempt, server \\ __MODULE__), do: call(server, {:defer_systemd, attempt})

  def finish(attempt, request, outcome, server \\ __MODULE__),
    do: call(server, {:event, {:finish_waiter, attempt, request, outcome}})

  def name_available(name, server \\ __MODULE__),
    do: call(server, {:event, {:name_available, name}})

  def name_owned(name, server \\ __MODULE__), do: call(server, {:name_owned, name})

  def caller_down(incarnation, server \\ __MODULE__),
    do: call(server, {:event, {:caller_down, incarnation}})

  def reload(generation, definitions, server \\ __MODULE__),
    do: call(server, {:event, {:reload, generation, definitions}})

  def backend_result(attempt, result, server \\ __MODULE__),
    do: call(server, {:event, {:backend_result, attempt, result}})

  def launch_helper(attempt, server \\ __MODULE__),
    do: call(server, {:launch_helper, attempt})

  def helper_result(attempt, token, server \\ __MODULE__),
    do: call(server, {:helper_result, attempt, token})

  defp call(server, message) do
    GenServer.call(server, message, 5000)
  catch
    :exit, _ -> {:error, :activation_unavailable}
  end

  @impl true
  def init(opts) do
    router = Keyword.get(opts, :router, Process.whereis(GaoBus.Router))

    if is_pid(router) and node(router) == node() and Process.alive?(router) do
      epoch = make_ref()

      {:ok,
       %{
         epoch: epoch,
         router: router,
         router_monitor: Process.monitor(router),
         limits: Keyword.get(opts, :limits, Limits),
         bookkeeping: State.new(epoch, Keyword.get(opts, :state_options, [])),
         messages: %{},
         timers: %{},
         effects: :queue.new(),
         drain: nil,
         launch_notifications: MapSet.new(),
         deferred_systemd: MapSet.new(),
         helper_supervisor:
           Keyword.get(opts, :helper_supervisor, GaoBus.Activation.HelperSupervisor),
         helper_binding: Keyword.get(opts, :helper_binding),
         helpers: %{}
       }}
    else
      {:stop, :activation_router_unavailable}
    end
  end

  @impl true
  def handle_call(:epoch, _from, state), do: {:reply, {:ok, state.epoch}, state}

  def handle_call(:snapshot, {caller, _}, %{router: caller} = state) do
    {:reply,
     {:ok,
      %{
        bookkeeping: state.bookkeeping,
        messages: map_size(state.messages),
        timers: map_size(state.timers),
        effects: :queue.len(state.effects)
      }}, state}
  end

  def handle_call({:admit, waiter, message, definition}, {caller, _}, %{router: caller} = state) do
    if Map.has_key?(state.messages, waiter.request) do
      {:reply, {:error, :duplicate_request}, state}
    else
      case Limits.reserve_terminal(state.router, terminal_bytes(state, waiter, message), state.limits) do
        {:ok, terminal_control} ->
          admit_reserved(state, waiter, message, definition, terminal_control)

        {:error, reason} ->
          release_lease(state, waiter.request, waiter.lease)
          {:reply, {:error, reason}, state}
      end
    end
  end

  def handle_call({:view, key}, {caller, _}, %{router: caller} = state) do
    case state.bookkeeping.attempts[key] do
      nil ->
        {:reply, {:error, :unknown_attempt}, state}

      attempt ->
        waiters =
          attempt.waiters
          |> Map.values()
          |> Enum.sort_by(& &1.sequence)
          |> Enum.map(fn waiter ->
            record = Map.fetch!(state.messages, waiter.request)
            %{waiter: metadata(waiter), message: launch_header(record.message, waiter.kind)}
          end)

        {:reply, {:ok, %{definition: attempt.definition, waiters: waiters}}, state}
    end
  end

  def handle_call({:waiter, key, request}, {caller, _}, %{router: caller} = state) do
    case get_in(state.bookkeeping.attempts, [key, :waiters, request]) do
      nil -> {:reply, {:error, :unknown_waiter}, state}
      waiter -> {:reply, {:ok, metadata(waiter)}, state}
    end
  end

  def handle_call({:systemd_view, unit, issuer}, {caller, _}, %{router: caller} = state) do
    case state.bookkeeping.units[{state.epoch, unit}] do
      %{issued: true, failed: false, issuer: ^issuer, attempts: attempts} ->
        waiters =
          attempts
          |> Enum.flat_map(fn key ->
            state.bookkeeping.attempts[key].waiters
            |> Map.values()
            |> Enum.map(&{key, &1})
          end)
          |> Enum.sort_by(fn {_key, waiter} -> waiter.sequence end)
          |> Enum.map(fn {key, waiter} ->
            record = Map.fetch!(state.messages, waiter.request)

            %{
              attempt: key,
              waiter: metadata(waiter),
              message: launch_header(record.message, waiter.kind)
            }
          end)

        {:reply, {:ok, waiters}, state}

      _ ->
        {:reply, {:error, :unknown_unit}, state}
    end
  end

  def handle_call(
        {:commit_systemd, key, generation, owner},
        {caller, _},
        %{router: caller} = state
      ) do
    case State.transition(state.bookkeeping, {:commit_issue, key, generation}, now_ms()) do
      {:ok, bookkeeping, result, effects} ->
        effects =
          Enum.map(effects, fn
            {:launch, attempt, definition} -> {:launch_systemd, attempt, definition, owner}
            effect -> effect
          end)

        state = %{
          state
          | bookkeeping: bookkeeping,
            launch_notifications: MapSet.delete(state.launch_notifications, key),
            deferred_systemd: MapSet.delete(state.deferred_systemd, key)
        }

        {:reply, {:ok, result}, enqueue_effects(state, effects)}

      {:error, reason, _} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:defer_systemd, key}, {caller, _}, %{router: caller} = state) do
    case state.bookkeeping.attempts[key] do
      %{issued: false, owned: false, definition: %{backend: :systemd}} ->
        {:reply, :ok,
         %{
           state
           | launch_notifications: MapSet.delete(state.launch_notifications, key),
             deferred_systemd: MapSet.put(state.deferred_systemd, key)
         }}

      _ ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:systemd_failure, unit, reason}, {caller, _}, %{router: caller} = state) do
    case state.bookkeeping.units[{state.epoch, unit}] do
      %{issued: true, attempts: attempts} ->
        key = Enum.min_by(attempts, &state.bookkeeping.attempts[&1].sequence)
        {:reply, :ok, transition(state, {:backend_result, key, {:error, reason}})}

      _ ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:name_owned, name}, {caller, _}, %{router: caller} = state) do
    key = state.bookkeeping.names[name]

    case state.bookkeeping.attempts[key] do
      %{issued: true, waiters: waiters} when map_size(waiters) == 0 ->
        {:reply, :ok, transition(state, {:backend_result, key, :owned})}

      _ ->
        # Active waiters establish ordered completion through finish/4.
        {:reply, :ok, state}
    end
  end

  def handle_call({:launch_helper, key}, {caller, _}, %{router: caller} = state) do
    case {state.bookkeeping.children[key], state.helpers[key]} do
      {%{phase: :reserved}, nil} ->
        helper = %{token: make_ref(), phase: :starting, pid: nil, monitor: nil, result: nil}
        state = %{state | helpers: Map.put(state.helpers, key, helper)}
        {:reply, :ok, state, {:continue, {:launch_helper, key}}}

      {_, helper} when not is_nil(helper) ->
        {:reply, {:error, :already_launched}, state}

      _ ->
        {:reply, {:error, :not_issued}, state}
    end
  end

  def handle_call({:helper_result, key, token}, {caller, _}, %{router: caller} = state) do
    case state.helpers[key] do
      %{phase: :ready, token: ^token, result: result} ->
        state = %{state | helpers: Map.delete(state.helpers, key)}
        {:reply, :ok, transition(state, {:backend_result, key, result})}

      _ ->
        {:reply, {:error, :unknown_helper_result}, state}
    end
  end

  def handle_call({:event, {:backend_result, key, _}}, {caller, _}, %{router: caller} = state)
      when is_map_key(state.helpers, key),
      do: {:reply, {:error, :helper_observation_required}, state}

  def handle_call({:event, event}, {caller, _}, %{router: caller} = state) do
    state =
      case event do
        {:commit_issue, key, _} ->
          %{
            state
            | launch_notifications: MapSet.delete(state.launch_notifications, key),
              deferred_systemd: MapSet.delete(state.deferred_systemd, key)
          }

        _ ->
          state
      end

    case State.transition(state.bookkeeping, event, now_ms()) do
      {:ok, bookkeeping, result, effects} ->
        response = if match?({:commit_issue, _, _}, event), do: {:ok, result}, else: :ok
        state = %{state | bookkeeping: bookkeeping}
        {state, effects} = retry_systemd(state, event, effects)
        {:reply, response, enqueue_effects(state, effects)}

      {:error, reason, _} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(_message, _from, state), do: {:reply, {:error, :not_router}, state}

  @impl true
  def handle_continue({:launch_helper, key}, state) do
    helper = Map.fetch!(state.helpers, key)
    child = Map.fetch!(state.bookkeeping.children, key)

    options = [
      owner: self(),
      epoch: state.epoch,
      attempt: key,
      token: helper.token,
      name: child.name,
      binding: state.helper_binding
    ]

    case start_helper(state.helper_supervisor, options) do
      {:ok, worker} ->
        helper = %{helper | phase: :observing, pid: worker, monitor: Process.monitor(worker)}
        state = %{state | helpers: Map.put(state.helpers, key, helper)}

        # The immutable worker is registered and monitored before this call.
        # It acknowledges before opening a Port in its own continuation.
        case launch_worker(worker, helper.token) do
          :ok ->
            {:noreply, state}

          {:error, _reason} ->
            DynamicSupervisor.terminate_child(state.helper_supervisor, worker)
            helper = %{helper | result: {:error, {:observation_lost, :launch_unavailable}}}
            {:noreply, %{state | helpers: Map.put(state.helpers, key, helper)}}
        end

      {:error, _reason} ->
        # Initialization has no launch effect; no call to launch/2 occurred.
        {:noreply, ready_helper(state, key, {:error, :backend_unavailable})}
    end
  end

  @impl true
  def handle_info({:activation_drain, token}, %{drain: token} = state) do
    state = %{state | drain: nil} |> drain_effects(@drain) |> schedule_drain()
    {:noreply, state}
  end

  def handle_info({:activation_deadline, epoch, key, token}, %{epoch: epoch} = state) do
    case state.timers[key] do
      {_timer, ^token} ->
        state = %{state | timers: Map.delete(state.timers, key)}
        {:noreply, transition(state, {:expire, key})}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:activation_cancelled, lease, request}, state) do
    case state.messages[request] do
      %{waiter: %{lease: ^lease, caller_incarnation: incarnation}} ->
        {:noreply, transition(state, {:caller_down, incarnation})}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:helper_result, worker, epoch, key, token, result}, %{epoch: epoch} = state) do
    case state.helpers[key] do
      %{phase: :observing, pid: ^worker, token: ^token, result: nil} = helper ->
        {:noreply, %{state | helpers: Map.put(state.helpers, key, %{helper | result: result})}}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info(
        {:DOWN, monitor, :process, router, reason},
        %{router_monitor: monitor, router: router} = state
      ),
      do: {:stop, {:router_down, reason}, state}

  def handle_info({:DOWN, monitor, :process, worker, reason}, state) do
    case Enum.find(state.helpers, fn {_key, helper} ->
           helper.phase == :observing and helper.pid == worker and helper.monitor == monitor
         end) do
      {key, helper} ->
        result =
          if reason == :normal and helper.result != nil,
            do: helper.result,
            else: {:error, {:observation_lost, :worker_down}}

        {:noreply, ready_helper(state, key, result)}

      nil ->
        {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    Enum.each(state.timers, fn {_key, {timer, _token}} -> Process.cancel_timer(timer) end)
    # Limits observes this exact coordinator's DOWN and closes owned leases even
    # if a Router/test still retains native resource terms.
    :ok
  end

  defp admit_reserved(state, waiter, message, definition, terminal_control) do
    case Limits.claim_activation(waiter.lease, waiter.request, state.limits) do
      {:ok, handles} ->
        case State.transition(
               state.bookkeeping,
               {:admit, waiter, make_ref(), definition},
               now_ms()
             ) do
          {:ok, bookkeeping, {:admitted, key}, effects} ->
            record = %{
              attempt: key,
              terminal_control: terminal_control,
              waiter: Map.take(waiter, @waiter_fields),
              message: %{message | fds: handles}
            }

            state = %{
              state
              | bookkeeping: bookkeeping,
                messages: Map.put(state.messages, waiter.request, record)
            }

            {:reply, {:ok, key}, enqueue_effects(state, effects)}

          {:error, reason, _} ->
            cancel_terminal(state, terminal_control)
            release_lease(state, waiter.request, waiter.lease)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        cancel_terminal(state, terminal_control)

        if reason in [:activation_cancelled, :activation_expired],
          do: release_lease(state, waiter.request, waiter.lease)

        {:reply, {:error, reason}, state}
    end
  end

  defp transition(state, event) do
    case State.transition(state.bookkeeping, event, now_ms()) do
      {:ok, bookkeeping, _result, effects} ->
        enqueue_effects(%{state | bookkeeping: bookkeeping}, effects)

      {:error, _reason, _} ->
        state
    end
  end

  defp start_helper(supervisor, options) do
    DynamicSupervisor.start_child(supervisor, {HelperWorker, options})
  catch
    :exit, _reason -> {:error, :helper_supervisor_unavailable}
  end

  defp launch_worker(worker, token) do
    HelperWorker.launch(worker, token)
  catch
    :exit, _reason -> {:error, :helper_launch_unavailable}
  end

  defp ready_helper(state, key, result) do
    helper = %{Map.fetch!(state.helpers, key) | phase: :ready, result: result, monitor: nil}
    state = %{state | helpers: Map.put(state.helpers, key, helper)}

    case notify(state, {:helper_result, key, helper.token}) do
      :ok -> state
      {:error, :control_capacity} ->
        # Preserve the observed exit/uncertain child charge even when the
        # best-effort notification cannot enter the authority FIFO.
        state = %{state | helpers: Map.delete(state.helpers, key)}
        state |> transition({:backend_result, key, result}) |> settle_overload(key)
    end
  end

  defp retry_systemd(state, {:name_available, "org.freedesktop.systemd1"}, effects) do
    # Remove a deferred reference when its retry is queued, rather than clearing
    # outstanding notifications on every hint. Owner churn cannot queue copies.
    keys =
      state.deferred_systemd
      |> Enum.filter(&Map.has_key?(state.bookkeeping.attempts, &1))
      |> Enum.sort_by(&state.bookkeeping.attempts[&1].sequence)

    deferred = Enum.reduce(keys, state.deferred_systemd, &MapSet.delete(&2, &1))

    {%{state | deferred_systemd: deferred},
     effects ++ Enum.map(keys, &{:request_launch_commit, &1})}
  end

  defp retry_systemd(state, _event, effects), do: {state, effects}

  defp enqueue_effects(state, effects) do
    notifications =
      MapSet.filter(state.launch_notifications, &Map.has_key?(state.bookkeeping.attempts, &1))

    deferred =
      MapSet.filter(state.deferred_systemd, &Map.has_key?(state.bookkeeping.attempts, &1))

    %{
      state
      | effects: Enum.reduce(effects, state.effects, &:queue.in/2),
        launch_notifications: notifications,
        deferred_systemd: deferred
    }
    |> schedule_drain()
  end

  defp schedule_drain(%{drain: nil} = state) do
    if :queue.is_empty(state.effects) do
      state
    else
      token = make_ref()
      send(self(), {:activation_drain, token})
      %{state | drain: token}
    end
  end

  defp schedule_drain(state), do: state

  defp drain_effects(state, 0), do: state

  defp drain_effects(state, remaining) do
    case :queue.out(state.effects) do
      {:empty, _} ->
        state

      {{:value, effect}, rest} ->
        apply_effect(%{state | effects: rest}, effect) |> drain_effects(remaining - 1)
    end
  end

  defp apply_effect(state, {:request_launch_commit, key}) do
    case state.bookkeeping.attempts[key] do
      %{issued: false, owned: false} ->
        if MapSet.member?(state.launch_notifications, key) do
          state
        else
          case notify(state, {:launch_commit, key}) do
            :ok ->
              %{
                state
                | launch_notifications: MapSet.put(state.launch_notifications, key),
                  deferred_systemd: MapSet.delete(state.deferred_systemd, key)
              }
            {:error, :control_capacity} -> settle_overload(state, key)
          end
        end

      _ ->
        state
    end
  end

  defp apply_effect(state, {:launch, key, definition}) do
    case notify(state, {:launch, key, definition}) do
      :ok -> state
      {:error, :control_capacity} ->
        state |> transition({:backend_result, key, :not_launched}) |> settle_overload(key)
    end
  end

  defp apply_effect(state, {:launch_systemd, key, definition, owner}) do
    case notify(state, {:launch_systemd, key, definition, owner}) do
      :ok -> state
      {:error, :control_capacity} ->
        transition(state, {:backend_result, key, {:error, :limits_exceeded}})
    end
  end

  defp apply_effect(state, {:resolve_waiter, key, request}) do
    case {state.messages[request], get_in(state.bookkeeping.attempts, [key, :waiters, request])} do
      {%{attempt: ^key} = record, waiter} when not is_nil(waiter) ->
        case notify(state, {:resolve, key, request, metadata(waiter), record.message}) do
          :ok -> state
          {:error, :control_capacity} ->
            transition(state, {:finish_waiter, key, request, {:terminal, :limits_exceeded}})
        end

      _ ->
        state
    end
  end

  defp apply_effect(state, {:terminal_waiter, key, request, reason}) do
    case state.messages[request] do
      %{attempt: ^key} = record ->
        event = {:terminal, key, request, record.waiter, header(record.message, :automatic),
                 terminal_reason(reason)}
        payload = {:activation_event, self(), state.epoch, event}

        case Limits.enqueue_terminal(record.terminal_control, payload, state.limits) do
          :ok -> :ok
          {:error, error} -> exit({:activation_terminal_accounting_failed, error})
        end

      _ ->
        :ok
    end

    state
  end

  defp apply_effect(state, {:release_lease, request, lease}) do
    case state.messages[request] do
      %{waiter: %{lease: ^lease}, terminal_control: terminal_control} ->
        cancel_terminal(state, terminal_control)
        release_lease(state, request, lease)
        %{state | messages: Map.delete(state.messages, request)}

      _ ->
        state
    end
  end

  defp apply_effect(state, {:arm_deadline, key, deadline}) do
    state = cancel_timer(state, key)
    token = make_ref()

    timer =
      Process.send_after(
        self(),
        {:activation_deadline, state.epoch, key, token},
        max(0, deadline - now_ms())
      )

    %{state | timers: Map.put(state.timers, key, {timer, token})}
  end

  defp apply_effect(state, {:cancel_deadline, key}), do: cancel_timer(state, key)

  defp cancel_timer(state, key) do
    case Map.pop(state.timers, key) do
      {nil, _} ->
        state

      {{timer, _token}, timers} ->
        Process.cancel_timer(timer)
        %{state | timers: timers}
    end
  end

  defp release_lease(state, request, lease) do
    case Limits.release_activation(lease, request, state.limits) do
      :ok -> :ok
      {:error, reason} -> exit({:activation_accounting_failed, reason})
    end
  end

  defp metadata(waiter),
    do:
      Map.take(waiter, @waiter_fields ++ [:pending_terminal])
      |> Map.reject(fn {key, value} -> key == :pending_terminal and is_nil(value) end)

  # Launch authorization needs the signature and actual leased FD count. Router
  # may inspect these handles; their ownership stays with Limits/coordinator.
  defp launch_header(message, :explicit), do: %{message | body: Enum.take(message.body, 2)}
  defp launch_header(message, _kind), do: %{message | body: []}
  defp header(message, _kind), do: %{message | body: [], fds: [], signature: ""}

  defp terminal_bytes(state, waiter, message) do
    # Header and selected metadata have already passed ingress validation.
    # The additional finite envelope covers attempt identity and bounded errors.
    event = {:terminal, nil, waiter.request, Map.take(waiter, @waiter_fields),
             header(message, :automatic), nil}
    :erlang.external_size({:activation_event, self(), state.epoch, event}) + 8192
  end

  defp terminal_reason({:backend_error, name, text}) when is_binary(name) and is_binary(text),
    do: {:backend_error, bounded_text(name, 255), bounded_text(text, 4096)}
  defp terminal_reason(reason) when is_atom(reason), do: reason
  defp terminal_reason({:backend_failed, status}) when is_integer(status) and status in 0..255,
    do: {:backend_failed, status}
  defp terminal_reason({:backend_signaled, signal}) when signal in 1..64,
    do: {:backend_signaled, signal}
  defp terminal_reason({:observation_lost, reason} = error)
       when reason in [:worker_down, :launch_unavailable, :port_open_failed, :extra_record_bytes,
                       :incomplete_observation, :bridge_exit, :port_exit, :port_down,
                       :bridge_observation_failed, :invalid_record],
       do: error
  defp terminal_reason({:observation_lost, _reason}), do: {:observation_lost, :unavailable}
  defp terminal_reason({kind, stage, errno} = error)
       when kind in [:not_started, :exec_failed] and
              stage in [:argument, :binding, :hardening, :stdio, :close_fds, :error_pipe,
                        :fork, :signals, :exec, :wait, :error_read] and
              is_integer(errno) and errno in 1..0xFFFFFFFF,
       do: error
  defp terminal_reason({:limit_exceeded, _, _}), do: :limits_exceeded
  defp terminal_reason({:xml_limit_exceeded, _}), do: :limits_exceeded
  defp terminal_reason(_reason), do: :backend_unavailable

  defp bounded_text(text, bytes),
    do: :binary.copy(trim_utf8(binary_part(text, 0, min(byte_size(text), bytes)), 3))

  defp trim_utf8(text, remaining) do
    cond do
      String.valid?(text) -> text
      remaining > 0 and byte_size(text) > 0 ->
        trim_utf8(binary_part(text, 0, byte_size(text) - 1), remaining - 1)
      true -> ""
    end
  end

  defp cancel_terminal(state, token) do
    case Limits.cancel_terminal(token, state.limits) do
      :ok -> :ok
      {:error, reason} -> exit({:activation_terminal_accounting_failed, reason})
    end
  end

  defp settle_overload(state, key) do
    case state.bookkeeping.attempts[key] do
      nil -> state
      attempt ->
        attempt.waiters
        |> Map.values()
        # An already-enqueued resolution keeps its body until Router's finish.
        |> Enum.reject(& &1.resolving)
        |> Enum.sort_by(& &1.sequence)
        |> Enum.reduce(state, fn waiter, current ->
          transition(current, {:finish_waiter, key, waiter.request, {:terminal, :limits_exceeded}})
        end)
    end
  end

  defp notify(state, event) do
    case GaoBus.Router.enqueue_activation_event(state.router, self(), state.epoch, event, state.limits) do
      :ok -> :ok
      {:error, :control_capacity} = error -> error
      {:error, reason} ->
        exit({:activation_control_enqueue_failed, reason})
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
