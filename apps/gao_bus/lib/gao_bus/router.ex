defmodule GaoBus.Router do
  @moduledoc """
  Ordered message authority. Trusted peer identity and a coherent destination
  snapshot are checked against one policy generation before any delivery.
  """

  use GenServer
  import Bitwise

  alias ExDBus.Message
  alias GaoBus.{Activation, Limits, NameRegistry, PendingCalls, Policy}
  alias GaoBus.Activation.{Helper, Systemd}
  alias GaoBus.Unix.Resources

  @bus "org.freedesktop.DBus"
  @systemd "org.freedesktop.systemd1"
  @denied "org.freedesktop.DBus.Error.AccessDenied"

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def route(message, from_peer_pid, bytes \\ nil) do
    bytes = bytes || :erlang.external_size(message)

    case handoff(message, from_peer_pid, bytes, :route) do
      {:ok, _token} -> :ok
      error -> error
    end
  end

  @doc false
  def route_frame(message, from_peer_pid, bytes),
    do: handoff(message, from_peer_pid, bytes, :frame)

  defp handoff(message, peer, bytes, mode) do
    with router when is_pid(router) <- Process.whereis(__MODULE__),
         {:ok, token} <- Limits.enqueue_route(message, peer, bytes, mode, router) do
      # Limits owns independent ingress copies before sending the envelope.
      # A timeout or caller death can therefore never invalidate queued rights.
      close_resources(message.fds)
      {:ok, token}
    else
      nil -> {:error, :route_unavailable}
      error -> error
    end
  end

  def emit_signal(path, interface, member, signature, body, destination \\ nil) do
    enqueue_control({:emit_signal, path, interface, member, signature, body, destination})
  end

  @doc false
  def enqueue_activation_event(router, coordinator, epoch, event, limits \\ Limits) do
    case Limits.enqueue_control(router, {:activation_event, coordinator, epoch, event}, limits) do
      {:ok, _token} -> :ok
      error -> error
    end
  end

  defp enqueue_control(payload, router \\ Process.whereis(__MODULE__)) do
    case Limits.enqueue_control(router, payload) do
      {:ok, _token} -> :ok
      error -> error
    end
  end

  @doc "Caches authenticated socket credentials before Hello; nil name is not registration."
  def register_peer(peer_pid, unique_name, credentials \\ %{}, unix_fd \\ false) do
    GenServer.cast(__MODULE__, {:register_peer, peer_pid, unique_name, credentials, unix_fd})
  end

  def unregister_peer(peer_pid) do
    if Process.whereis(__MODULE__),
      do: GenServer.call(__MODULE__, {:unregister_peer, peer_pid}),
      else: :ok
  end

  @impl true
  def init(opts) do
    limits =
      Keyword.get(opts, :pending_limits, Application.get_env(:gao_bus, :pending_call_limits, %{}))

    max_output_bytes = Keyword.get(opts, :max_output_bytes, 1_048_576)

    result =
      with true <- is_integer(max_output_bytes) and max_output_bytes in 1..134_217_728,
           do: PendingCalls.new(limits)

    case result do
      {:ok, pending} ->
        {:ok,
         %{
           peers: %{},
           next_serial: 1,
           policy_snapshot: {:error, :policy_unavailable},
           pending: pending,
           pending_timer: nil,
           reload_waiter: nil,
           max_output_bytes: max_output_bytes,
           activation_options: Keyword.get(opts, :activation),
           activation_owner: nil,
           activation_claims: %{},
           work_queue: :queue.new(),
           work_tick: nil,
           executing_work: false,
           active_fanout: nil
         }}

      {:error, reason} ->
        {:stop, reason}

      false ->
        {:stop, :invalid_output_limit}
    end
  end

  @impl true
  def handle_cast({:register_peer, peer_pid, unique_name, credentials, unix_fd}, state) do
    reference =
      case state.peers[peer_pid] do
        nil -> Process.monitor(peer_pid)
        peer -> peer.monitor_ref
      end

    info = %{
      unique_name: unique_name,
      credentials: credentials,
      monitor_ref: reference,
      unix_fd: unix_fd
    }

    {:noreply, put_in(state.peers[peer_pid], info)}
  end

  @impl true
  def handle_call({:unregister_peer, peer_pid}, _from, state),
    do: {:reply, :ok, state |> remove_peer(peer_pid) |> cancel_source_fanout(peer_pid)}

  @impl true
  def handle_info({:owned_route, message, peer, token, bytes, mode}, state) do
    {:noreply, submit_work({:route, message, peer, token, bytes, mode}, state)}
  end

  def handle_info({:control_work, token, payload}, state),
    do: {:noreply, submit_work({:control, token, payload}, state)}

  def handle_info({:drain_work, tick}, %{work_tick: tick} = state) do
    state = %{state | work_tick: nil}
    {:noreply, drain_work(state)}
  end

  def handle_info(
        {:DOWN, monitor, :process, coordinator, reason},
        %{activation_owner: {coordinator, _epoch, monitor}} = state
      ),
      do: {:stop, {:activation_down, reason}, state}

  def handle_info(
        {:policy_reload_prepared, policy_pid, epoch, job, base_generation},
        state
      )
      when is_pid(policy_pid) and is_reference(epoch) and is_reference(job) do
    if Process.whereis(Policy) == policy_pid do
      case Policy.commit_reload(policy_pid, epoch, job, base_generation) do
        {:error, :policy_unavailable} -> exit({:reload_authority_failed, :policy_unavailable})
        _result -> :ok
      end
    end

    {:noreply, state}
  end

  def handle_info(
        {:policy_reload_finished, policy_pid, epoch, job, result},
        %{reload_waiter: %{handle: {policy_pid, epoch, job}} = waiter} = state
      ) do
    state =
      if Process.whereis(Policy) == policy_pid do
        if Map.get(waiter, :completion_queued, false) do
          state
        else
          state = %{state | reload_waiter: Map.put(waiter, :completion_queued, true)}
          submit_work({:reload_completion, waiter, result}, state)
        end
      else
        state
      end

    {:noreply, state}
  end

  def handle_info({:pending_expiry, token}, %{pending_timer: {timer, token}} = state)
      when is_reference(timer) do
    # The existing single timer slot bounds this essential completion. Keep it
    # occupied until the FIFO reaches the event instead of borrowing emit credit.
    {:noreply, submit_work({:pending_expiry, token}, %{state | pending_timer: {:queued, token}})}
  end

  def handle_info({:DOWN, reference, :process, peer_pid, _reason}, state) do
    case state.peers[peer_pid] do
      %{monitor_ref: ^reference} ->
        {:noreply, state |> remove_peer(peer_pid) |> cancel_source_fanout(peer_pid)}
      _ -> {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Only completed work retires its ingress lease. Deferred fan-out retains
  # both its original resources and route_complete acknowledgement until finish.
  defp route_owned(message, peer, state, token, bytes) do
    if live_source?(state, peer) do
      {:noreply, next} = route_authorized(message, peer, state, token, bytes)
      if next.active_fanout, do: {:deferred, next}, else: {:completed, next}
    else
      {:completed, state}
    end
  end

  defp submit_work(work, %{active_fanout: nil, work_tick: nil} = state) do
    if :queue.is_empty(state.work_queue),
      do: run_work(work, state),
      else: schedule_work(%{state | work_queue: :queue.in(work, state.work_queue)})
  end

  defp submit_work(work, state),
    do: schedule_work(%{state | work_queue: :queue.in(work, state.work_queue)})

  defp schedule_work(%{work_tick: nil} = state) do
    if state.active_fanout || not :queue.is_empty(state.work_queue) do
      tick = make_ref()
      send(self(), {:drain_work, tick})
      %{state | work_tick: tick}
    else
      state
    end
  end

  defp schedule_work(state), do: state

  defp drain_work(%{active_fanout: nil} = state) do
    case :queue.out(state.work_queue) do
      {:empty, _queue} -> state
      {{:value, work}, queue} -> run_work(work, %{state | work_queue: queue})
    end
  end

  defp drain_work(state) do
    fanout = state.active_fanout

    if fanout_source_authorized?(fanout, state, Policy.snapshot()) do
      case GaoBus.MatchRules.broadcast_batch(fanout.cursor) do
        {status, recipients, cursor} when status in [:more, :done] ->
          fanout = %{fanout | cursor: cursor}
          fanout =
            Enum.reduce_while(recipients, fanout, fn peer, current ->
              next = fanout_delivery(current, peer, state)
              if Map.get(next, :cancelled, false), do: {:halt, next}, else: {:cont, next}
            end)
          state = %{state | active_fanout: fanout}
          if status == :done or Map.get(fanout, :cancelled, false),
            do: complete_fanout(state), else: schedule_work(state)

        {:error, _reason} -> complete_fanout(state)
      end
    else
      complete_fanout(state)
    end
  end

  defp run_work({:route, message, peer, token, bytes, _mode} = work, state) do
    before = state.reload_waiter
    state = %{state | executing_work: true}
    {outcome, state} = route_owned(message, peer, state, token, bytes)
    state = %{state | executing_work: false}

    case outcome do
      :deferred ->
        schedule_work(put_in(state.active_fanout.owner, work))

      :completed ->
        state =
          case state.reload_waiter do
            %{peer: ^peer, route_ack: nil} = waiter when is_nil(before) ->
              %{state | reload_waiter: %{waiter | route_ack: token}}

            _ -> state
          end
        finish_work(work, state)
    end
  end

  defp run_work({:pending_expiry, _token}, state) do
    state = %{state | executing_work: true, pending_timer: nil}
    state = state |> expire_pending() |> schedule_pending()
    schedule_work(%{state | executing_work: false})
  end

  defp run_work({:reload_completion, waiter, result}, state) do
    state = complete_reload(waiter, result, %{state | executing_work: true})
    schedule_work(%{state | executing_work: false})
  end

  defp run_work({:control, _token, payload} = work, state) do
    state = execute_control(payload, %{state | executing_work: true})
    state = %{state | executing_work: false}

    if state.active_fanout,
      do: schedule_work(put_in(state.active_fanout.owner, work)),
      else: finish_work(work, state)
  end

  defp finish_work({:route, _message, peer, token, _bytes, mode}, state) do
    case Limits.release(token) do
      :ok -> :ok
      {:error, reason} -> exit({:resource_accounting_failed, reason})
    end

    # Reload retains the transport window until its ordered completion reply.
    unless match?(%{route_ack: ^token}, state.reload_waiter) do
      if mode == :frame, do: send(peer, {:route_complete, token})
    end

    schedule_work(state)
  end

  defp finish_work({:control, token, _payload}, state) do
    case Limits.release_control(token) do
      :ok -> schedule_work(state)
      {:error, reason} -> exit({:control_accounting_failed, reason})
    end
  end

  defp complete_fanout(state) do
    work = state.active_fanout.owner
    finish_work(work, %{state | active_fanout: nil})
  end

  defp cancel_source_fanout(%{active_fanout: %{owner: {:route, _, peer, _, _, _}}} = state, peer),
    do: complete_fanout(state)
  defp cancel_source_fanout(state, _peer), do: state

  defp live_source?(state, peer),
    do: Map.has_key?(state.peers, peer) and Process.alive?(peer)

  defp fanout_source_live?(%{owner: {:route, _, peer, _, _, _}} = fanout, state),
    do: same_incarnation?(fanout.peers[peer], state.peers[peer]) and live_source?(state, peer)
  defp fanout_source_live?(_fanout, _state), do: true

  defp fanout_source_authorized?(fanout, state, snapshot) do
    case fanout.owner do
      {:route, _, source, _, _, _} ->
        fanout_source_live?(fanout, state) and
          match?({:allow, _}, Policy.authorize(snapshot, :send, fanout.context)) and
          capability_send(fanout.peers[source].credentials, fanout.message) == :allow
      _ -> true
    end
  end

  defp same_incarnation?(%{monitor_ref: monitor, unique_name: name},
                          %{monitor_ref: monitor, unique_name: name}), do: true
  defp same_incarnation?(_old, _current), do: false

  defp fanout_delivery(fanout, peer, state) do
    if same_incarnation?(fanout.peers[peer], state.peers[peer]) and Process.alive?(peer) do
      snapshot = Policy.snapshot()
      delivery_state = %{state | policy_snapshot: snapshot}
      context = fanout.context

      # Sender names/identity are frozen at admission, but every delayed enqueue
      # sees one current policy generation and the same live recipient incarnation.
      if fanout_source_authorized?(fanout, state, snapshot) do
        case authorize_recipient(peer, context, delivery_state) do
          {:ok, false} when fanout.message.fds != [] -> fanout
          {:ok, negotiated} ->
            bytes = fanout.bytes || byte_size(Message.encode_message(fanout.message))
            _ = enqueue(fanout.message, peer, negotiated, Map.get(context, :source_token),
                        state.max_output_bytes, bytes)
            %{fanout | bytes: bytes}
          {:error, _reason} -> fanout
        end
      else
        Map.put(fanout, :cancelled, true)
      end
    else
      fanout
    end
  end

  defp ordered_control(payload, %{executing_work: true, active_fanout: nil} = state),
    do: execute_control(payload, state)

  defp ordered_control(payload, state) do
    case Limits.reserve_control(self(), :erlang.external_size(payload)) do
      {:ok, token} -> submit_work({:control, token, payload}, state)
      {:error, :control_capacity} -> state
      {:error, reason} -> exit({:control_accounting_failed, reason})
    end
  end

  defp execute_control({:emit_signal, path, interface, member, signature, body, destination}, state) do
    {serial, state} = next_serial(%{state | policy_snapshot: Policy.snapshot()})

    signal =
      Message.signal(path, interface, member,
        serial: serial,
        sender: @bus,
        destination: destination,
        signature: signature,
        body: body
      )

    signal = %{signal | sender: @bus}
    {destination, context} = context(signal, %{}, :bus)
    state = deliver_signal(signal, destination, context, state)

    case {interface, member, signature, body, state.activation_owner} do
      {@bus, "NameOwnerChanged", "sss", [name, _old, new], {coordinator, _epoch, _monitor}}
      when new != "" ->
        activation_result!(Activation.name_available(name, coordinator))

        # The signal is only a hint. Retire an empty launch tombstone only for
        # the current registered owner, after normal authorized acquisition.
        with {:ok, owner} <- NameRegistry.resolve(name),
             %{unique_name: ^new} <- state.peers[owner] do
          activation_result!(Activation.name_owned(name, coordinator))
        end

      _ ->
        :ok
    end

    state
  end

  defp execute_control({:activation_event, coordinator, epoch, event},
                       %{activation_owner: {coordinator, epoch, _monitor}} = state),
    do: activation_event(event, state)

  defp execute_control({:failed_pending, entries, explanation}, state) do
    Enum.reduce(entries, state, fn entry, state ->
      message = %Message{type: :method_call, serial: entry.serial, sender: entry.caller_name}
      error_reply(message, entry.caller, "org.freedesktop.DBus.Error.NoReply", explanation, state)
    end)
  end

  defp execute_control(_payload, state), do: state

  defp route_authorized(message, from_peer_pid, state, source_token, bytes) do
    state = expire_pending(%{state | policy_snapshot: Policy.snapshot()})

    case Map.get(state.peers, from_peer_pid) do
      %{credentials: credentials, unique_name: name} when is_map(credentials) ->
        message = %{message | sender: name}
        {destination, context} = context(message, credentials, from_peer_pid)

        context = context |> Map.put(:source_token, source_token) |> Map.put(:source_bytes, bytes)

        context = %{
          context
          | requested_reply: requested_reply?(state, message, from_peer_pid, destination)
        }

        state =
          if context.requested_reply and
               match?({:ok, _, %GaoBus.Policy.XML{}}, state.policy_snapshot) do
            {:peer, caller, _names} = destination

            # The XML reference consumes the actual callee's correlation before
            # send/receive policy, including a denied reply. Other peers cannot
            # retire it because requested_reply is bound to the callee PID.
            %{
              state
              | pending:
                  PendingCalls.complete(
                    state.pending,
                    caller,
                    from_peer_pid,
                    message.reply_serial
                  )
            }
          else
            state
          end

        with true <- registered_or_hello?(name, message),
             {:allow, _} <- Policy.authorize(state.policy_snapshot, :send, context),
             :allow <- capability_send(credentials, message),
             :ok <- activation_serial_available(state, from_peer_pid, message) do
          {:noreply, do_route(message, from_peer_pid, destination, context, state)}
        else
          _ -> {:noreply, reject(message, from_peer_pid, state)}
        end

      _ ->
        {:noreply, reject(%{message | sender: nil}, from_peer_pid, state)}
    end
  end

  defp remove_peer(state, peer_pid) do
    case state.peers[peer_pid] do
      nil ->
        state

      info ->
        if state.activation_owner do
          {coordinator, _epoch, _monitor} = state.activation_owner

          activation_result!(
            Activation.caller_down({info.monitor_ref, info.unique_name}, coordinator)
          )
        end

        Process.demonitor(info.monitor_ref, [:flush])
        GaoBus.MatchRules.peer_disconnected(peer_pid)
        NameRegistry.peer_disconnected(peer_pid)
        if info.unique_name, do: GaoBus.Policy.Capability.peer_disconnected(info.unique_name)
        {failed, pending} = PendingCalls.disconnected(state.pending, peer_pid)

        # Retain the single reload job slot through its FIFO completion even
        # after caller death. Its incarnation check suppresses the dead reply.
        state = %{
          state
          | peers: Map.delete(state.peers, peer_pid),
            pending: pending
        }

        fail_pending(failed, state, "The destination disconnected before replying")
    end
  end

  defp registered_or_hello?(name, _message) when is_binary(name), do: true

  defp registered_or_hello?(nil, %Message{type: :method_call, destination: dest, member: "Hello"}),
    do: dest in [nil, @bus]

  defp registered_or_hello?(_, _), do: false

  defp do_route(%Message{type: :method_call} = msg, peer, :bus, context, state) do
    case GaoBus.BusInterface.handle_message(msg, peer, state, :deferred) do
      {{:activation_start, validated}, state} ->
        [name, _flags] = validated.body

        case NameRegistry.resolve(name) do
          {kind, _target} when kind in [:ok, :bus] ->
            {reply, state} = GaoBus.BusInterface.activation_reply(validated, 2, state)
            deliver_bus_reply(validated, peer, reply, state)

          _ ->
            admit_activation(validated, peer, name, :explicit, context, state)
        end

      {{:deferred, handle}, state} ->
        info = Map.fetch!(state.peers, peer)

        waiter = %{
          handle: handle,
          request: Map.take(msg, [:serial, :flags, :sender]),
          peer: peer,
          registration: {info.monitor_ref, info.unique_name},
          policy_snapshot: state.policy_snapshot,
          route_ack: nil
        }

        %{state | reload_waiter: waiter}

      {reply, state} ->
        deliver_bus_reply(msg, peer, reply, state)
    end
  end

  defp do_route(
         %Message{type: type, flags: flags} = msg,
         peer,
         {:missing, name},
         context,
         %{activation_options: options} = state
       )
       when type in [:method_call, :signal] and not is_nil(options) and (flags &&& 2) == 0 do
    if NameRegistry.requestable_name?(name),
      do: admit_activation(msg, peer, name, :automatic, context, state),
      else: activation_error(msg, peer, :service_unknown, state)
  end

  defp do_route(%Message{type: :method_call} = msg, peer, {:peer, target, _names}, context, state) do
    pending =
      if reply_expected?(msg),
        do: PendingCalls.add(state.pending, msg, peer, target, context.credentials.uid, now_ms()),
        else: {:ok, state.pending}

    case pending do
      {:ok, candidate} ->
        case deliver(msg, target, context, state) do
          :ok ->
            schedule_pending(%{state | pending: candidate})

          {:error, :unix_fd_not_negotiated} ->
            error_reply(
              msg,
              peer,
              "org.freedesktop.DBus.Error.NotSupported",
              "Destination did not negotiate Unix FDs",
              state
            )

          {:error, {:limit_exceeded, _, _}} ->
            error_reply(
              msg,
              peer,
              "org.freedesktop.DBus.Error.LimitsExceeded",
              "Destination queue limit exceeded",
              state
            )

          {:error, {:xml_limit_exceeded, _name}} ->
            error_reply(
              msg,
              peer,
              "org.freedesktop.DBus.Error.LimitsExceeded",
              "Destination queue limit exceeded",
              state
            )

          {:error, :outbound_message_too_large} ->
            error_reply(
              msg,
              peer,
              "org.freedesktop.DBus.Error.LimitsExceeded",
              "Routed frame exceeds output limit",
              state
            )

          {:error, _reason} ->
            reject(msg, peer, state)
        end

      {:error, :duplicate_serial} ->
        error_reply(msg, peer, @denied, "Duplicate outstanding call serial", state)

      {:error, :limits_exceeded} ->
        error_reply(
          msg,
          peer,
          "org.freedesktop.DBus.Error.LimitsExceeded",
          "Pending call limit exceeded",
          state
        )
    end
  end

  defp do_route(%Message{type: :method_call} = msg, peer, _destination, _context, state) do
    error_name =
      if (msg.flags &&& 2) != 0 do
        "org.freedesktop.DBus.Error.NameHasNoOwner"
      else
        "org.freedesktop.DBus.Error.ServiceUnknown"
      end

    error_reply(msg, peer, error_name, "The destination has no owner", state)
  end

  defp do_route(%Message{type: type} = msg, peer, {:peer, target, _names}, context, state)
       when type in [:method_return, :error] do
    case deliver(msg, target, context, state) do
      :ok when context.requested_reply ->
        %{state | pending: PendingCalls.complete(state.pending, target, peer, msg.reply_serial)}

      {:error, :receive_denied} ->
        reject(msg, peer, state)

      _ ->
        state
    end
  end

  defp do_route(
         %Message{
           type: :signal,
           destination: @bus,
           interface: "org.freedesktop.systemd1.Activator",
           member: "ActivationFailure"
         } = msg,
         peer,
         _destination,
         context,
         state
       ) do
    systemd_failure(msg, peer, context, state)
  end

  defp do_route(%Message{type: :signal} = msg, _peer, destination, context, state) do
    deliver_signal(msg, destination, context, state)
  end

  defp do_route(_message, _peer, _destination, _context, state), do: state

  defp activation_serial_available(state, peer, %{type: type, serial: serial})
       when type in [:method_call, :signal] do
    if Map.has_key?(state.activation_claims, {peer, serial}) or
         (type == :method_call and Map.has_key?(state.pending.entries, {peer, serial})),
       do: {:error, :duplicate_serial},
       else: :ok
  end

  defp activation_serial_available(_state, _peer, _message), do: :ok

  defp activation_definitions(state) do
    case Policy.configuration(state.policy_snapshot) do
      {:ok, %{services: %{selected: selected}}} ->
        Map.new(selected, fn {name, entry} ->
          backend =
            cond do
              state.activation_options.mode in [:systemd, :systemd_helper] and name == "org.freedesktop.systemd1" ->
                :wait

              state.activation_options.mode in [:systemd, :systemd_helper] and entry.systemd_service != nil ->
                :systemd

              true ->
                :helper
            end

          key =
            {name, entry.path, entry.capture.sha256, entry.argv, entry.account,
             entry.systemd_service}

          {name, %{key: key, backend: backend, unit: entry.systemd_service}}
        end)
        |> Map.reject(fn {_name, definition} ->
          definition.backend not in
            Map.get(state.activation_options, :backends, [:systemd, :wait, :helper])
        end)

      _ ->
        %{}
    end
  end

  defp bind_activation(%{activation_owner: nil} = state) do
    case Process.whereis(Activation) do
      coordinator when is_pid(coordinator) ->
        case Activation.epoch(coordinator) do
          {:ok, epoch} ->
            {:ok, %{state | activation_owner: {coordinator, epoch, Process.monitor(coordinator)}}}

          error ->
            error
        end

      _ ->
        {:error, :activation_unavailable}
    end
  end

  defp bind_activation(state), do: {:ok, state}

  defp synchronize_activation(state) do
    {coordinator, _epoch, _monitor} = state.activation_owner
    {:ok, generation, _policy} = state.policy_snapshot
    definitions = activation_definitions(state)
    activation_result!(Activation.reload(generation, definitions, coordinator))
    definitions
  end

  defp admit_activation(message, peer, name, kind, context, state) do
    with {:ok, bound} <- bind_activation(state) do
      definitions = synchronize_activation(bound)

      case Map.get(definitions, name) do
        nil ->
          activation_error(message, peer, :service_unknown, bound)

        definition ->
          {coordinator, epoch, _monitor} = bound.activation_owner
          info = Map.fetch!(bound.peers, peer)
          incarnation = {info.monitor_ref, info.unique_name}
          request = {epoch, make_ref()}
          deadline = now_ms() + Map.get(bound.activation_options, :service_start_timeout, 25_000)

          identity = %{
            caller: peer,
            caller_incarnation: incarnation,
            request_key: request,
            deadline: deadline
          }

          case Limits.reserve_activation(
                 context.source_token,
                 identity,
                 context.source_bytes,
                 message.fds,
                 coordinator
               ) do
            {:ok, lease} ->
              {:ok, generation, _} = bound.policy_snapshot

              waiter = %{
                caller: peer,
                caller_incarnation: incarnation,
                request: request,
                serial: {epoch, incarnation, message.serial},
                kind: kind,
                message_type: message.type,
                flags: message.flags,
                destination: name,
                generation: generation,
                definition: definition.key,
                deadline: deadline,
                lease: lease
              }

              case Activation.admit(waiter, message, definition, coordinator) do
                {:ok, attempt} ->
                  claim = %{attempt: attempt, request: request, incarnation: incarnation}

                  next = %{
                    bound
                    | activation_claims:
                        Map.put(bound.activation_claims, {peer, message.serial}, claim)
                  }

                  # Acquisition can precede the asynchronous ownership hint.
                  if match?({:ok, _}, NameRegistry.resolve(name)),
                    do: activation_result!(Activation.name_available(name, coordinator))

                  next

                {:error, :activation_unavailable} ->
                  # A call timeout does not cancel the coordinator's admitted
                  # request. Tear down this epoch; its monitors reclaim leases.
                  exit({:activation_failed, :activation_unavailable})

                {:error, reason} ->
                  activation_error(message, peer, reason, bound)
              end

            {:error, reason} ->
              activation_error(message, peer, reason, bound)
          end
      end
    else
      {:error, reason} -> activation_error(message, peer, reason, state)
    end
  end

  defp activation_event({:launch_commit, attempt}, state) do
    state = %{state | policy_snapshot: Policy.snapshot()}
    _definitions = synchronize_activation(state)
    {coordinator, _epoch, _monitor} = state.activation_owner

    case Activation.view(attempt, coordinator) do
      {:ok, %{definition: definition, waiters: waiters}} ->
        Enum.each(waiters, fn %{waiter: waiter, message: message} ->
          unless activation_authorized?(waiter, message, state) do
            activation_result!(
              Activation.finish(attempt, waiter.request, {:terminal, :denied}, coordinator)
            )
          end
        end)

        {:ok, generation, _} = state.policy_snapshot

        commit =
          case definition.backend do
            :systemd ->
              case systemd_owner(state) do
                {:ok, owner} ->
                  Activation.commit_systemd(attempt, generation, owner, coordinator)

                :missing ->
                  activation_result!(Activation.defer_systemd(attempt, coordinator))
                  {:ok, :waiting}
              end

            _ ->
              Activation.commit(attempt, generation, coordinator)
          end

        case commit do
          {:ok, _result} ->
            :ok

          {:error, reason} ->
            activation_result!(Activation.backend_result(attempt, {:error, reason}, coordinator))
        end

      {:error, :unknown_attempt} ->
        :ok

      {:error, reason} ->
        exit({:activation_failed, reason})
    end

    state
  end

  defp activation_event({:launch_systemd, attempt, definition, owner}, state) do
    state = %{state | policy_snapshot: Policy.snapshot()}
    {coordinator, _epoch, _monitor} = state.activation_owner

    case Activation.systemd_view(definition.unit, attempt, coordinator) do
      {:ok, waiters} when waiters != [] ->
        Enum.each(waiters, fn %{attempt: key, waiter: waiter, message: message} ->
          reason = activation_waiter_refusal(waiter, message, state)

          if reason,
            do:
              activation_result!(
                Activation.finish(key, waiter.request, {:terminal, reason}, coordinator)
              )
        end)

        case Activation.systemd_view(definition.unit, attempt, coordinator) do
          {:ok, remaining} ->
            if Enum.any?(remaining, &is_nil(Map.get(&1.waiter, :pending_terminal))) do
              issue_systemd(definition, owner, state)
            else
              activation_result!(
                Activation.systemd_failure(definition.unit, :caller_down, coordinator)
              )

              state
            end

          {:error, :unknown_unit} ->
            state

          {:error, reason} ->
            exit({:activation_failed, reason})
        end

      {:ok, []} ->
        activation_result!(Activation.systemd_failure(definition.unit, :caller_down, coordinator))
        state

      {:error, :unknown_unit} ->
        state

      {:error, reason} ->
        exit({:activation_failed, reason})
    end
  end

  # The explicit installed-helper mode validates package binding before startup
  # and again in the worker. Systemd-only mode excludes this backend.
  defp activation_event({:launch, attempt, %{backend: :helper}}, state) do
    state = %{state | policy_snapshot: Policy.snapshot()}
    {coordinator, _epoch, _monitor} = state.activation_owner

    case Activation.view(attempt, coordinator) do
      {:ok, %{waiters: waiters}} ->
        Enum.each(waiters, fn %{waiter: waiter, message: message} ->
          if reason = activation_waiter_refusal(waiter, message, state) do
            activation_result!(
              Activation.finish(attempt, waiter.request, {:terminal, reason}, coordinator)
            )
          end
        end)

        case Activation.view(attempt, coordinator) do
          {:ok, %{waiters: remaining}} ->
            active = Enum.filter(remaining, &is_nil(Map.get(&1.waiter, :pending_terminal)))

            case active do
              [] ->
                activation_result!(Activation.backend_result(attempt, :not_launched, coordinator))

              [%{waiter: %{destination: name}} | _] ->
                if match?({:ok, _}, NameRegistry.resolve(name)) do
                  activation_result!(Activation.name_available(name, coordinator))

                  activation_result!(
                    Activation.backend_result(attempt, :not_launched, coordinator)
                  )
                else
                  activation_result!(Activation.launch_helper(attempt, coordinator))
                end
            end

          {:error, :unknown_attempt} ->
            activation_result!(Activation.backend_result(attempt, :not_launched, coordinator))

          {:error, reason} ->
            exit({:activation_failed, reason})
        end

      {:error, :unknown_attempt} ->
        activation_result!(Activation.backend_result(attempt, :not_launched, coordinator))

      {:error, reason} ->
        exit({:activation_failed, reason})
    end

    state
  end

  defp activation_event({:helper_result, attempt, token}, state) do
    {coordinator, _epoch, _monitor} = state.activation_owner

    case Activation.helper_result(attempt, token, coordinator) do
      :ok -> :ok
      {:error, :unknown_helper_result} -> :ok
      {:error, reason} -> exit({:activation_failed, reason})
    end

    state
  end

  defp activation_event({:resolve, attempt, request, waiter, message}, state) do
    if activation_claim?(state, attempt, request, waiter) do
      state = %{state | policy_snapshot: Policy.snapshot()}
      {coordinator, _epoch, _monitor} = state.activation_owner
      # A failure/cancellation may have been ordered ahead of this queued event.
      # Its original metadata cannot acknowledge that terminal decision away.
      case Activation.waiter(attempt, request, coordinator) do
        {:ok, current} ->
          case activation_waiter_refusal(current, message, state) do
            nil ->
              {destination, context} =
                context(message, state.peers[current.caller].credentials, current.caller)

              target =
                if current.kind == :explicit,
                  do: NameRegistry.resolve(current.destination),
                  else: destination

              case target do
                {:ok, _pid} ->
                  complete_activation_start(attempt, request, current, message, state)

                {:peer, pid, _names} ->
                  forward_activation(attempt, request, current, message, pid, context, state)

                _ ->
                  activation_result!(Activation.finish(attempt, request, :retry, coordinator))
                  state
              end

            reason ->
              activation_result!(
                Activation.finish(attempt, request, {:terminal, reason}, coordinator)
              )

              state
          end

        {:error, :unknown_waiter} ->
          state

        {:error, reason} ->
          exit({:activation_failed, reason})
      end
    else
      state
    end
  end

  defp activation_event({:terminal, attempt, request, waiter, message, reason}, state) do
    if activation_claim?(state, attempt, request, waiter) do
      next = remove_activation_claim(state, waiter)

      if current_activation_caller?(waiter, next) and reason != :caller_down,
        do: activation_error(message, waiter.caller, reason, next),
        else: next
    else
      state
    end
  end

  defp activation_event(_event, state), do: state

  defp issue_systemd(definition, owner, state) do
    {coordinator, _epoch, _monitor} = state.activation_owner
    {serial, state} = next_serial(state)

    result =
      with {:ok, ^owner} <- systemd_owner(state),
           {:ok, signal} <- Systemd.request(definition.unit, serial),
           {:ok, credentials} <- daemon_credentials(state) do
        {target, context} = context(signal, credentials, :bus)

        case {target, Policy.authorize(state.policy_snapshot, :send, context)} do
          {{:peer, pid, _names}, {:allow, _}} -> deliver(signal, pid, context, state)
          _ -> {:error, :denied}
        end
      else
        _ -> {:error, :backend_unavailable}
      end

    case result do
      :ok ->
        :ok

      {:error, reason} ->
        activation_result!(Activation.systemd_failure(definition.unit, reason, coordinator))
    end

    state
  end

  defp activation_claim?(state, attempt, request, waiter) do
    {_epoch, _incarnation, serial} = waiter.serial

    case state.activation_claims[{waiter.caller, serial}] do
      %{attempt: ^attempt, request: ^request, incarnation: incarnation} ->
        incarnation == waiter.caller_incarnation

      _ ->
        false
    end
  end

  defp current_activation_caller?(waiter, state) do
    case state.peers[waiter.caller] do
      %{monitor_ref: monitor, unique_name: name} -> {monitor, name} == waiter.caller_incarnation
      _ -> false
    end
  end

  defp activation_authorized?(waiter, message, state) do
    if current_activation_caller?(waiter, state) do
      credentials = state.peers[waiter.caller].credentials
      {_destination, context} = context(message, credentials, waiter.caller)
      action = if waiter.kind == :explicit, do: :activate, else: :send

      context =
        if waiter.kind == :explicit,
          do: Map.merge(context, %{control: :start_service, name: waiter.destination}),
          else: context

      match?({:allow, _}, Policy.authorize(state.policy_snapshot, action, context)) and
        capability_send(credentials, message) == :allow
    else
      false
    end
  end

  defp activation_waiter_refusal(waiter, message, state) do
    cond do
      Map.get(waiter, :pending_terminal) != nil -> waiter.pending_terminal
      not current_activation_caller?(waiter, state) -> :caller_down
      waiter.deadline <= now_ms() -> :timed_out
      not activation_authorized?(waiter, message, state) -> :denied
      true -> nil
    end
  end

  defp complete_activation_start(attempt, request, waiter, message, state) do
    {coordinator, _epoch, _monitor} = state.activation_owner
    {reply, state} = GaoBus.BusInterface.activation_reply(message, 1, state)
    next = deliver_bus_reply(message, waiter.caller, reply, state)
    activation_result!(Activation.finish(attempt, request, :delivered, coordinator))
    remove_activation_claim(next, waiter)
  end

  defp forward_activation(attempt, request, waiter, message, target, context, state) do
    {coordinator, _epoch, _monitor} = state.activation_owner
    context = Map.put(context, :source_token, {:activation, waiter.lease, request})

    pending =
      if message.type == :method_call and reply_expected?(message),
        do:
          PendingCalls.add(
            state.pending,
            message,
            waiter.caller,
            target,
            context.credentials.uid,
            now_ms()
          ),
        else: {:ok, state.pending}

    with {:ok, candidate} <- pending, :ok <- deliver(message, target, context, state) do
      next = schedule_pending(%{state | pending: candidate}) |> remove_activation_claim(waiter)
      activation_result!(Activation.finish(attempt, request, :delivered, coordinator))
      next
    else
      {:error, reason} ->
        activation_result!(Activation.finish(attempt, request, {:terminal, reason}, coordinator))
        state
    end
  end

  defp remove_activation_claim(state, waiter) do
    {_epoch, _incarnation, serial} = waiter.serial
    %{state | activation_claims: Map.delete(state.activation_claims, {waiter.caller, serial})}
  end

  defp activation_error(message, peer, {:backend_error, name, text}, state),
    do: error_reply(message, peer, name, text, state)

  defp activation_error(message, peer, {:backend_failed, status}, state) do
    {:error, %{error_name: name, error_text: text}} = Helper.status(status)
    error_reply(message, peer, name, text, state)
  end

  defp activation_error(message, peer, reason, state) do
    {name, text} =
      case reason do
        :service_unknown ->
          {"ServiceUnknown", "The destination has no activatable service"}

        reason when reason in [:timed_out, :activation_expired] ->
          {"TimedOut", "Service activation timed out"}

        :denied ->
          {"AccessDenied", "Operation denied by current bus policy"}

        :receive_denied ->
          {"AccessDenied", "Operation denied by current bus policy"}

        :duplicate_serial ->
          {"AccessDenied", "Duplicate outstanding call serial"}

        :unix_fd_not_negotiated ->
          {"NotSupported", "Destination did not negotiate Unix FDs"}

        reason when reason in [:limits_exceeded, :control_capacity] ->
          {"LimitsExceeded", "Activation admission limit exceeded"}

        {:limit_exceeded, _, _} ->
          {"LimitsExceeded", "Activation admission limit exceeded"}

        {:xml_limit_exceeded, _} ->
          {"LimitsExceeded", "Activation admission limit exceeded"}

        :definition_changed ->
          {"Failed", "Service definition changed; retry after the earlier attempt resolves"}

        :attempt_unresolved ->
          {"Failed", "Earlier service attempt remains unresolved; retry later"}

        {:backend_signaled, _signal} ->
          {"Spawn.ChildSignaled", "Launch helper was terminated by a signal"}

        {:not_started, _stage, _errno} ->
          {"Spawn.FailedToSetup", "Launch helper could not be started"}

        {:exec_failed, _stage, _errno} ->
          {"Spawn.ExecFailed", "Launch helper could not be executed"}

        {:observation_lost, _reason} ->
          {"Failed", "Launch helper observation was lost; its child may still be running"}

        _ ->
          {"Failed", "Service activation failed"}
      end

    error_reply(message, peer, @bus <> ".Error." <> name, text, state)
  end

  defp systemd_owner(state) do
    with {:ok, pid} <- NameRegistry.resolve(@systemd),
         %{monitor_ref: monitor, unique_name: name} when is_binary(name) <- state.peers[pid] do
      {:ok, {pid, {monitor, name}}}
    else
      _ -> :missing
    end
  end

  defp daemon_credentials(state) do
    case Policy.configuration(state.policy_snapshot) do
      {:ok, %{daemon_uid: uid}} when is_integer(uid) -> {:ok, %{uid: uid}}
      _ -> {:error, :policy_unavailable}
    end
  end

  defp systemd_failure(
         message,
         peer,
         context,
         %{
           activation_owner: {coordinator, epoch, _monitor},
           activation_options: %{mode: mode}
         } = state
       )
       when mode in [:systemd, :systemd_helper] do
    with {:ok, {owner, incarnation}} <- systemd_owner(state),
         {:ok, credentials} <- daemon_credentials(state),
         %{monitor_ref: monitor, unique_name: name} <- state.peers[peer],
         {:allow, _} <-
           Policy.authorize(state.policy_snapshot, :receive, %{context | credentials: credentials}),
         {:ok, failure} <-
           Systemd.failure(message, %{
             systemd_mode: true,
             epoch: epoch,
             current_epoch: epoch,
             current_owner: owner,
             current_owner_incarnation: incarnation,
             peer: peer,
             peer_incarnation: {monitor, name},
             uid: context.credentials.uid,
             daemon_uid: credentials.uid,
             authorized: true,
             container_checked: true,
             container: false
           }) do
      reason = {:backend_error, failure.error_name, failure.error_text}
      activation_result!(Activation.systemd_failure(failure.unit, reason, coordinator))
    else
      _ -> :ok
    end

    state
  end

  defp systemd_failure(_message, _peer, _context, state), do: state

  defp activation_result!(:ok), do: :ok
  defp activation_result!({:ok, _result}), do: :ok
  defp activation_result!({:error, reason}), do: exit({:activation_failed, reason})

  defp deliver_bus_reply(msg, peer, reply, state) do
    # The reference daemon always returns the registration identity for Hello,
    # including a Hello carrying NO_REPLY_EXPECTED.
    if reply && (reply_expected?(msg) or msg.member == "Hello") do
      case {msg.member, state.peers[peer], reply} do
        {"Hello", %{unique_name: nil},
         %Message{
           type: :error,
           sender: @bus,
           error_name: "org.freedesktop.DBus.Error.LimitsExceeded",
           destination: nil,
           fds: []
         }} ->
          # Admission failure cannot yet address a unique name. Return only this
          # bounded bus diagnostic to the authenticated Hello caller.
          enqueue(reply, peer, false, nil, state.max_output_bytes)

        _ ->
          deliver(reply, peer, bus_context(reply), state)
      end
    end

    state
  end

  defp complete_reload(waiter, result, state) do
    registration =
      case state.peers[waiter.peer] do
        %{monitor_ref: reference, unique_name: name} -> {reference, name}
        _ -> nil
      end

    next =
      if registration == waiter.registration do
        next =
          if reply_expected?(waiter.request) do
            {reply, next} = GaoBus.BusInterface.reload_reply(waiter.request, result, state)
            delivery_state = %{next | policy_snapshot: Policy.snapshot()}
            deliver(reply, waiter.peer, bus_context(reply), delivery_state)
            next
          else
            state
          end

        if waiter.route_ack, do: send(waiter.peer, {:route_complete, waiter.route_ack})
        next
      else
        state
      end

    %{next | reload_waiter: nil}
  end

  defp deliver_signal(signal, {:peer, target, _names}, context, state) do
    _ = deliver(signal, target, context, state)
    state
  end

  defp deliver_signal(%Message{destination: nil} = signal, _destination, context, state) do
    case GaoBus.MatchRules.broadcast_cursor(signal, context.sender_names) do
      {:ok, cursor} ->
        fanout = %{
          message: signal,
          context: context,
          cursor: cursor,
          peers: state.peers,
          bytes: nil,
          owner: nil
        }
        %{state | active_fanout: fanout}

      {:error, _reason} -> state
    end
  end

  defp deliver_signal(_signal, _destination, _context, state), do: state

  defp deliver(message, target, context, state) do
    with {:ok, negotiated} <- authorize_recipient(target, context, state) do
      enqueue(
        message,
        target,
        negotiated,
        Map.get(context, :source_token),
        state.max_output_bytes
      )
    end
  end

  defp authorize_recipient(target, context, state) do
    case state.peers[target] do
      %{credentials: credentials, unique_name: name} when is_binary(name) ->
        receive_context = %{context | credentials: credentials}

        case Policy.authorize(state.policy_snapshot, :receive, receive_context) do
          {:allow, _} ->
            {:ok, state.peers[target].unix_fd}

          {:deny, _} ->
            {:error, :receive_denied}
        end

      _ ->
        {:error, :unknown_peer}
    end
  end

  # A bounded, payload-free failure response to the originating connection is
  # allowed even when policy is unavailable; it grants no routing or authority.
  defp reject(message, peer, state),
    do: error_reply(message, peer, @denied, "Operation denied by bus policy", state)

  defp error_reply(message, peer, name, explanation, state) do
    xml_reply? =
      match?({:ok, _, %GaoBus.Policy.XML{}}, state.policy_snapshot) and
        message.type in [:method_return, :error]

    if (message.type == :method_call or xml_reply?) and reply_expected?(message) do
      {serial, state} = next_serial(state)

      reply =
        Message.error(name, message.serial,
          serial: serial,
          destination: message.sender,
          sender: @bus,
          flags: if(xml_reply?, do: 1, else: 0),
          signature: "s",
          body: [explanation]
        )

      enqueue(reply, peer, false, nil, state.max_output_bytes)
      state
    else
      state
    end
  end

  defp reply_expected?(message), do: (message.flags &&& 1) == 0

  defp enqueue(message, target, negotiated, source_token, max_bytes, bytes \\ nil)

  defp enqueue(%{fds: [_ | _]}, _target, false, _source_token, _max_bytes, _bytes),
    do: {:error, :unix_fd_not_negotiated}

  defp enqueue(message, target, _negotiated, source_token, max_bytes, bytes) do
    bytes = bytes || byte_size(Message.encode_message(message))

    with true <- bytes <= max_bytes or {:error, :outbound_message_too_large},
         {:ok, token} <-
           GaoBus.Limits.reserve_egress(
             target,
             bytes,
             length(message.fds),
             GaoBus.Limits,
             source_token
           ) do
      case Resources.duplicate(message.fds) do
        {:ok, handles} ->
          case GaoBus.Limits.bind_egress(token, handles) do
            :ok ->
              send(target, {:send_message, %{message | fds: handles}, {token, now_ms()}})
              :ok

            {:error, reason} ->
              close_resources(handles)
              release_egress(token)
              {:error, reason}
          end

        {:error, reason} ->
          release_egress(token)
          {:error, reason}
      end
    end
  end

  defp release_egress(token) do
    case GaoBus.Limits.release(token) do
      :ok -> :ok
      {:error, :unknown_reservation} -> :ok
      {:error, failure} -> exit({:resource_accounting_failed, failure})
    end
  end

  defp close_resources(handles) do
    case Resources.close(handles) do
      :ok -> :ok
      {:error, reason} -> exit({:resource_cleanup_failed, reason})
    end
  end

  defp requested_reply?(state, %{type: type, reply_serial: serial}, callee, {:peer, caller, _})
       when type in [:method_return, :error],
       do: PendingCalls.requested?(state.pending, caller, callee, serial, now_ms())

  defp requested_reply?(_state, _message, _peer, _destination), do: false

  defp expire_pending(state) do
    {expired, pending} = PendingCalls.expire(state.pending, now_ms())

    fail_pending(
      expired,
      %{state | pending: pending},
      "The destination did not reply before the deadline"
    )
  end

  defp fail_pending([], state, _explanation), do: state

  defp fail_pending(entries, state, explanation),
    do: ordered_control({:failed_pending, entries, explanation}, state)

  defp schedule_pending(%{pending_timer: nil} = state) do
    case PendingCalls.next_deadline(state.pending) do
      deadline when deadline in [nil, :infinity] ->
        state

      deadline ->
        token = make_ref()
        timer = Process.send_after(self(), {:pending_expiry, token}, max(deadline - now_ms(), 0))
        %{state | pending_timer: {timer, token}}
    end
  end

  defp schedule_pending(state), do: state
  defp now_ms, do: System.monotonic_time(:millisecond)

  defp destination_name(%Message{destination: name, type: :method_call}) when name in [nil, @bus],
    do: :bus

  defp destination_name(%Message{destination: name}) when is_binary(name), do: name
  defp destination_name(_message), do: :broadcast

  defp context(message, credentials, source) do
    snapshot = NameRegistry.routing_snapshot(source, destination_name(message))
    {destination, names} = Map.pop(snapshot, :destination)

    {destination,
     Map.merge(names, %{credentials: credentials, message: message, requested_reply: false})}
  end

  defp bus_context(message) do
    {_destination, context} = context(message, %{}, :bus)
    %{context | requested_reply: message.type in [:method_return, :error]}
  end

  defp capability_send(credentials, message) do
    if Application.get_env(:gao_bus, :capability_restrictions, false),
      do: GaoBus.Policy.Capability.check_send(credentials, Map.from_struct(message)),
      else: :allow
  end

  defp next_serial(state) do
    serial = state.next_serial
    {serial, %{state | next_serial: if(serial >= 0xFFFFFFFF, do: 1, else: serial + 1)}}
  end
end
