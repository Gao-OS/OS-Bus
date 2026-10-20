defmodule GaoBus.Limits do
  @moduledoc """
  Finite, monitored admission, frame, ingress and egress reservations.

  Acquire only after credentials have been verified from the socket and policy
  has admitted the connection. This module validates the credential shape; it
  does not authenticate a claimed UID. The owner and its UID remain fixed until
  cleanup. Native authentication credit completes at BEGIN. When XML connection
  limits are supplied, separate incomplete credit remains until successful Hello;
  completed global and UID credit is exchanged atomically before naming. XML
  counters never replace native safety counters. Reserve actual frame bytes
  before placing work in Router's mailbox. Release its token after handling,
  including rejection paths.

  Set an absolute frame budget before receiving, trim it to actual buffered
  bytes/FDs afterwards, and atomically promote complete frames into ingress.
  Ingress tokens survive source DOWN: queued Router work must stay charged until
  its handler releases the token. Otherwise disconnect/reconnect floods bypass
  the queue ceilings. Removed peers retain only these credits in tombstones.
  Connection, authentication, frame and egress credits are reclaimed on DOWN.
  Egress is charged to the recipient until write completion or recipient death.
  Bind independently duplicated egress handles before enqueueing. Bound resources
  are closed before release/DOWN retires their credit, even if another process
  still holds resource terms. Missing accounting never permits work; release and
  binding are exactly once. Failed binding leaves handles with the caller.
  """

  use GenServer

  alias GaoBus.Unix.Resources

  @metrics [
    :connections,
    :authenticating,
    :ingress_messages,
    :ingress_bytes,
    :ingress_fds,
    :egress_messages,
    :egress_bytes,
    :egress_fds,
    :frame_bytes,
    :frame_fds,
    :activation_messages,
    :activation_bytes,
    :activation_fds
  ]
  @empty Map.new(@metrics, &{&1, 0})
  @defaults %{
    global: %{
      connections: 256,
      authenticating: 64,
      ingress_messages: 512,
      ingress_bytes: 4_194_304,
      ingress_fds: 2048,
      egress_messages: 512,
      egress_bytes: 4_194_304,
      egress_fds: 2048,
      frame_bytes: 16_777_216,
      frame_fds: 1024,
      activation_messages: 512,
      activation_bytes: 4_194_304,
      activation_fds: 2048
    },
    uid: %{
      connections: 64,
      authenticating: 16,
      ingress_messages: 128,
      ingress_bytes: 1_048_576,
      ingress_fds: 512,
      egress_messages: 128,
      egress_bytes: 1_048_576,
      egress_fds: 512,
      frame_bytes: 4_194_304,
      frame_fds: 256,
      activation_messages: 128,
      activation_bytes: 1_048_576,
      activation_fds: 512
    },
    peer: %{
      ingress_messages: 32,
      ingress_bytes: 1_048_576,
      ingress_fds: 128,
      egress_messages: 32,
      egress_bytes: 1_048_576,
      egress_fds: 128,
      frame_bytes: 1_048_576,
      frame_fds: 64,
      activation_messages: 32,
      activation_bytes: 1_048_576,
      activation_fds: 128
    }
  }

  @xml_defaults %{
    "max_completed_connections" => 2048,
    "max_incomplete_connections" => 64,
    "max_connections_per_user" => 256,
    "auth_timeout" => 30_000
  }

  @xml_queue_defaults %{
    "max_incoming_bytes" => 133_169_152,
    "max_incoming_unix_fds" => 64,
    "max_outgoing_bytes" => 133_169_152,
    "max_outgoing_unix_fds" => 64
  }

  def defaults, do: @defaults

  @doc "Validate the connection subset of original XML limit names, preserving zero."
  def connection_limits(nil), do: {:ok, nil}

  def connection_limits(values) when is_map(values) do
    connection = Map.take(values, Map.keys(@xml_defaults))

    if Enum.all?(connection, fn {_name, value} -> is_integer(value) and value in 0..0x7FFFFFFF end),
       do: {:ok, Map.merge(@xml_defaults, connection)},
       else: {:error, :invalid_xml_connection_limits}
  end

  def connection_limits(_values), do: {:error, :invalid_xml_connection_limits}

  defp queue_limits(nil), do: {:ok, nil}

  defp queue_limits(values) when is_map(values) do
    queues = Map.take(values, Map.keys(@xml_queue_defaults))

    if Enum.all?(queues, fn {_name, value} ->
         is_integer(value) and value in 0..0x7FFFFFFFFFFFFFFF
       end),
       do: {:ok, Map.merge(@xml_queue_defaults, queues)},
       else: {:error, :invalid_xml_queue_limits}
  end

  defp queue_limits(_values), do: {:error, :invalid_xml_queue_limits}

  defp pending_starts_limit(nil), do: {:ok, 512}

  defp pending_starts_limit(values) when is_map(values) do
    value = Map.get(values, "max_pending_service_starts", 512)

    if is_integer(value) and value in 0..0x7FFFFFFF,
      do: {:ok, value},
      else: {:error, :invalid_xml_activation_limit}
  end

  defp pending_starts_limit(_values), do: {:error, :invalid_xml_activation_limit}

  def start_link(opts \\ []) do
    with {:ok, limits} <- validate_limits(Keyword.get(opts, :limits, %{})),
         {:ok, xml_limits} <- connection_limits(Keyword.get(opts, :xml_limits)),
         {:ok, xml_queues} <- queue_limits(Keyword.get(opts, :xml_limits)),
         {:ok, pending_starts} <- pending_starts_limit(Keyword.get(opts, :xml_limits)) do
      case Keyword.get(opts, :name, __MODULE__) do
        nil ->
          GenServer.start_link(__MODULE__, {limits, xml_limits, xml_queues, pending_starts})

        name ->
          GenServer.start_link(__MODULE__, {limits, xml_limits, xml_queues, pending_starts},
            name: name
          )
      end
    else
      {:error, reason} -> {:error, {:invalid_limits, reason}}
    end
  end

  def acquire(pid, credentials, server \\ __MODULE__),
    do: call(server, {:acquire, pid, credentials})

  @doc false
  def peer_identity(pid, server \\ __MODULE__), do: call(server, {:peer_identity, pid})

  @doc "Atomically exchange XML incomplete credit for completed global and UID credit."
  def hello_completed(pid, server \\ __MODULE__, deadline \\ nil),
    do: call(server, {:hello_completed, pid, deadline})

  @doc "Observe incomplete capacity; callers must serialize accept and admission."
  def accept_ready(observer, server \\ __MODULE__), do: call(server, {:accept_ready, observer})

  def unsubscribe_accept(observer, server \\ __MODULE__),
    do: call(server, {:unsubscribe_accept, observer})

  def auth_completed(pid, server \\ __MODULE__), do: call(server, {:auth_completed, pid})

  def reserve_ingress(pid, bytes, server \\ __MODULE__),
    do: reserve_ingress_fds(pid, bytes, 0, server)

  def reserve_ingress_fds(pid, bytes, fds, server \\ __MODULE__),
    do: call(server, {:reserve, :ingress, pid, bytes, fds})

  def reserve_egress(pid, bytes, fds, server \\ __MODULE__, source_token \\ nil),
    do: call(server, {:reserve, :egress, pid, bytes, fds, source_token})

  @doc "Pause XML input at its live-message threshold; retirement wakes the peer once."
  def ingress_ready(pid, server \\ __MODULE__), do: call(server, {:ingress_ready, pid})

  @doc "Attach exclusive delivery handles to an active egress token exactly once."
  def bind_egress(token, handles, server \\ __MODULE__),
    do: call(server, {:bind_egress, token, handles})

  def set_frame(pid, bytes, fds, server \\ __MODULE__),
    do: call(server, {:set_frame, pid, bytes, fds})

  def promote_frame(pid, bytes, fds, server \\ __MODULE__),
    do: call(server, {:promote_frame, pid, bytes, fds})

  def release(token, server \\ __MODULE__), do: call(server, {:release, token})
  def release_peer(pid, server \\ __MODULE__), do: call(server, {:release_peer, pid})
  def snapshot(server \\ __MODULE__), do: call(server, :snapshot)

  @doc "Own independent message descriptors and pin causal ingress before activation enqueue."
  def reserve_activation(ingress, identity, bytes, originals, coordinator, server \\ __MODULE__),
    do: call(server, {:reserve_activation, ingress, identity, bytes, originals, coordinator})

  @doc "Only the exact coordinator can claim a request's independently owned descriptors."
  def claim_activation(lease, request_key, server \\ __MODULE__),
    do: call(server, {:claim_activation, lease, request_key})

  @doc "Discard admitted body credit only after coordinator drain, closing descriptors first."
  def release_activation(lease, request_key, server \\ __MODULE__),
    do: call(server, {:release_activation, lease, request_key})

  @doc "Reserve the single reload job before enqueueing preparation; owner is the authority PID."
  def reserve_reload(owner, timeout_ms, server \\ __MODULE__),
    do: call(server, {:reserve_reload, owner, timeout_ms})

  @doc "The exact authority claims one admitted job before starting its worker."
  def claim_reload(token, owner, server \\ __MODULE__),
    do: call(server, {:claim_reload, token, owner})

  @doc "Retire reload credit only after preparation drains; stale references are harmless."
  def release_reload(token, server \\ __MODULE__), do: call(server, {:release_reload, token})

  @doc "Reserve/promote and own a Router envelope before its mailbox receives it."
  def enqueue_route(message, pid, bytes, mode, router, server \\ __MODULE__),
    do: call(server, {:enqueue_route, message, pid, bytes, mode, router})

  @doc "Reserve bounded internal work and atomically send it to one monitored authority."
  def enqueue_control(owner, payload, server \\ __MODULE__),
    do: call(server, {:enqueue_control, owner, payload})

  @doc "Reserve internal work that the owner immediately places in its local FIFO."
  def reserve_control(owner, bytes, server \\ __MODULE__),
    do: call(server, {:reserve_control, owner, bytes})

  def release_control(token, server \\ __MODULE__),
    do: call(server, {:release_control, token})

  @doc "Admit one terminal completion before activation effects; producer death cancels only unqueued work."
  def reserve_terminal(owner, bytes, server \\ __MODULE__),
    do: call(server, {:reserve_terminal, owner, bytes})

  def enqueue_terminal(token, payload, server \\ __MODULE__),
    do: call(server, {:enqueue_terminal, token, payload})

  def cancel_terminal(token, server \\ __MODULE__),
    do: call(server, {:cancel_terminal, token})

  defp call(server, message) do
    GenServer.call(server, message, 5000)
  catch
    :exit, _reason -> {:error, :accounting_unavailable}
  end

  @impl true
  def init({limits, xml_limits, xml_queues, pending_starts}),
    do:
      {:ok,
       %{
         limits: limits,
         xml_limits: xml_limits,
         xml_queues: xml_queues,
         pending_starts_limit: pending_starts,
         xml_global: %{incomplete: 0, completed: 0},
         xml_uids: %{},
         accept_observers: %{},
         global: @empty,
         uids: %{},
         peers: %{},
         retired: %{},
         reservations: %{},
         bound_handles: %{},
         reload: nil,
         control: %{count: 0, bytes: 0, dropped: 0, entries: %{}}
       }}

  @impl true
  def handle_call({:enqueue_route, message, pid, bytes, mode, router}, {reserver, _}, state) do
    fds = length(message.fds)

    with true <- mode in [:route, :frame] or {:error, :invalid_route_mode},
         true <- local_live_peer?(pid) and local_live_peer?(router) or {:error, :route_unavailable},
         :ok <- validate_reservation(state, pid, bytes, fds, :ingress),
         :ok <- handoff_frame(state, pid, bytes, fds, mode),
         changes = reservation_changes(:ingress, bytes, fds),
         capacity_changes = handoff_changes(changes, bytes, fds, mode),
         :ok <- peer_capacity(state, pid, capacity_changes),
         :ok <- xml_queue_capacity(state, pid, :ingress),
         :ok <- validate_handles(message.fds, fds),
         {:ok, handles} <- Resources.duplicate(message.fds) do
      state =
        if mode == :frame,
          do: update_usage(state, pid, %{frame_bytes: -bytes, frame_fds: -fds}),
          else: state

      {token, state} = put_reservation(state, pid, :ingress, changes)

      reservation = Map.merge(state.reservations[token], %{
        owner: router,
        owner_monitor: Process.monitor(router),
        reserver: reserver,
        enqueued: true,
        handles: handles
      })

      state = %{state |
        reservations: Map.put(state.reservations, token, reservation),
        bound_handles: Enum.reduce(handles, state.bound_handles, &Map.put(&2, &1, token))
      }

      send(router, {:owned_route, %{message | fds: handles}, pid, token, bytes, mode})
      {:reply, {:ok, token}, state}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:enqueue_control, owner, payload}, _from, state) do
    case put_control(state, owner, :erlang.external_size(payload)) do
      {:ok, token, next} ->
        send(owner, {:control_work, token, payload})
        {:reply, {:ok, token}, next}

      error -> {:reply, error, control_refusal(state, error)}
    end
  end

  def handle_call({:reserve_control, owner, bytes}, {caller, _}, state) do
    if caller == owner do
      case put_control(state, owner, bytes) do
        {:ok, token, next} -> {:reply, {:ok, token}, next}
        error -> {:reply, error, control_refusal(state, error)}
      end
    else
      {:reply, {:error, :control_not_owner}, state}
    end
  end

  def handle_call({:release_control, token}, {caller, _}, state) do
    case state.control.entries[token] do
      %{owner: ^caller} -> {:reply, :ok, retire_control(state, token)}
      nil -> {:reply, {:error, :unknown_control_reservation}, state}
      _ -> {:reply, {:error, :control_not_owner}, state}
    end
  end

  def handle_call({:reserve_terminal, owner, bytes}, {producer, _}, state) do
    case put_control(state, owner, bytes) do
      {:ok, token, next} ->
        entry = Map.merge(next.control.entries[token], %{
          producer: producer,
          producer_monitor: Process.monitor(producer),
          enqueued: false
        })
        {:reply, {:ok, token}, put_in(next.control.entries[token], entry)}
      error -> {:reply, error, control_refusal(state, error)}
    end
  end

  def handle_call({:enqueue_terminal, token, payload}, {producer, _}, state) do
    case state.control.entries[token] do
      %{producer: ^producer, enqueued: false, bytes: bytes} = entry ->
        if :erlang.external_size(payload) <= bytes do
          Process.demonitor(entry.producer_monitor, [:flush])
          entry = entry |> Map.delete(:producer_monitor) |> Map.put(:enqueued, true)
          send(entry.owner, {:control_work, token, payload})
          {:reply, :ok, put_in(state.control.entries[token], entry)}
        else
          {:reply, {:error, :terminal_envelope_too_large}, state}
        end
      _ -> {:reply, {:error, :invalid_terminal_reservation}, state}
    end
  end

  def handle_call({:cancel_terminal, token}, {producer, _}, state) do
    case state.control.entries[token] do
      %{producer: ^producer, enqueued: false} ->
        {:reply, :ok, retire_control(state, token)}
      %{producer: ^producer, enqueued: true} ->
        # Ownership already moved to the Router; producer shutdown cannot retire
        # its queued bytes or make a reconnect churn past the control ceiling.
        {:reply, :ok, state}
      nil -> {:reply, :ok, state}
      _ -> {:reply, {:error, :control_not_producer}, state}
    end
  end

  def handle_call({:reserve_reload, owner, timeout_ms}, _from, state) do
    cond do
      not local_live_peer?(owner) ->
        {:reply, {:error, :invalid_reload_owner}, state}

      not (is_integer(timeout_ms) and timeout_ms in 1..60_000) ->
        {:reply, {:error, :invalid_reload_timeout}, state}

      state.reload != nil ->
        {:reply, {:error, :reload_busy}, state}

      true ->
        token = make_ref()

        reload = %{
          token: token,
          owner: owner,
          monitor: Process.monitor(owner),
          deadline: System.monotonic_time(:millisecond) + timeout_ms,
          timer: Process.send_after(self(), {:reload_expiry, token}, timeout_ms),
          claimed: false,
          expired: false
        }

        {:reply, {:ok, token}, %{state | reload: reload}}
    end
  end

  def handle_call({:claim_reload, token, owner}, {caller, _tag}, state) do
    case state.reload do
      %{token: ^token} = reload ->
        cond do
          owner != reload.owner or caller != owner ->
            {:reply, {:error, :reload_not_owner}, state}

          reload.expired or System.monotonic_time(:millisecond) >= reload.deadline ->
            {:reply, {:error, :reload_timeout}, state}

          reload.claimed ->
            {:reply, {:error, :reload_already_claimed}, state}

          true ->
            {:reply, {:ok, reload.deadline}, put_in(state.reload.claimed, true)}
        end

      _ ->
        {:reply, {:error, :unknown_reload_reservation}, state}
    end
  end

  def handle_call({:release_reload, token}, {caller, _tag}, state) do
    case state.reload do
      %{token: ^token, owner: ^caller} ->
        {:reply, :ok, retire_reload(state)}

      %{token: ^token} ->
        {:reply, {:error, :reload_not_owner}, state}

      _ ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:acquire, pid, credentials}, _from, state) do
    cond do
      not local_live_peer?(pid) ->
        {:reply, {:error, :invalid_peer}, state}

      not valid_credentials?(credentials) ->
        {:reply, {:error, :invalid_credentials}, state}

      Map.has_key?(state.peers, pid) or Map.has_key?(state.retired, pid) ->
        {:reply, {:error, :already_acquired}, state}

      true ->
        uid = credentials.uid
        changes = %{connections: 1, authenticating: 1}
        uid_counts = Map.get(state.uids, uid, @empty)

        with :ok <- xml_incomplete_capacity(state),
             :ok <- capacity(uid_counts, state.limits.uid, changes, :uid),
             :ok <- capacity(state.global, state.limits.global, changes, :global) do
          peer = %{
            uid: uid,
            monitor: Process.monitor(pid),
            counts: @empty,
            tokens: MapSet.new(),
            ingress_waiting: false,
            xml_completed: false
          }

          state = %{
            state
            | peers: Map.put(state.peers, pid, peer),
              uids: Map.put(state.uids, uid, uid_counts)
          }

          {:reply, :ok, state |> update_usage(pid, changes) |> xml_acquired()}
        else
          error -> {:reply, error, state}
        end
    end
  end

  def handle_call({:peer_identity, pid}, _from, state) do
    case state.peers[pid] do
      %{uid: uid, monitor: admission} ->
        if local_live_peer?(pid),
          do: {:reply, {:ok, %{uid: uid, admission: admission}}, state},
          else: {:reply, {:error, :unknown_peer}, state}

      nil ->
        {:reply, {:error, :unknown_peer}, state}
    end
  end

  def handle_call({:auth_completed, pid}, _from, state) do
    case state.peers[pid] do
      nil -> {:reply, {:error, :unknown_peer}, state}
      %{counts: %{authenticating: 0}} -> {:reply, {:error, :already_authenticated}, state}
      _peer -> {:reply, :ok, update_usage(state, pid, %{authenticating: -1})}
    end
  end

  def handle_call({:hello_completed, _pid, _deadline}, _from, %{xml_limits: nil} = state),
    do: {:reply, :ok, state}

  def handle_call({:hello_completed, pid, deadline}, _from, state) do
    case state.peers[pid] do
      nil ->
        {:reply, {:error, :unknown_peer}, state}

      %{xml_completed: true} ->
        {:reply, {:error, :already_completed}, state}

      peer ->
        with :ok <- hello_before_deadline(deadline),
             :ok <- xml_completed_capacity(state, peer.uid) do
          state = put_in(state.peers[pid].xml_completed, true)

          state = %{
            state
            | xml_global: %{
                incomplete: state.xml_global.incomplete - 1,
                completed: state.xml_global.completed + 1
              },
              xml_uids: Map.update(state.xml_uids, peer.uid, 1, &(&1 + 1))
          }

          {:reply, :ok, notify_accept(state)}
        else
          error -> {:reply, error, state}
        end
    end
  end

  def handle_call({:accept_ready, observer}, _from, state) do
    state =
      if Map.has_key?(state.accept_observers, observer),
        do: state,
        else: %{
          state
          | accept_observers: Map.put(state.accept_observers, observer, Process.monitor(observer))
        }

    {:reply, xml_incomplete_capacity(state), state}
  end

  def handle_call({:unsubscribe_accept, observer}, _from, state),
    do: {:reply, :ok, remove_accept_observer(state, observer)}

  def handle_call(
        {:reserve_activation, ingress, identity, bytes, originals, coordinator},
        {reserver, _tag},
        state
      ) do
    with :ok <- activation_owner(coordinator),
         {:ok, pid, request_key} <- activation_identity(identity),
         :ok <- validate_activation_source(state, ingress, pid, bytes, originals),
         :ok <- unique_activation_request(state, request_key),
         :ok <- activation_capacity(state),
         changes = %{
           activation_messages: 1,
           activation_bytes: bytes,
           activation_fds: length(originals)
         },
         :ok <- peer_capacity(state, pid, changes),
         :ok <- validate_handles(originals, length(originals)),
         {:ok, copies} <- Resources.duplicate(originals) do
      {token, state} = put_reservation(state, pid, :activation, changes)

      reservation =
        Map.merge(state.reservations[token], %{
          request_key: request_key,
          caller_incarnation: identity.caller_incarnation,
          peer_monitor: state.peers[pid].monitor,
          deadline: identity.deadline,
          owner: coordinator,
          owner_monitor: Process.monitor(coordinator),
          reserver: reserver,
          claimed: false,
          cancelled: false,
          handles: copies,
          source_token: ingress
        })

      state = %{
        state
        | reservations: Map.put(state.reservations, token, reservation),
          bound_handles: Enum.reduce(copies, state.bound_handles, &Map.put(&2, &1, token))
      }

      state = pin_source(state, ingress)
      {:reply, {:ok, token}, state}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:claim_activation, token, request_key}, {caller, _tag}, state) do
    with {:ok, lease} <- activation_lease(state, token, request_key, caller),
         :ok <- live_activation(lease),
         false <- lease.claimed do
      {:reply, {:ok, lease.handles}, put_in(state.reservations[token].claimed, true)}
    else
      true -> {:reply, {:error, :activation_already_claimed}, state}
      error -> {:reply, error, state}
    end
  end

  def handle_call({:release_activation, token, request_key}, {caller, _tag}, state) do
    with {:ok, _lease} <- activation_lease(state, token, request_key, caller),
         {:ok, next} <- release_reservation(state, token) do
      {:reply, :ok, next}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:reserve, kind, pid, bytes, fds}, _from, state) do
    with :ok <- validate_reservation(state, pid, bytes, fds, kind),
         changes = reservation_changes(kind, bytes, fds),
         :ok <- peer_capacity(state, pid, changes),
         :ok <- xml_queue_capacity(state, pid, kind) do
      {token, state} = put_reservation(state, pid, kind, changes)
      {:reply, {:ok, token}, state}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:reserve, :egress, pid, bytes, fds, source_token}, {caller, _tag}, state) do
    with :ok <- validate_reservation(state, pid, bytes, fds, :egress),
         changes = reservation_changes(:egress, bytes, fds),
         :ok <- peer_capacity(state, pid, changes),
         :ok <- xml_queue_capacity(state, pid, :egress),
         {:ok, source_token} <- egress_source(state, source_token, caller) do
      {token, state} = put_reservation(state, pid, :egress, changes)

      state =
        if source_token do
          state
          |> put_in([:reservations, token, :source_token], source_token)
          |> pin_source(source_token)
        else
          state
        end

      {:reply, {:ok, token}, state}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:ingress_ready, pid}, _from, state) do
    case state.peers[pid] do
      nil ->
        {:reply, {:error, :unknown_peer}, state}

      _ ->
        case xml_queue_capacity(state, pid, :ingress) do
          :ok -> {:reply, :ok, put_in(state.peers[pid].ingress_waiting, false)}
          error -> {:reply, error, put_in(state.peers[pid].ingress_waiting, true)}
        end
    end
  end

  def handle_call({:set_frame, pid, bytes, fds}, _from, state) do
    with :ok <- validate_reservation(state, pid, bytes, fds, :frame),
         counts = state.peers[pid].counts,
         changes = %{frame_bytes: bytes - counts.frame_bytes, frame_fds: fds - counts.frame_fds},
         :ok <- peer_capacity(state, pid, changes) do
      {:reply, :ok, update_usage(state, pid, changes)}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:bind_egress, token, handles}, _from, state) do
    with {:ok, reservation} <- bindable_reservation(state, token),
         :ok <- validate_handles(handles, reservation.changes.egress_fds),
         :ok <- exclusive_handles(state, handles) do
      reservation = Map.put(reservation, :handles, handles)
      owned = Enum.reduce(handles, state.bound_handles, &Map.put(&2, &1, token))

      {:reply, :ok,
       %{
         state
         | reservations: Map.put(state.reservations, token, reservation),
           bound_handles: owned
       }}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:promote_frame, pid, bytes, fds}, _from, state) do
    with :ok <- validate_reservation(state, pid, bytes, fds, :ingress),
         :ok <- frame_reserved(state.peers[pid].counts, bytes, fds),
         ingress = reservation_changes(:ingress, bytes, fds),
         changes = Map.merge(ingress, %{frame_bytes: -bytes, frame_fds: -fds}),
         :ok <- peer_capacity(state, pid, changes),
         :ok <- xml_queue_capacity(state, pid, :ingress) do
      state = update_usage(state, pid, %{frame_bytes: -bytes, frame_fds: -fds})
      {token, state} = put_reservation(state, pid, :ingress, ingress)
      {:reply, {:ok, token}, state}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:release, token}, {caller, _}, state) do
    case state.reservations[token] do
      nil ->
        {:reply, {:error, :unknown_reservation}, state}

      %{kind: :activation} ->
        {:reply, {:error, :activation_requires_owner}, state}

      %{kind: :ingress, owner: owner} when owner != caller ->
        {:reply, {:error, :ingress_not_owner}, state}

      %{release_requested: true} ->
        {:reply, {:error, :unknown_reservation}, state}

      %{kind: :ingress, output_refs: refs} when refs > 0 ->
        # The received message remains live while any forwarded output owns it.
        {:reply, :ok, finish_owned_ingress(state, token)}

      _reservation ->
        case release_reservation(state, token) do
          {:ok, next} -> {:reply, :ok, next}
          {:error, reason} -> {:reply, {:error, reason}, state}
        end
    end
  end

  def handle_call({:release_peer, pid}, _from, state) do
    if Map.has_key?(state.peers, pid) do
      {:reply, :ok, remove_peer(state, pid)}
    else
      {:reply, {:error, :unknown_peer}, state}
    end
  end

  def handle_call(:snapshot, _from, state) do
    snapshot = %{
      global: state.global,
      uids: state.uids,
      peers: Map.new(state.peers, fn {pid, peer} -> {pid, peer.counts} end),
      reservations: map_size(state.reservations),
      reload_reservations: if(state.reload, do: 1, else: 0),
      control: Map.take(state.control, [:count, :bytes]),
      control_dropped: state.control.dropped,
      limits: state.limits,
      xml: %{
        limits: state.xml_limits,
        queues: state.xml_queues,
        global: state.xml_global,
        uids: state.xml_uids
      }
    }

    {:reply, {:ok, snapshot}, state}
  end

  @impl true
  def handle_info({:reload_expiry, token}, %{reload: %{token: token, expired: false}} = state) do
    remaining = state.reload.deadline - System.monotonic_time(:millisecond)

    if remaining > 0 do
      timer = Process.send_after(self(), {:reload_expiry, token}, remaining)
      {:noreply, put_in(state.reload.timer, timer)}
    else
      # Expiry refuses late admission, but cannot establish cancellation of a
      # running worker. The coordinator retains credit until actual worker DOWN.
      send(state.reload.owner, {:reload_timeout, token})
      {:noreply, %{state | reload: %{state.reload | expired: true, timer: nil}}}
    end
  end

  def handle_info(
        {:DOWN, monitor, :process, owner, _reason},
        %{reload: %{monitor: monitor, owner: owner}} = state
      ),
      do: {:noreply, retire_reload(state)}

  def handle_info({:DOWN, monitor, :process, pid, _reason}, state) do
    state =
      Enum.reduce(state.control.entries, state, fn {token, entry}, state ->
        owner_down = entry.monitor == monitor and entry.owner == pid
        producer_down = Map.get(entry, :producer_monitor) == monitor and
                          Map.get(entry, :producer) == pid
        if owner_down or producer_down, do: retire_control(state, token), else: state
      end)

    state =
      Enum.reduce(state.reservations, state, fn {token, reservation}, state ->
        if reservation.kind == :ingress and Map.get(reservation, :owner_monitor) == monitor and
             Map.get(reservation, :owner) == pid do
          finish_owned_ingress(state, token)
        else
          state
        end
      end)

    lease =
      Enum.find(state.reservations, fn {_token, reservation} ->
        reservation.kind == :activation and reservation.owner == pid and
          reservation.owner_monitor == monitor
      end)

    case lease do
      {token, _reservation} ->
        case release_reservation(state, token) do
          {:ok, next} -> {:noreply, next}
          {:error, reason} -> exit(reason)
        end

      nil ->
        case state.peers[pid] do
          %{monitor: ^monitor} ->
            {:noreply, remove_peer(state, pid)}

          _ ->
            if state.accept_observers[pid] == monitor,
              do: {:noreply, remove_accept_observer(state, pid)},
              else: {:noreply, state}
        end
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  # Each internal item has one count and byte lease. No client/activation
  # budget is borrowed; refusal happens before a mailbox/FIFO receives payload.
  defp put_control(state, owner, bytes) do
    cond do
      not local_live_peer?(owner) -> {:error, :control_owner_unavailable}
      not (is_integer(bytes) and bytes > 0) -> {:error, :invalid_control_bytes}
      state.control.count >= 512 or state.control.bytes + bytes > 4_194_304 ->
        {:error, :control_capacity}
      true ->
        token = make_ref()
        entry = %{owner: owner, monitor: Process.monitor(owner), bytes: bytes}
        control = %{state.control |
          count: state.control.count + 1,
          bytes: state.control.bytes + bytes,
          entries: Map.put(state.control.entries, token, entry)
        }
        {:ok, token, %{state | control: control}}
    end
  end

  defp control_refusal(state, {:error, :control_capacity}),
    do: update_in(state.control.dropped, &min(&1 + 1, 0xFFFFFFFFFFFFFFFF))
  defp control_refusal(state, _error), do: state

  defp retire_control(state, token) do
    entry = Map.fetch!(state.control.entries, token)
    Process.demonitor(entry.monitor, [:flush])
    if producer_monitor = Map.get(entry, :producer_monitor),
      do: Process.demonitor(producer_monitor, [:flush])
    control = %{state.control |
      count: state.control.count - 1,
      bytes: state.control.bytes - entry.bytes,
      entries: Map.delete(state.control.entries, token)
    }
    %{state | control: control}
  end

  defp handoff_frame(state, pid, bytes, fds, :frame),
    do: frame_reserved(state.peers[pid].counts, bytes, fds)
  defp handoff_frame(_state, _pid, _bytes, _fds, :route), do: :ok

  defp handoff_changes(changes, bytes, fds, :frame),
    do: Map.merge(changes, %{frame_bytes: -bytes, frame_fds: -fds})
  defp handoff_changes(changes, _bytes, _fds, :route), do: changes

  defp finish_owned_ingress(state, token) do
    reservation = Map.fetch!(state.reservations, token)
    handles = Map.get(reservation, :handles, [])

    case Resources.close(handles) do
      :ok ->
        if monitor = Map.get(reservation, :owner_monitor),
          do: Process.demonitor(monitor, [:flush])

        reservation = reservation
          |> Map.drop([:owner_monitor])
          |> Map.put(:handles, [])
          |> Map.put(:release_requested, true)

        state = %{state |
          reservations: Map.put(state.reservations, token, reservation),
          bound_handles: Map.drop(state.bound_handles, handles)
        }

        if Map.get(reservation, :output_refs, 0) == 0,
          do: retire_reservation(state, token, []),
          else: state

      {:error, reason} -> exit({:resource_cleanup_failed, reason})
    end
  end

  defp retire_reload(state) do
    if state.reload.timer, do: Process.cancel_timer(state.reload.timer)
    Process.demonitor(state.reload.monitor, [:flush])
    %{state | reload: nil}
  end

  defp local_live_peer?(pid),
    do: is_pid(pid) and node(pid) == node() and Process.alive?(pid)

  defp valid_credentials?(%{uid: uid, gid: gid, pid: pid}) do
    is_integer(uid) and uid >= 0 and uid < 0xFFFFFFFF and
      is_integer(gid) and gid >= 0 and gid < 0xFFFFFFFF and
      is_integer(pid) and pid > 0 and pid <= 0x7FFFFFFF
  end

  defp valid_credentials?(_credentials), do: false

  defp capacity(counts, limits, changes, scope) do
    case Enum.find(@metrics, fn metric ->
           Map.has_key?(changes, metric) and counts[metric] + changes[metric] > limits[metric]
         end) do
      nil -> :ok
      metric -> {:error, {:limit_exceeded, scope, metric}}
    end
  end

  defp peer_capacity(state, pid, changes) do
    peer = state.peers[pid]

    with :ok <- capacity(peer.counts, state.limits.peer, changes, :peer),
         :ok <- capacity(state.uids[peer.uid], state.limits.uid, changes, :uid),
         do: capacity(state.global, state.limits.global, changes, :global)
  end

  defp validate_reservation(state, pid, bytes, fds, kind) do
    cond do
      not Map.has_key?(state.peers, pid) ->
        {:error, :unknown_peer}

      not (is_integer(bytes) and (bytes > 0 or (kind == :frame and bytes == 0))) ->
        {:error, invalid_metric(kind, :bytes)}

      not (is_integer(fds) and fds >= 0) ->
        {:error, invalid_metric(kind, :fds)}

      true ->
        :ok
    end
  end

  defp invalid_metric(:ingress, :bytes), do: :invalid_ingress_bytes
  defp invalid_metric(:ingress, :fds), do: :invalid_ingress_fds
  defp invalid_metric(:egress, :bytes), do: :invalid_egress_bytes
  defp invalid_metric(:egress, :fds), do: :invalid_egress_fds
  defp invalid_metric(:frame, :bytes), do: :invalid_frame_bytes
  defp invalid_metric(:frame, :fds), do: :invalid_frame_fds

  defp frame_reserved(counts, bytes, fds) do
    if bytes <= counts.frame_bytes and fds <= counts.frame_fds,
      do: :ok,
      else: {:error, :insufficient_frame_reservation}
  end

  defp reservation_changes(:ingress, bytes, fds),
    do: %{ingress_messages: 1, ingress_bytes: bytes, ingress_fds: fds}

  defp reservation_changes(:egress, bytes, fds),
    do: %{egress_messages: 1, egress_bytes: bytes, egress_fds: fds}

  defp put_reservation(state, pid, kind, changes) do
    token = make_ref()
    state = update_usage(state, pid, changes)
    state = update_in(state.peers[pid].tokens, &MapSet.put(&1, token))
    reservation = %{pid: pid, kind: kind, changes: changes}
    {token, %{state | reservations: Map.put(state.reservations, token, reservation)}}
  end

  defp update_usage(state, pid, changes) do
    owners = if Map.has_key?(state.peers, pid), do: :peers, else: :retired
    uid = state[owners][pid].uid
    state = update_in(state[owners][pid].counts, &adjust(&1, changes))
    state = update_in(state.uids[uid], &adjust(&1, changes))
    %{state | global: adjust(state.global, changes)}
  end

  defp adjust(counts, changes) do
    Enum.reduce(changes, counts, fn {metric, change}, counts ->
      Map.update!(counts, metric, &(&1 + change))
    end)
  end

  defp release_reservation(state, token) do
    handles = Map.get(state.reservations[token], :handles, [])

    case Resources.close(handles) do
      :ok ->
        source = Map.get(state.reservations[token], :source_token)
        state = retire_reservation(state, token, handles)
        {:ok, retire_source_reference(state, source)}

      {:error, reason} ->
        {:error, {:resource_cleanup_failed, reason}}
    end
  end

  defp retire_reservation(state, token, handles) do
    %{pid: pid, changes: changes} = Map.fetch!(state.reservations, token)

    if monitor = Map.get(state.reservations[token], :owner_monitor),
      do: Process.demonitor(monitor, [:flush])

    owners = if Map.has_key?(state.peers, pid), do: :peers, else: :retired
    uid = state[owners][pid].uid
    state = update_usage(state, pid, Map.new(changes, fn {metric, count} -> {metric, -count} end))
    state = update_in(state[owners][pid].tokens, &MapSet.delete(&1, token))

    state = %{
      state
      | reservations: Map.delete(state.reservations, token),
        bound_handles: Map.drop(state.bound_handles, handles)
    }

    state =
      if owners == :retired and MapSet.size(state.retired[pid].tokens) == 0,
        do: %{state | retired: Map.delete(state.retired, pid)},
        else: state

    state |> prune_uid(uid) |> notify_ingress(pid)
  end

  defp retire_source_reference(state, nil), do: state

  defp retire_source_reference(state, source_token) do
    source = Map.fetch!(state.reservations, source_token)
    refs = source.output_refs - 1
    state = put_in(state.reservations[source_token].output_refs, refs)

    if refs == 0 and Map.get(source, :release_requested, false),
      do: retire_reservation(state, source_token, []),
      else: state
  end

  defp ingress_source(%{xml_queues: nil}, _token), do: {:ok, nil}
  defp ingress_source(_state, nil), do: {:ok, nil}

  defp ingress_source(state, token) do
    case state.reservations[token] do
      %{kind: :ingress} = source ->
        if Map.get(source, :release_requested, false),
          do: {:error, :invalid_ingress_reservation},
          else: {:ok, token}

      _ ->
        {:error, :invalid_ingress_reservation}
    end
  end

  defp pin_source(state, token),
    do:
      update_in(
        state.reservations[token],
        &Map.update(&1, :output_refs, 1, fn count -> count + 1 end)
      )

  # Delayed delivery is Router-ordered. Only its original reserver or the exact
  # coordinator may continue a claimed lease after original ingress retirement.
  defp egress_source(state, {:activation, token, request_key}, caller) do
    case state.reservations[token] do
      %{kind: :activation, request_key: ^request_key, claimed: true} = lease ->
        if caller in [lease.owner, lease.reserver] do
          with :ok <- live_activation(lease), do: {:ok, lease.source_token}
        else
          {:error, :activation_not_owner}
        end

      _ ->
        {:error, :invalid_activation_source}
    end
  end

  defp egress_source(state, token, _caller), do: ingress_source(state, token)

  defp activation_owner(pid) do
    if local_live_peer?(pid), do: :ok, else: {:error, :invalid_activation_owner}
  end

  defp activation_identity(%{
         caller: pid,
         caller_incarnation: {monitor, name},
         request_key: {epoch, reference} = key,
         deadline: deadline
       })
       when is_pid(pid) and is_reference(monitor) and is_binary(name) and
              is_reference(epoch) and is_reference(reference) and is_integer(deadline) do
    if deadline > System.monotonic_time(:millisecond),
      do: {:ok, pid, key},
      else: {:error, :activation_expired}
  end

  defp activation_identity(_identity), do: {:error, :invalid_activation_identity}

  defp validate_activation_source(state, token, pid, bytes, originals) do
    case state.reservations[token] do
      %{kind: :ingress, pid: ^pid, changes: changes} = source ->
        cond do
          not Map.has_key?(state.peers, pid) or not local_live_peer?(pid) ->
            {:error, :unknown_peer}

          Map.get(source, :release_requested, false) ->
            {:error, :invalid_activation_source}

          not (is_integer(bytes) and bytes > 0 and bytes == changes.ingress_bytes) ->
            {:error, :invalid_activation_source}

          not is_list(originals) or length(originals) != changes.ingress_fds ->
            {:error, :invalid_activation_source}

          true ->
            :ok
        end

      _ ->
        {:error, :invalid_activation_source}
    end
  end

  defp unique_activation_request(state, key) do
    if Enum.any?(state.reservations, fn {_token, res} ->
         res.kind == :activation and res.request_key == key
       end),
       do: {:error, :duplicate_activation_request},
       else: :ok
  end

  defp activation_capacity(state) do
    if state.global.activation_messages < state.pending_starts_limit,
      do: :ok,
      else: {:error, {:xml_limit_exceeded, "max_pending_service_starts"}}
  end

  defp activation_lease(state, token, request_key, caller) do
    case state.reservations[token] do
      %{kind: :activation} = lease ->
        if lease.owner == caller and lease.request_key == request_key,
          do: {:ok, lease},
          else: {:error, :activation_not_owner}

      _ ->
        {:error, :unknown_activation_lease}
    end
  end

  defp live_activation(%{cancelled: true}), do: {:error, :activation_cancelled}

  defp live_activation(lease) do
    if lease.deadline > System.monotonic_time(:millisecond) and local_live_peer?(lease.pid),
      do: :ok,
      else: {:error, :activation_expired}
  end

  defp cancel_activation(state, token) do
    lease = state.reservations[token]

    case Resources.close(lease.handles) do
      :ok ->
        send(lease.owner, {:activation_cancelled, token, lease.request_key})

        %{
          state
          | reservations:
              Map.put(state.reservations, token, %{lease | handles: [], cancelled: true}),
            bound_handles: Map.drop(state.bound_handles, lease.handles)
        }

      {:error, reason} ->
        exit({:resource_cleanup_failed, reason})
    end
  end

  # dbus-daemon 1.14.10 transport.c:1123-1125, bus.c:1946-1958.
  # Input pauses at >=; output permits one additional frame while current <=.
  defp xml_queue_capacity(%{xml_queues: nil}, _pid, _kind), do: :ok

  defp xml_queue_capacity(state, pid, kind) do
    counts = state.peers[pid].counts
    prefix = if kind == :ingress, do: "max_incoming", else: "max_outgoing"
    bytes = if kind == :ingress, do: counts.ingress_bytes, else: counts.egress_bytes
    fds = if kind == :ingress, do: counts.ingress_fds, else: counts.egress_fds
    comparison = if kind == :ingress, do: &Kernel.>=/2, else: &Kernel.>/2

    cond do
      comparison.(bytes, state.xml_queues[prefix <> "_bytes"]) ->
        {:error, {:xml_limit_exceeded, prefix <> "_bytes"}}

      comparison.(fds, state.xml_queues[prefix <> "_unix_fds"]) ->
        {:error, {:xml_limit_exceeded, prefix <> "_unix_fds"}}

      true ->
        :ok
    end
  end

  defp notify_ingress(state, pid) do
    case state.peers[pid] do
      %{ingress_waiting: true} ->
        if xml_queue_capacity(state, pid, :ingress) == :ok do
          send(pid, :ingress_capacity)
          put_in(state.peers[pid].ingress_waiting, false)
        else
          state
        end

      _ ->
        state
    end
  end

  defp remove_peer(state, pid) do
    peer = state.peers[pid]
    Process.demonitor(peer.monitor, [:flush])

    state =
      Enum.reduce(peer.tokens, state, fn token, state ->
        case state.reservations[token] do
          %{kind: :egress} ->
            case release_reservation(state, token) do
              {:ok, next} -> next
              {:error, reason} -> exit(reason)
            end

          %{kind: :activation} ->
            cancel_activation(state, token)

          _ ->
            state
        end
      end)

    state =
      update_usage(state, pid, %{
        connections: -1,
        authenticating: -peer.counts.authenticating,
        frame_bytes: -peer.counts.frame_bytes,
        frame_fds: -peer.counts.frame_fds
      })

    retained = state.peers[pid]

    retired =
      if MapSet.size(retained.tokens) == 0,
        do: state.retired,
        else: Map.put(state.retired, pid, Map.delete(retained, :monitor))

    state = xml_removed(state, peer)

    prune_uid(%{state | peers: Map.delete(state.peers, pid), retired: retired}, peer.uid)
    |> notify_accept()
  end

  defp prune_uid(state, uid) do
    if Enum.all?(state.uids[uid], fn {_metric, count} -> count == 0 end),
      do: %{state | uids: Map.delete(state.uids, uid)},
      else: state
  end

  defp bindable_reservation(state, token) do
    case state.reservations[token] do
      nil ->
        {:error, :unknown_reservation}

      %{kind: :egress} = reservation ->
        if Map.has_key?(reservation, :handles),
          do: {:error, :already_bound},
          else: {:ok, reservation}

      _ ->
        {:error, :not_egress_reservation}
    end
  end

  defp validate_handles(handles, count) when is_list(handles) do
    if length(handles) == count and count <= 253 and
         Enum.all?(handles, &(Resources.info(&1) == {:ok, %{cloexec: true}})),
       do: :ok,
       else: {:error, :invalid_handles}
  rescue
    ArgumentError -> {:error, :invalid_handles}
  end

  defp validate_handles(_handles, _count), do: {:error, :invalid_handles}

  defp exclusive_handles(state, handles) do
    if MapSet.size(MapSet.new(handles)) == length(handles) and
         Enum.all?(handles, &(not Map.has_key?(state.bound_handles, &1))),
       do: :ok,
       else: {:error, :shared_handles}
  end

  defp xml_incomplete_capacity(%{xml_limits: nil}), do: :ok

  defp xml_incomplete_capacity(state) do
    if state.xml_global.incomplete < state.xml_limits["max_incomplete_connections"],
      do: :ok,
      else: {:error, {:xml_limit_exceeded, "max_incomplete_connections"}}
  end

  defp hello_before_deadline(nil), do: :ok

  defp hello_before_deadline(deadline) do
    if System.monotonic_time(:millisecond) < deadline, do: :ok, else: {:error, :hello_timeout}
  end

  defp xml_completed_capacity(state, uid) do
    cond do
      state.xml_global.completed >= state.xml_limits["max_completed_connections"] ->
        {:error, {:xml_limit_exceeded, "max_completed_connections"}}

      Map.get(state.xml_uids, uid, 0) >= state.xml_limits["max_connections_per_user"] ->
        {:error, {:xml_limit_exceeded, "max_connections_per_user"}}

      true ->
        :ok
    end
  end

  defp xml_acquired(%{xml_limits: nil} = state), do: state
  defp xml_acquired(state), do: update_in(state.xml_global.incomplete, &(&1 + 1))
  defp xml_removed(%{xml_limits: nil} = state, _peer), do: state

  defp xml_removed(state, %{xml_completed: false}),
    do: update_in(state.xml_global.incomplete, &(&1 - 1))

  defp xml_removed(state, peer) do
    remaining = state.xml_uids[peer.uid] - 1

    uids =
      if remaining == 0,
        do: Map.delete(state.xml_uids, peer.uid),
        else: Map.put(state.xml_uids, peer.uid, remaining)

    %{
      state
      | xml_uids: uids,
        xml_global: %{state.xml_global | completed: state.xml_global.completed - 1}
    }
  end

  defp notify_accept(state) do
    if xml_incomplete_capacity(state) == :ok do
      for {observer, _monitor} <- state.accept_observers, do: send(observer, :incomplete_capacity)
    end

    state
  end

  defp remove_accept_observer(state, observer) do
    case Map.pop(state.accept_observers, observer) do
      {nil, _} ->
        state

      {monitor, observers} ->
        Process.demonitor(monitor, [:flush])
        %{state | accept_observers: observers}
    end
  end

  defp validate_limits(overrides) when is_map(overrides) do
    if Map.keys(overrides) -- Map.keys(@defaults) != [] do
      {:error, :unknown_scope}
    else
      Enum.reduce_while(overrides, {:ok, @defaults}, fn {scope, values}, {:ok, limits} ->
        cond do
          not is_map(values) ->
            {:halt, {:error, {:invalid_scope, scope}}}

          Map.keys(values) -- Map.keys(@defaults[scope]) != [] ->
            {:halt, {:error, {:unknown_metric, scope}}}

          not Enum.all?(values, fn {_metric, value} ->
            is_integer(value) and value in 1..0x7FFFFFFF
          end) ->
            {:halt, {:error, {:invalid_ceiling, scope}}}

          true ->
            {:cont, {:ok, Map.update!(limits, scope, &Map.merge(&1, values))}}
        end
      end)
    end
  end

  defp validate_limits(_overrides), do: {:error, :invalid_configuration}
end
