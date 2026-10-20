defmodule GaoBus.NameRegistry do
  @moduledoc """
  ETS-backed well-known name registry for the D-Bus bus.

  Manages name ownership with RequestName / ReleaseName semantics.
  Emits NameOwnerChanged signals through the Router when ownership changes.
  """

  use GenServer

  import Bitwise

  require Logger

  # RequestName flags
  @flag_allow_replacement 0x1
  @flag_replace_existing 0x2
  @flag_do_not_queue 0x4

  # RequestName return values
  @name_primary_owner 1
  @name_in_queue 2
  @name_exists 3
  @name_already_owner 4

  # ReleaseName return values
  @name_released 1
  @name_non_existent 2
  @name_not_owner 3

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Request ownership of a well-known name.

  Returns `{:ok, result_code}` where result_code is one of:
  - 1 = primary owner
  - 2 = in queue
  - 3 = exists (cannot replace)
  - 4 = already owner
  """
  @spec request_name(String.t(), non_neg_integer(), pid(), String.t()) ::
          {:ok, 1..4} | {:error, String.t()}
  def request_name(name, flags, peer_pid, unique_name) do
    GenServer.call(__MODULE__, {:request_name, name, flags, peer_pid, unique_name})
  end

  @doc """
  Release a well-known name.

  Returns `{:ok, result_code}` where result_code is one of:
  - 1 = released
  - 2 = non-existent
  - 3 = not owner
  """
  @spec release_name(String.t(), pid()) :: {:ok, 1..3} | {:error, String.t()}
  def release_name(name, peer_pid) do
    GenServer.call(__MODULE__, {:release_name, name, peer_pid})
  end

  @doc """
  Get the unique name of the owner of a well-known name.
  """
  @spec get_name_owner(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def get_name_owner(name) do
    GenServer.call(__MODULE__, {:get_name_owner, name})
  end

  @doc "Return primary owner followed by queued requesters, in promotion order."
  @spec list_queued_owners(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def list_queued_owners(name), do: GenServer.call(__MODULE__, {:list_queued_owners, name})

  @doc """
  List all registered names (well-known + unique).
  """
  @spec list_names() :: [String.t()]
  def list_names do
    GenServer.call(__MODULE__, :list_names)
  end

  @doc """
  Check if a name exists.
  """
  @spec name_has_owner?(String.t()) :: boolean()
  def name_has_owner?(name) do
    GenServer.call(__MODULE__, {:name_has_owner, name})
  end

  @doc """
  Register a unique name for a peer. Called during Hello().
  """
  @spec register_unique(String.t(), pid()) :: :ok
  def register_unique(unique_name, peer_pid) do
    GenServer.call(__MODULE__, {:register_unique, unique_name, peer_pid})
  end

  @doc """
  Remove all names owned by a peer (called when peer disconnects).
  """
  @spec peer_disconnected(pid()) :: :ok
  def peer_disconnected(peer_pid) do
    GenServer.cast(__MODULE__, {:peer_disconnected, peer_pid})
  end

  @doc """
  Resolve a name (well-known or unique) to a peer pid.
  """
  @spec resolve(String.t()) :: {:ok, pid()} | {:bus, pid()} | {:error, :name_not_found}
  def resolve(name) do
    GenServer.call(__MODULE__, {:resolve, name})
  end

  @doc "Resolve recipient and all its owned names in one authority snapshot."
  def resolve_with_names(name), do: GenServer.call(__MODULE__, {:resolve_with_names, name})

  @doc "Return currently owned names, excluding names for which the peer is only queued."
  def names_for(peer_pid), do: GenServer.call(__MODULE__, {:names_for, peer_pid})

  @doc "Resolve one routing decision with primary and queued policy names in a single snapshot."
  def routing_snapshot(source, destination),
    do: GenServer.call(__MODULE__, {:routing_snapshot, source, destination})

  # --- GenServer callbacks ---

  @impl true
  def init(opts) do
    # Well-known names: name => %{owner: pid, unique_name: string, flags: int, queue: []}
    names = :ets.new(:gao_bus_names, [:set, :protected])
    # Unique names: unique_name => pid
    uniques = :ets.new(:gao_bus_uniques, [:set, :protected])
    # Reverse: pid => [owned_names]
    pid_names = :ets.new(:gao_bus_pid_names, [:bag, :protected])

    xml_limits = Keyword.get(opts, :xml_limits)

    per_peer =
      if is_map(xml_limits) do
        Map.get(xml_limits, "max_names_per_connection", 512)
      else
        Keyword.get(
          opts,
          :max_names_per_peer,
          Application.get_env(:gao_bus, :max_names_per_peer, 64)
        )
      end

    global =
      Keyword.get(opts, :max_name_entries, Application.get_env(:gao_bus, :max_name_entries, 8192))

    per_uid =
      Keyword.get(
        opts,
        :max_names_per_uid,
        Application.get_env(:gao_bus, :max_names_per_uid, 2048)
      )

    minimum = if is_map(xml_limits), do: 0, else: 1

    if is_integer(per_peer) and per_peer >= minimum and is_integer(global) and global > 0 and
         is_integer(per_uid) and per_uid > 0 do
      {:ok,
       %{
         names: names,
         uniques: uniques,
         pid_names: pid_names,
         max_names_per_peer: per_peer,
         max_name_entries: global,
         max_names_per_uid: per_uid,
         xml_limits?: is_map(xml_limits),
         peers: %{},
         uid_counts: %{}
       }}
    else
      {:stop, :invalid_name_limits}
    end
  end

  @impl true
  def handle_call({:names_for, peer_pid}, _from, state),
    do: {:reply, owned_names(state, peer_pid), state}

  def handle_call({:resolve_with_names, name}, from, state) do
    case handle_call({:resolve, name}, from, state) do
      {:reply, {:ok, pid}, state} -> {:reply, {:ok, pid, owned_names(state, pid)}, state}
      result -> result
    end
  end

  def handle_call({:routing_snapshot, source, destination}, _from, state) do
    {sender_names, sender_policy_names} =
      if source == :bus,
        do: {["org.freedesktop.DBus"], ["org.freedesktop.DBus"]},
        else: {owned_names(state, source), policy_names(state, source)}

    {recipient, destination_names, destination_policy_names} =
      routing_destination(state, destination)

    {:reply,
     %{
       destination: recipient,
       sender_names: sender_names,
       sender_policy_names: sender_policy_names,
       destination_names: destination_names,
       destination_policy_names: destination_policy_names
     }, state}
  end

  def handle_call({:request_name, name, flags, peer_pid, unique_name}, _from, state) do
    cond do
      not requestable_name?(name) or not is_integer(flags) or flags < 0 or flags > 0xFFFFFFFF ->
        {:reply, {:error, "org.freedesktop.DBus.Error.InvalidArgs"}, state}

      name_capacity?(state, peer_pid, name, flags) ->
        request_name_transition(name, flags, peer_pid, unique_name, state)

      true ->
        {:reply, {:error, "org.freedesktop.DBus.Error.LimitsExceeded"}, state}
    end
  end

  def handle_call({:release_name, name, peer_pid}, _from, state) do
    if requestable_name?(name) do
      release_name_transition(name, peer_pid, state)
    else
      {:reply, {:error, "org.freedesktop.DBus.Error.InvalidArgs"}, state}
    end
  end

  def handle_call({:get_name_owner, "org.freedesktop.DBus"}, _from, state),
    do: {:reply, {:ok, "org.freedesktop.DBus"}, state}

  def handle_call({:list_queued_owners, "org.freedesktop.DBus"}, _from, state),
    do: {:reply, {:ok, ["org.freedesktop.DBus"]}, state}

  def handle_call({:list_queued_owners, name}, _from, state) do
    result =
      case :ets.lookup(state.names, name) do
        [{^name, _pid, unique, _flags, queue}] ->
          {:ok, [unique | Enum.map(queue, fn {_, queued_unique, _} -> queued_unique end)]}

        [] ->
          case :ets.lookup(state.uniques, name) do
            [{^name, _pid}] -> {:ok, [name]}
            [] -> {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"}
          end
      end

    {:reply, result, state}
  end

  def handle_call({:get_name_owner, name}, _from, state) do
    result =
      case :ets.lookup(state.names, name) do
        [{^name, _pid, unique_name, _, _}] ->
          {:ok, unique_name}

        [] ->
          # Check unique names
          case :ets.lookup(state.uniques, name) do
            [{^name, _pid}] -> {:ok, name}
            [] -> {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"}
          end
      end

    {:reply, result, state}
  end

  def handle_call(:list_names, _from, state) do
    well_known = :ets.select(state.names, [{{:"$1", :_, :_, :_, :_}, [], [:"$1"]}])
    unique = :ets.select(state.uniques, [{{:"$1", :_}, [], [:"$1"]}])
    {:reply, ["org.freedesktop.DBus" | well_known ++ unique], state}
  end

  def handle_call({:name_has_owner, name}, _from, state) do
    has_owner =
      name == "org.freedesktop.DBus" or
        :ets.lookup(state.names, name) != [] or
        :ets.lookup(state.uniques, name) != []

    {:reply, has_owner, state}
  end

  def handle_call({:register_unique, unique_name, peer_pid}, _from, state) do
    :ets.insert(state.uniques, {unique_name, peer_pid})
    :ets.insert(state.pid_names, {peer_pid, unique_name})
    emit_name_owner_changed(unique_name, "", unique_name)
    {:reply, :ok, state}
  end

  def handle_call({:resolve, "org.freedesktop.DBus"}, _from, state) do
    {:reply, {:bus, self()}, state}
  end

  def handle_call({:resolve, name}, _from, state) do
    result =
      case :ets.lookup(state.names, name) do
        [{^name, pid, _, _, _}] ->
          {:ok, pid}

        [] ->
          case :ets.lookup(state.uniques, name) do
            [{^name, pid}] -> {:ok, pid}
            [] -> {:error, :name_not_found}
          end
      end

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:peer_disconnected, peer_pid}, state) do
    {:noreply, remove_peer_names(state, peer_pid)}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, peer_pid, _reason}, state) do
    case state.peers[peer_pid] do
      %{monitor: ^monitor} -> {:noreply, remove_peer_names(state, peer_pid)}
      _ -> {:noreply, state}
    end
  end

  defp remove_peer_names(state, peer_pid) do
    owned = :ets.lookup(state.pid_names, peer_pid)

    for {_pid, name} <- owned do
      release_owned_name(state, name, peer_pid)
      release_unique_name(state, name, peer_pid)
    end

    :ets.delete(state.pid_names, peer_pid)

    case state.peers[peer_pid] do
      nil -> state
      peer -> release_name_charges(state, peer_pid, peer.count)
    end
  end

  defp release_name_transition(name, peer_pid, state) do
    result =
      case :ets.lookup(state.names, name) do
        [] ->
          @name_non_existent

        [{^name, ^peer_pid, unique_name, _flags, queue}] ->
          :ets.delete_object(state.pid_names, {peer_pid, name})

          case queue do
            [] ->
              :ets.delete(state.names, name)
              emit_name_owner_changed(name, unique_name, "")

            [{next_pid, next_unique, next_flags} | rest] ->
              :ets.insert(state.names, {name, next_pid, next_unique, next_flags, rest})
              :ets.insert(state.pid_names, {next_pid, name})
              emit_name_owner_changed(name, unique_name, next_unique)
          end

          @name_released

        [{^name, owner, unique, flags, queue}] ->
          if Enum.any?(queue, fn {pid, _, _} -> pid == peer_pid end) do
            remaining = Enum.reject(queue, fn {pid, _, _} -> pid == peer_pid end)
            :ets.insert(state.names, {name, owner, unique, flags, remaining})
            :ets.delete_object(state.pid_names, {peer_pid, name})
            @name_released
          else
            @name_not_owner
          end
      end

    state =
      if result == @name_released,
        do: release_name_charges(state, peer_pid, 1),
        else: state

    {:reply, {:ok, result}, state}
  end

  defp request_name_transition(name, flags, peer_pid, unique_name, state) do
    before = :ets.lookup(state.names, name)
    {result, row} = request_name_plan(before, name, flags, peer_pid, unique_name)
    changes = association_changes(before, [row])

    with {:ok, identity} <- name_identity(state, peer_pid),
         {:ok, uid_changes} <- name_uid_changes(state, peer_pid, identity, changes),
         true <- name_uid_capacity?(state, uid_changes),
         :ok <- live_name_peer(peer_pid) do
      state = apply_name_charges(state, identity, changes, uid_changes)
      :ets.insert(state.names, row)

      for {pid, change} <- changes do
        if change > 0,
          do: :ets.insert(state.pid_names, {pid, name}),
          else: :ets.delete_object(state.pid_names, {pid, name})
      end

      if result == @name_primary_owner do
        old_unique =
          case before do
            [] -> ""
            [{^name, _pid, unique, _flags, _queue}] -> unique
          end

        emit_name_owner_changed(name, old_unique, elem(row, 2))
      end

      {:reply, {:ok, result}, state}
    else
      false -> {:reply, {:error, "org.freedesktop.DBus.Error.LimitsExceeded"}, state}
      {:error, _} = error -> {:reply, error, state}
    end
  end

  defp request_name_plan([], name, flags, peer_pid, unique_name),
    do: {@name_primary_owner, {name, peer_pid, unique_name, flags, []}}

  defp request_name_plan(
         [{name, peer_pid, current_unique, _flags, queue}],
         name,
         flags,
         peer_pid,
         _unique_name
       ),
       do: {@name_already_owner, {name, peer_pid, current_unique, flags, queue}}

  defp request_name_plan(
         [{name, current_pid, current_unique, current_flags, queue}],
         name,
         flags,
         peer_pid,
         unique_name
       ) do
    can_replace = (current_flags &&& @flag_allow_replacement) != 0
    wants_replace = (flags &&& @flag_replace_existing) != 0

    cond do
      can_replace and wants_replace ->
        remaining = Enum.reject(queue, fn {pid, _, _} -> pid == peer_pid end)

        new_queue =
          if (current_flags &&& @flag_do_not_queue) == 0,
            do: [{current_pid, current_unique, current_flags} | remaining],
            else: remaining

        {@name_primary_owner, {name, peer_pid, unique_name, flags, new_queue}}

      (flags &&& @flag_do_not_queue) != 0 ->
        remaining = Enum.reject(queue, fn {pid, _, _} -> pid == peer_pid end)
        {@name_exists, {name, current_pid, current_unique, current_flags, remaining}}

      true ->
        new_queue =
          if Enum.any?(queue, fn {pid, _, _} -> pid == peer_pid end) do
            # RequestName: "If replacement is not possible, and the method
            # caller is currently in the queue but not the primary owner,
            # its flags are updated with the values from the new RequestName call."
            # dbus-daemon 1.14.10 reorders this case; retain normative position.
            Enum.map(queue, fn
              {^peer_pid, queued_unique, _} -> {peer_pid, queued_unique, flags}
              entry -> entry
            end)
          else
            queue ++ [{peer_pid, unique_name, flags}]
          end

        {@name_in_queue, {name, current_pid, current_unique, current_flags, new_queue}}
    end
  end

  # --- Helpers ---

  defp association_changes(before, after_rows) do
    previous = association_pids(before)
    current = association_pids(after_rows)
    added = Map.new(MapSet.difference(current, previous), &{&1, 1})
    removed = Map.new(MapSet.difference(previous, current), &{&1, -1})
    Map.merge(added, removed)
  end

  defp association_pids([]), do: MapSet.new()

  defp association_pids([{_name, owner, _unique, _flags, queue}]),
    do: MapSet.new([owner | Enum.map(queue, fn {pid, _unique, _flags} -> pid end)])

  defp name_identity(state, peer_pid) do
    case GaoBus.Limits.peer_identity(peer_pid) do
      {:ok, %{uid: uid, admission: admission} = identity} ->
        case state.peers[peer_pid] do
          nil -> {:ok, identity}
          %{uid: ^uid, admission: ^admission} -> {:ok, identity}
          _ -> {:error, "org.freedesktop.DBus.Error.Failed"}
        end

      {:error, _reason} ->
        {:error, "org.freedesktop.DBus.Error.Failed"}
    end
  end

  defp live_name_peer(peer_pid) do
    if is_pid(peer_pid) and node(peer_pid) == node() and Process.alive?(peer_pid),
      do: :ok,
      else: {:error, "org.freedesktop.DBus.Error.Failed"}
  end

  defp name_uid_changes(state, requester, identity, changes) do
    Enum.reduce_while(changes, {:ok, %{}}, fn {pid, change}, {:ok, uid_changes} ->
      peer =
        case state.peers[pid] do
          nil -> if pid == requester and change > 0, do: identity, else: nil
          peer -> peer
        end

      case peer do
        %{uid: uid} ->
          {:cont, {:ok, Map.update(uid_changes, uid, change, &(&1 + change))}}

        nil ->
          {:halt, {:error, "org.freedesktop.DBus.Error.Failed"}}
      end
    end)
  end

  defp name_uid_capacity?(state, uid_changes),
    do:
      Enum.all?(uid_changes, fn {uid, change} ->
        change <= 0 or Map.get(state.uid_counts, uid, 0) + change <= state.max_names_per_uid
      end)

  defp apply_name_charges(state, identity, changes, uid_changes) do
    peers =
      Enum.reduce(changes, state.peers, fn {pid, change}, peers ->
        case peers[pid] do
          nil ->
            peer = Map.merge(identity, %{monitor: Process.monitor(pid), count: change})
            Map.put(peers, pid, peer)

          peer ->
            remaining = peer.count + change

            if remaining == 0 do
              Process.demonitor(peer.monitor, [:flush])
              Map.delete(peers, pid)
            else
              Map.put(peers, pid, %{peer | count: remaining})
            end
        end
      end)

    uid_counts =
      Enum.reduce(uid_changes, state.uid_counts, fn {uid, change}, counts ->
        remaining = Map.get(counts, uid, 0) + change

        if remaining == 0,
          do: Map.delete(counts, uid),
          else: Map.put(counts, uid, remaining)
      end)

    %{state | peers: peers, uid_counts: uid_counts}
  end

  defp release_name_charges(state, peer_pid, count) do
    case state.peers[peer_pid] do
      nil ->
        state

      peer ->
        apply_name_charges(state, nil, %{peer_pid => -count}, %{peer.uid => -count})
    end
  end

  defp name_capacity?(state, peer, name, flags) do
    # XML counts the unique service and queued associations, and the reference
    # checks this quota even for duplicate and non-allocating requests.
    (not state.xml_limits? or
       length(:ets.lookup(state.pid_names, peer)) < state.max_names_per_peer) and
      name_allocation_capacity?(state, peer, name, flags)
  end

  defp name_allocation_capacity?(state, peer, name, flags) do
    entries = :ets.lookup(state.names, name)

    case entries do
      [{^name, ^peer, _, _, _}] ->
        true

      _ ->
        {existing?, extra} =
          case entries do
            [{^name, _owner, _unique, owner_flags, queue}] ->
              queued? = Enum.any?(queue, fn {pid, _, _} -> pid == peer end)

              replace? =
                (owner_flags &&& @flag_allow_replacement) != 0 and
                  (flags &&& @flag_replace_existing) != 0

              no_allocation? = not replace? and (flags &&& @flag_do_not_queue) != 0
              drops_owner? = replace? and (owner_flags &&& @flag_do_not_queue) != 0
              {queued? or no_allocation?, if(drops_owner?, do: 0, else: 1)}

            [] ->
              {false, 1}
          end

        {total, peer_total} =
          :ets.foldl(
            fn {_name, owner, _unique, _flags, queue}, {total, owned} ->
              {total + 1 + length(queue),
               owned + if(owner == peer, do: 1, else: 0) +
                 Enum.count(queue, fn {pid, _, _} -> pid == peer end)}
            end,
            {0, 0},
            state.names
          )

        existing? or
          (total + extra <= state.max_name_entries and peer_total < state.max_names_per_peer)
    end
  end

  @doc "Whether a name may be acquired or released by a client (not bus-self or unique)."
  @spec requestable_name?(term()) :: boolean()
  def requestable_name?(name) do
    ExDBus.Wire.Types.valid?(:string, name) and name != "org.freedesktop.DBus" and
      byte_size(name) <= 255 and
      Regex.match?(~r/\A[A-Za-z_-][A-Za-z0-9_-]*(?:\.[A-Za-z_-][A-Za-z0-9_-]*)+\z/, name)
  end

  defp owned_names(state, pid) do
    uniques = :ets.select(state.uniques, [{{:"$1", pid}, [], [:"$1"]}])
    owned = :ets.select(state.names, [{{:"$1", pid, :_, :_, :_}, [], [:"$1"]}])
    uniques ++ owned
  end

  defp policy_names(state, pid),
    do: :ets.lookup(state.pid_names, pid) |> Enum.map(fn {_, name} -> name end)

  defp routing_destination(_state, :bus),
    do: {:bus, ["org.freedesktop.DBus"], ["org.freedesktop.DBus"]}

  defp routing_destination(_state, :broadcast), do: {:broadcast, [], []}

  defp routing_destination(state, name) do
    case handle_call({:resolve, name}, nil, state) do
      {:reply, {:ok, pid}, _state} ->
        names = owned_names(state, pid)
        {{:peer, pid, names}, names, policy_names(state, pid)}

      {:reply, {:bus, _pid}, _state} ->
        routing_destination(state, :bus)

      {:reply, {:error, :name_not_found}, _state} ->
        {{:missing, name}, [name], [name]}
    end
  end

  defp release_owned_name(state, name, peer_pid) do
    case :ets.lookup(state.names, name) do
      [{^name, ^peer_pid, unique_name, _flags, queue}] ->
        case queue do
          [] ->
            :ets.delete(state.names, name)
            emit_name_owner_changed(name, unique_name, "")

          [{next_pid, next_unique, next_flags} | rest] ->
            :ets.insert(state.names, {name, next_pid, next_unique, next_flags, rest})
            :ets.insert(state.pid_names, {next_pid, name})
            emit_name_owner_changed(name, unique_name, next_unique)
        end

      _ ->
        remove_from_queue(state.names, name, peer_pid)
    end
  end

  defp release_unique_name(state, name, peer_pid) do
    case :ets.lookup(state.uniques, name) do
      [{^name, ^peer_pid}] ->
        :ets.delete(state.uniques, name)
        emit_name_owner_changed(name, name, "")

      _ ->
        :ok
    end
  end

  defp remove_from_queue(names_table, name, peer_pid) do
    case :ets.lookup(names_table, name) do
      [{^name, owner, unique, flags, queue}] ->
        new_queue = Enum.reject(queue, fn {pid, _, _} -> pid == peer_pid end)
        :ets.insert(names_table, {name, owner, unique, flags, new_queue})

      _ ->
        :ok
    end
  end

  defp emit_name_owner_changed(name, old_owner, new_owner) do
    # Broadcast to PubSub for web monitor
    cond do
      new_owner != "" and old_owner == "" ->
        GaoBus.PubSub.broadcast({:name_acquired, name, new_owner})

      new_owner == "" and old_owner != "" ->
        GaoBus.PubSub.broadcast({:name_released, name, old_owner})

      true ->
        GaoBus.PubSub.broadcast({:name_acquired, name, new_owner})
    end

    # Send through the router if available
    if Process.whereis(GaoBus.Router) do
      if old_owner != "" do
        GaoBus.Router.emit_signal(
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus",
          "NameLost",
          "s",
          [name],
          old_owner
        )
      end

      if new_owner != "" do
        GaoBus.Router.emit_signal(
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus",
          "NameAcquired",
          "s",
          [name],
          new_owner
        )
      end

      GaoBus.Router.emit_signal(
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameOwnerChanged",
        "sss",
        [name, old_owner, new_owner]
      )
    end
  end
end
