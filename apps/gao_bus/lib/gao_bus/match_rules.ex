defmodule GaoBus.MatchRules do
  @moduledoc """
  D-Bus match rules for signal subscription filtering.

  Stores match rules per peer and evaluates signals against them.
  Rules are parsed from the standard D-Bus match rule string format:

      type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'
  """

  use GenServer
  alias ExDBus.Wire.Types

  require Logger

  @table :gao_bus_match_rules
  @index :gao_bus_match_rule_order

  @type t :: %__MODULE__{
          type: atom() | nil,
          sender: String.t() | nil,
          interface: String.t() | nil,
          member: String.t() | nil,
          path: String.t() | nil,
          path_namespace: String.t() | nil,
          destination: String.t() | nil,
          eavesdrop: boolean() | nil,
          args: map()
        }

  defstruct [
    :type,
    :sender,
    :interface,
    :member,
    :path,
    :path_namespace,
    :destination,
    :eavesdrop,
    args: %{}
  ]

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add a match rule for a peer.

  The rule_string follows D-Bus match rule format:
  `type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'`

  Returns `:ok` or `{:error, reason}`.
  """
  @spec add_match(pid(), String.t()) :: :ok | {:error, term()}
  def add_match(peer_pid, rule_string) do
    GenServer.call(__MODULE__, {:add, peer_pid, rule_string})
  end

  @doc """
  Remove a match rule for a peer.
  """
  @spec remove_match(pid(), String.t()) :: :ok | {:error, term()}
  def remove_match(peer_pid, rule_string) do
    with {:ok, rule} <- parse(rule_string) do
      GenServer.call(__MODULE__, {:remove, peer_pid, canonical(rule)})
    end
  end

  @doc """
  Remove all match rules for a peer (called on disconnect).
  """
  @spec peer_disconnected(pid()) :: :ok
  def peer_disconnected(peer_pid) do
    GenServer.cast(__MODULE__, {:peer_disconnected, peer_pid})
  end

  @doc """
  Get all peer PIDs that have a match rule matching the given signal.
  """
  @spec matching_peers(ExDBus.Message.t()) :: [pid()]
  def matching_peers(signal, sender_names \\ []) do
    types = argument_types(signal.signature)
    senders = MapSet.new([signal.sender | sender_names])

    :ets.foldl(
      fn {pid, _name, rule, _raw}, acc ->
        if matches_with_types?(rule, signal, senders, types), do: MapSet.put(acc, pid), else: acc
      end,
      MapSet.new(),
      @table
    )
    |> MapSet.to_list()
  catch
    :error, :badarg -> []
  end

  @doc "Start a finite scan; later additions cannot extend this broadcast."
  def broadcast_cursor(signal, sender_names) do
    table = :ets.whereis(@index)

    {:ok,
     %{
       table: table,
       position: 0,
       ceiling: :ets.last(table),
       signal: signal,
       senders: MapSet.new([signal.sender | sender_names]),
       types: argument_types(signal.signature),
       seen: MapSet.new()
     }}
  catch
    :error, :badarg -> {:error, :match_index_unavailable}
  end

  @doc "Visit at most 32 rule rows and select at most 8 distinct recipients."
  def broadcast_batch(cursor), do: scan_broadcast(cursor, 32, 8, [])

  defp scan_broadcast(cursor, rows, deliveries, peers)
       when rows == 0 or deliveries == 0,
       do: {:more, Enum.reverse(peers), cursor}

  defp scan_broadcast(%{ceiling: :"$end_of_table"} = cursor, _rows, _deliveries, peers),
    do: {:done, Enum.reverse(peers), cursor}

  defp scan_broadcast(cursor, rows, deliveries, peers) do
    case :ets.next(cursor.table, cursor.position) do
      id when id == :"$end_of_table" or id > cursor.ceiling ->
        {:done, Enum.reverse(peers), cursor}

      id ->
        next = %{cursor | position: id}

        case :ets.lookup(cursor.table, id) do
          [{^id, pid, rule}] ->
            if not MapSet.member?(cursor.seen, pid) and
                 matches_with_types?(rule, cursor.signal, cursor.senders, cursor.types) do
              next = %{next | seen: MapSet.put(next.seen, pid)}
              scan_broadcast(next, rows - 1, deliveries - 1, [pid | peers])
            else
              scan_broadcast(next, rows - 1, deliveries, peers)
            end

          [] ->
            # Concurrent deletion still consumes this turn's row budget.
            scan_broadcast(next, rows - 1, deliveries, peers)
        end
    end
  catch
    :error, :badarg -> {:error, :match_index_unavailable}
  end

  @doc "Check if a peer has any match rules registered."
  @spec has_rules?(pid()) :: boolean()
  def has_rules?(peer_pid) do
    :ets.match(@table, {peer_pid, :_, :_, :_}) != []
  catch
    :error, :badarg -> false
  end

  @doc """
  Parse a D-Bus match rule string into a `%GaoBus.MatchRules{}` struct.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(rule_string) when is_binary(rule_string) and byte_size(rule_string) > 1024,
    do: {:error, :match_rule_too_long}

  def parse(rule_string) when is_binary(rule_string) do
    with true <- Types.valid?(:string, rule_string) or {:error, :invalid_match_text},
         {:ok, pairs} <- split_rule(rule_string),
         false <- duplicate_keys?(pairs) do
      Enum.reduce_while(pairs, {:ok, %__MODULE__{}}, fn {key, value}, {:ok, acc} ->
        case apply_pair(acc, key, value) do
          {:ok, acc} -> {:cont, {:ok, acc}}
          {:error, _} = err -> {:halt, err}
        end
      end)
    else
      true -> {:error, :duplicate_match_key}
      {:error, _} = error -> error
    end
  end

  def parse(_), do: {:error, :invalid_match_text}

  @doc """
  Check if a signal message matches a rule.
  """
  @spec matches?(t(), ExDBus.Message.t()) :: boolean()
  def matches?(%__MODULE__{} = rule, %ExDBus.Message{} = msg, sender_names \\ []) do
    matches_with_types?(
      rule,
      msg,
      MapSet.new([msg.sender | sender_names]),
      argument_types(msg.signature)
    )
  end

  defp matches_with_types?(rule, msg, senders, types) do
    match_field(rule.type, msg.type) and
      (is_nil(rule.sender) or MapSet.member?(senders, rule.sender)) and
      match_field(rule.interface, msg.interface) and
      match_field(rule.member, msg.member) and
      match_path(rule.path, rule.path_namespace, msg.path) and
      match_field(rule.destination, msg.destination) and
      (is_nil(msg.destination) or rule.eavesdrop == true) and
      match_args(rule.args, msg.body, types)
  end

  # --- GenServer callbacks ---

  @impl true
  def init(opts) do
    :ets.new(@table, [:bag, :named_table, :protected])
    :ets.new(@index, [:ordered_set, :named_table, :protected])

    xml_limits = Keyword.get(opts, :xml_limits)

    per_peer =
      if is_map(xml_limits) do
        Map.get(xml_limits, "max_match_rules_per_connection", 512)
      else
        Keyword.get(
          opts,
          :max_matches_per_peer,
          Application.get_env(:gao_bus, :max_matches_per_peer, 256)
        )
      end

    global =
      Keyword.get(
        opts,
        :max_match_entries,
        Application.get_env(:gao_bus, :max_match_entries, 8192)
      )

    per_uid =
      Keyword.get(
        opts,
        :max_matches_per_uid,
        Application.get_env(:gao_bus, :max_matches_per_uid, 2048)
      )

    minimum = if is_map(xml_limits), do: 0, else: 1

    if is_integer(per_peer) and per_peer >= minimum and is_integer(global) and global > 0 and
         is_integer(per_uid) and per_uid > 0 do
      {:ok,
       %{
         next_rule_id: 1,
         max_matches_per_peer: per_peer,
         max_match_entries: global,
         max_matches_per_uid: per_uid,
         xml_limits?: is_map(xml_limits),
         peers: %{},
         uid_counts: %{}
       }}
    else
      {:stop, :invalid_match_limits}
    end
  end

  @impl true
  def handle_call({:add, peer_pid, raw}, from, state) do
    # XML's quota error precedes parsing, including malformed duplicate requests.
    if state.xml_limits? and not match_capacity?(state, peer_pid) do
      {:reply, {:error, :limits_exceeded}, state}
    else
      case parse(raw) do
        {:ok, rule} -> handle_call({:add, peer_pid, rule, raw}, from, state)
        {:error, _} = error -> {:reply, error, state}
      end
    end
  end

  def handle_call({:add, peer_pid, rule, raw}, _from, state) do
    with true <- match_capacity?(state, peer_pid),
         {:ok, identity} <- match_identity(state, peer_pid),
         true <- Map.get(state.uid_counts, identity.uid, 0) < state.max_matches_per_uid,
         :ok <- live_match_peer(peer_pid) do
      id = state.next_rule_id
      rule = canonical(rule)
      :ets.insert(@table, {peer_pid, id, rule, raw})
      :ets.insert(@index, {id, peer_pid, rule})
      {:reply, :ok, retain_match(%{state | next_rule_id: id + 1}, peer_pid, identity)}
    else
      false -> {:reply, {:error, :limits_exceeded}, state}
      {:error, _} = error -> {:reply, error, state}
    end
  end

  def handle_call({:remove, peer_pid, rule}, _from, state) do
    # Delete the first matching rule for this peer
    matches = :ets.match_object(@table, {peer_pid, :_, rule, :_})

    case matches do
      [entry | _] ->
        :ets.delete(@index, elem(entry, 1))
        :ets.delete_object(@table, entry)
        {:reply, :ok, release_matches(state, peer_pid, 1)}

      [] ->
        {:reply, {:error, "org.freedesktop.DBus.Error.MatchRuleNotFound"}, state}
    end
  end

  @impl true
  def handle_cast({:peer_disconnected, peer_pid}, state) do
    {:noreply, remove_peer_matches(state, peer_pid)}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, peer_pid, _reason}, state) do
    case state.peers[peer_pid] do
      %{monitor: ^monitor} -> {:noreply, remove_peer_matches(state, peer_pid)}
      _ -> {:noreply, state}
    end
  end

  defp match_identity(state, peer_pid) do
    case GaoBus.Limits.peer_identity(peer_pid) do
      {:ok, %{uid: uid, admission: admission} = identity} ->
        case state.peers[peer_pid] do
          nil -> {:ok, identity}
          %{uid: ^uid, admission: ^admission} -> {:ok, identity}
          _ -> {:error, :identity_unavailable}
        end

      {:error, _reason} ->
        {:error, :identity_unavailable}
    end
  end

  defp live_match_peer(peer_pid) do
    if is_pid(peer_pid) and node(peer_pid) == node() and Process.alive?(peer_pid),
      do: :ok,
      else: {:error, :identity_unavailable}
  end

  defp retain_match(state, peer_pid, identity) do
    peer =
      case state.peers[peer_pid] do
        nil -> Map.merge(identity, %{monitor: Process.monitor(peer_pid), count: 1})
        peer -> %{peer | count: peer.count + 1}
      end

    %{
      state
      | peers: Map.put(state.peers, peer_pid, peer),
        uid_counts: Map.update(state.uid_counts, identity.uid, 1, &(&1 + 1))
    }
  end

  defp release_matches(state, peer_pid, count) do
    case state.peers[peer_pid] do
      nil ->
        state

      peer ->
        remaining = peer.count - count
        uid_remaining = Map.fetch!(state.uid_counts, peer.uid) - count

        peers =
          if remaining == 0 do
            Process.demonitor(peer.monitor, [:flush])
            Map.delete(state.peers, peer_pid)
          else
            Map.put(state.peers, peer_pid, %{peer | count: remaining})
          end

        uid_counts =
          if uid_remaining == 0,
            do: Map.delete(state.uid_counts, peer.uid),
            else: Map.put(state.uid_counts, peer.uid, uid_remaining)

        %{state | peers: peers, uid_counts: uid_counts}
    end
  end

  defp remove_peer_matches(state, peer_pid) do
    entries = :ets.lookup(@table, peer_pid)
    count = length(entries)
    for {^peer_pid, id, _rule, _raw} <- entries, do: :ets.delete(@index, id)
    :ets.match_delete(@table, {peer_pid, :_, :_, :_})
    release_matches(state, peer_pid, count)
  end

  # --- Rule parsing ---

  defp match_capacity?(state, peer_pid),
    do:
      length(:ets.lookup(@table, peer_pid)) < state.max_matches_per_peer and
        :ets.info(@table, :size) < state.max_match_entries

  defp split_rule(rule), do: parse_pairs(String.trim(rule), [])

  defp parse_pairs("", pairs), do: {:ok, Enum.reverse(pairs)}

  defp parse_pairs(binary, pairs) do
    case :binary.split(binary, "=") do
      [key, rest] ->
        key = String.trim(key)

        with true <- Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, key),
             {:ok, value, rest} <- take_value(rest, false, []) do
          parse_pairs(String.trim(rest), [{key, value} | pairs])
        else
          false -> {:error, :invalid_match_key}
          {:error, _} = error -> error
        end

      _ ->
        {:error, :missing_match_equals}
    end
  end

  defp take_value("", true, _acc), do: {:error, :unbalanced_match_quotes}
  defp take_value("", false, acc), do: {:ok, value_text(acc), ""}
  defp take_value(<<",", rest::binary>>, false, acc), do: {:ok, value_text(acc), rest}
  defp take_value(<<"'", rest::binary>>, quoted, acc), do: take_value(rest, not quoted, acc)

  defp take_value(<<"\\'", rest::binary>>, false, acc),
    do: take_value(rest, false, [{?', true} | acc])

  defp take_value(<<byte, rest::binary>>, quoted, acc),
    do: take_value(rest, quoted, [{byte, quoted} | acc])

  defp value_text(acc) do
    whitespace? = fn {byte, quoted} -> not quoted and byte in [9, 10, 13, 32] end

    acc
    |> Enum.drop_while(whitespace?)
    |> Enum.reverse()
    |> Enum.drop_while(whitespace?)
    |> Enum.map(fn {byte, _} -> byte end)
    |> :erlang.list_to_binary()
  end

  defp duplicate_keys?(pairs) do
    keys = Enum.map(pairs, fn {key, _} -> if key == "path_namespace", do: "path", else: key end)
    length(Enum.uniq(keys)) != length(keys)
  end

  defp canonical(rule), do: %{rule | eavesdrop: rule.eavesdrop || false}

  defp apply_pair(rule, "type", value) do
    case value do
      "signal" -> {:ok, %{rule | type: :signal}}
      "method_call" -> {:ok, %{rule | type: :method_call}}
      "method_return" -> {:ok, %{rule | type: :method_return}}
      "error" -> {:ok, %{rule | type: :error}}
      _ -> {:error, {:invalid_type, value}}
    end
  end

  defp apply_pair(rule, "sender", value),
    do: put_field(rule, :sender, value, valid_bus_name?(value))

  defp apply_pair(rule, "interface", value),
    do:
      put_field(
        rule,
        :interface,
        value,
        byte_size(value) <= 255 and
          Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\z/, value)
      )

  defp apply_pair(rule, "member", value),
    do:
      put_field(
        rule,
        :member,
        value,
        byte_size(value) <= 255 and Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_]*\z/, value)
      )

  defp apply_pair(rule, "path", value),
    do: put_field(rule, :path, value, Types.valid?(:object_path, value))

  defp apply_pair(rule, "path_namespace", value),
    do: put_field(rule, :path_namespace, value, Types.valid?(:object_path, value))

  # dbus-daemon 1.14.10 accepts well-known destinations as well as unique ones.
  defp apply_pair(rule, "destination", value),
    do: put_field(rule, :destination, value, valid_bus_name?(value))

  defp apply_pair(rule, "arg0namespace", value) do
    valid =
      byte_size(value) <= 255 and
        Regex.match?(
          ~r/\A(?:[A-Za-z_-][A-Za-z0-9_-]*(?:\.[A-Za-z_-][A-Za-z0-9_-]*)*|:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\z/,
          value
        )

    if valid,
      do: {:ok, %{rule | args: Map.put(rule.args, :arg0namespace, value)}},
      else: {:error, {:invalid_value, "arg0namespace"}}
  end

  defp apply_pair(rule, "eavesdrop", value) do
    if value in ["true", "false"],
      do: {:ok, %{rule | eavesdrop: value == "true"}},
      else: {:error, {:invalid_value, "eavesdrop"}}
  end

  defp apply_pair(rule, "arg" <> rest, value) do
    case Integer.parse(rest) do
      {n, ""} when n >= 0 and n <= 63 ->
        put_arg(rule, {:arg, n}, value)

      {n, "path"} when n >= 0 and n <= 63 ->
        put_arg(rule, {:arg_path, n}, value)

      _ ->
        {:error, {:invalid_arg, "arg" <> rest}}
    end
  end

  defp apply_pair(_rule, key, _value), do: {:error, {:unknown_key, key}}

  defp put_arg(rule, key, value) do
    if Map.has_key?(rule.args, key),
      do: {:error, :duplicate_match_key},
      else: {:ok, %{rule | args: Map.put(rule.args, key, value)}}
  end

  defp put_field(rule, field, value, true), do: {:ok, Map.put(rule, field, value)}
  defp put_field(_rule, field, _value, false), do: {:error, {:invalid_value, field}}

  defp valid_bus_name?(value) do
    byte_size(value) <= 255 and
      Regex.match?(
        ~r/\A(?:[A-Za-z_-][A-Za-z0-9_-]*(?:\.[A-Za-z_-][A-Za-z0-9_-]*)+|:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\z/,
        value
      )
  end

  # --- Matching ---

  defp match_field(nil, _), do: true
  defp match_field(expected, actual), do: expected == actual

  defp match_path(nil, nil, _), do: true
  defp match_path(path, nil, msg_path), do: path == msg_path

  defp match_path(nil, namespace, msg_path) when is_binary(msg_path) do
    namespace == "/" or msg_path == namespace or String.starts_with?(msg_path, namespace <> "/")
  end

  defp match_path(nil, _namespace, nil), do: false
  defp match_path(_, _, _), do: false

  defp argument_types(nil), do: []

  defp argument_types(signature) do
    case Types.parse_types(signature) do
      {:ok, types} -> types
      {:error, _} -> []
    end
  end

  defp match_args(args, _body, _types) when map_size(args) == 0, do: true
  defp match_args(_args, nil, _types), do: false
  defp match_args(_args, [], _types), do: false

  defp match_args(args, body, types) when is_list(body) do
    Enum.all?(args, fn
      {{:arg, n}, expected} ->
        Enum.at(types, n) == :string and Enum.at(body, n) == expected

      {{:arg_path, n}, expected} ->
        Enum.at(types, n) in [:string, :object_path] and
          argument_path?(expected, Enum.at(body, n))

      {:arg0namespace, expected} ->
        actual = Enum.at(body, 0)

        Enum.at(types, 0) == :string and is_binary(actual) and
          (actual == expected or String.starts_with?(actual, expected <> "."))
    end)
  end

  defp argument_path?(expected, actual) when is_binary(actual),
    do:
      actual == expected or
        (String.ends_with?(expected, "/") and String.starts_with?(actual, expected)) or
        (String.ends_with?(actual, "/") and String.starts_with?(expected, actual))

  defp argument_path?(_, _), do: false
end
