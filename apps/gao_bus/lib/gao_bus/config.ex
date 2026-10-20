defmodule GaoBus.Config do
  @moduledoc """
  Complete, bounded D-Bus configuration candidate with ordered XML policies.

  Loading has no runtime policy effects. A compiler must validate supported
  runtime semantics before atomically publishing the candidate. Policy classes,
  wildcards, omitted reply/eavesdrop modifiers and repeated includes are retained;
  this loader never flattens them into permissive native grants.

  Includes expand at their document position. Included directories use lexical
  `.conf` order (the reference leaves their order unspecified). Missing include
  directories are empty; `ignore_missing=yes` suppresses only a missing file.
  Reads are finite, regular files only. Symlink aliases participate in cycle
  detection through filesystem identity. No external DTD or NSS service is used.
  """
  alias GaoBus.Config.{Accounts, Capture, Services, XML}

  defstruct policies: [],
            settings: %{},
            limits: %{},
            accounts: %{},
            sources: [],
            directives: [],
            captures: nil,
            services: %{directories: [], occurrences: [], selected: %{}},
            daemon_uid: nil

  @max_file_bytes 1_048_576
  @max_total_bytes 8_388_608
  @max_files 1024
  @max_include_depth 32
  @max_rules 10_000
  @limits ~w(max_incoming_bytes max_incoming_unix_fds max_outgoing_bytes max_outgoing_unix_fds max_message_size max_message_unix_fds service_start_timeout auth_timeout pending_fd_timeout max_completed_connections max_incomplete_connections max_connections_per_user max_pending_service_starts max_names_per_connection max_match_rules_per_connection max_replies_per_connection reply_timeout)
  @send ~w(send_interface send_member send_error send_broadcast send_destination send_destination_prefix send_type send_path send_requested_reply)
  @receive ~w(receive_interface receive_member receive_error receive_sender receive_type receive_path receive_requested_reply)
  @modifiers ~w(eavesdrop min_fds max_fds)
  @ownership ~w(own own_prefix)
  @admission ~w(user group)
  @booleans ~w(send_broadcast send_requested_reply receive_requested_reply eavesdrop)
  @types %{
    "method_call" => :method_call,
    "method_return" => :method_return,
    "error" => :error,
    "signal" => :signal
  }
  @scalar_settings %{
    "type" => :type,
    "user" => :user,
    "pidfile" => :pidfile,
    "servicehelper" => :servicehelper
  }
  @list_settings %{"auth" => :auth, "listen" => :listen, "servicedir" => :servicedir}
  @flags %{"fork" => :fork, "syslog" => :syslog, "keep_umask" => :keep_umask}

  def load(path, options \\ []) when is_binary(path) and is_list(options) do
    with {:ok, path} <- config_path(path) do
      load_file(path, options)
    end
  end

  defp load_file(path, options) do
    with {:ok, accounts, capture} <- Accounts.load_captured(options, Capture.new()) do
      state = %{
        config: %__MODULE__{accounts: accounts},
        captures: capture,
        active: MapSet.new(),
        files: 0,
        bytes: 0,
        rules: 0
      }

      origin = %{file: path, line: 1, element: "busconfig", occurrence: 1, include_chain: []}

      try do
        state = read(path, state, origin, 0)
        daemon_uid = Map.get(state.config.settings, :user, Keyword.get(options, :daemon_uid))
        if not Accounts.valid_id?(daemon_uid), do: reject(origin, :missing_daemon_uid)

        config = %{
          state.config
          | policies: Enum.reverse(state.config.policies),
            sources: Enum.reverse(state.config.sources),
            directives: Enum.reverse(state.config.directives),
            daemon_uid: daemon_uid
        }

        case Services.discover(config, state.captures) do
          {:ok, services, capture} -> {:ok, %{config | services: services, captures: capture}}
          failure -> failure
        end
      catch
        {:config_error, error} -> {:error, error}
      end
    end
  end

  defp read(path, state, origin, depth, optional \\ false) do
    if depth >= @max_include_depth, do: reject(origin, :include_depth_exceeded)
    if state.files >= @max_files, do: reject(origin, :include_count_exceeded)

    case Capture.read(state.captures, path, @max_file_bytes) do
      {:ok, record, capture} ->
        read_record(record, %{state | captures: capture}, origin, depth)

      {:error, %{reason: :enoent}, capture} when optional ->
        %{state | captures: capture}

      {:error, %{reason: reason}, _capture} ->
        reason =
          case reason do
            :file_byte_limit ->
              :xml_too_large

            :not_regular_file ->
              :not_regular_file

            reason when reason in [:file_changed, :directory_changed] ->
              :configuration_changed_during_read

            reason ->
              {:file_error, reason}
          end

        reject(origin, reason)
    end
  end

  defp read_record(record, state, origin, depth) do
    path = record.path
    identity = {record.identity.before.device, record.identity.before.inode}
    if MapSet.member?(state.active, identity), do: reject(origin, :include_cycle)
    bytes = record.bytes

    if state.bytes + record.bytes_read > @max_total_bytes,
      do: reject(origin, :config_bytes_exceeded)

    occurrence = state.files + 1

    chain =
      if origin.element in ["include", "includedir"],
        do: Map.get(origin, :include_chain, []) ++ [Map.delete(origin, :include_chain)],
        else: []

    tree =
      case XML.parse(bytes, path) do
        {:ok, tree} ->
          source_context(tree, occurrence, chain)

        {:error, error} ->
          throw(
            {:config_error, Map.merge(error, %{occurrence: occurrence, include_chain: chain})}
          )
      end

    if tree.name != "busconfig", do: reject(provenance(path, tree), :invalid_root)
    container!(path, tree, [])

    source = %{
      file: path,
      path: path,
      occurrence: occurrence,
      line: tree.line,
      element: tree.name,
      include_chain: chain,
      sha256: record.sha256,
      identity: record.identity.before,
      read_identity: record.identity,
      directory: record.directory,
      bytes_read: record.bytes_read,
      syscall_attempts: record.syscall_attempts,
      read_attempts: record.read_attempts
    }

    config = %{state.config | sources: [source | state.config.sources]}

    state = %{
      state
      | config: config,
        files: occurrence,
        bytes: state.bytes + byte_size(bytes),
        active: MapSet.put(state.active, identity)
    }

    state = Enum.reduce(tree.children, state, &element(&1, path, &2, depth))
    %{state | active: MapSet.delete(state.active, identity)}
  end

  defp element(%{name: "include"} = node, file, state, depth) do
    text = leaf!(file, node, ["ignore_missing"])

    optional =
      case Map.get(node.attributes, "ignore_missing", "no") do
        "yes" -> true
        "no" -> false
        _ -> reject(provenance(file, node), :invalid_ignore_missing)
      end

    path = Path.expand(text, Path.dirname(file))

    read(path, state, provenance(file, node), depth + 1, optional)
  end

  defp element(%{name: "includedir"} = node, file, state, depth) do
    text = leaf!(file, node, [])
    directory = Path.expand(text, Path.dirname(file))

    {entries, capture} =
      case Capture.list(state.captures, directory) do
        {:ok, listing, capture} ->
          {listing.names, capture}

        {:error, %{reason: :enoent}, capture} ->
          {[], capture}

        {:error, %{reason: reason}, _capture} ->
          reject(provenance(file, node), {:directory_error, reason})
      end

    state = %{state | captures: capture}

    entries
    |> Enum.filter(&String.ends_with?(&1, ".conf"))
    |> Enum.sort()
    |> Enum.reduce(state, fn name, state ->
      read(Path.join(directory, name), state, provenance(file, node), depth + 1)
    end)
  end

  defp element(%{name: "policy"} = node, file, state, _depth) do
    container!(file, node, ["context", "user", "group", "at_console"])
    selector = selector(node, file, state.config.accounts)
    rules = Enum.map(node.children, &rule(&1, file, selector, state.config.accounts))

    if state.rules + length(rules) > @max_rules,
      do: reject(provenance(file, node), :rule_count_exceeded)

    policy = %{selector: selector, rules: rules, provenance: provenance(file, node)}

    %{
      state
      | config: %{state.config | policies: [policy | state.config.policies]},
        rules: state.rules + length(rules)
    }
  end

  defp element(%{name: "limit"} = node, file, state, _depth) do
    text = leaf!(file, node, ["name"])
    name = Map.get(node.attributes, "name")
    if name not in @limits, do: reject(provenance(file, node), {:unsupported_limit, name})
    value = number!(text, file, node, 0x7FFFFFFFFFFFFFFF)
    state = %{state | config: %{state.config | limits: Map.put(state.config.limits, name, value)}}
    directive(state, :limit, name, value, file, node)
  end

  defp element(%{name: "apparmor"} = node, file, state, _depth) do
    empty!(file, node, ["mode"])

    if node.attributes != %{"mode" => "disabled"},
      do: reject(provenance(file, node), :unsupported_mac_enforcement)

    setting(state, :apparmor, :disabled, :disabled, file, node)
  end

  defp element(%{name: name} = node, file, state, _depth)
       when is_map_key(@scalar_settings, name) do
    text = leaf!(file, node, [])

    value =
      case name do
        "type" ->
          case text do
            "system" -> :system
            "session" -> :session
            _ -> reject(provenance(file, node), :unsupported_bus_type)
          end

        "user" ->
          account!(state.config.accounts, :users, text, file, node)

        _ ->
          path!(text, file, node)
      end

    declaration = if name == "user", do: text, else: value
    setting(state, Map.fetch!(@scalar_settings, name), value, declaration, file, node)
  end

  defp element(%{name: name} = node, file, state, _depth) when is_map_key(@list_settings, name) do
    text = leaf!(file, node, [])

    value =
      case name do
        "auth" ->
          if text == "EXTERNAL",
            do: text,
            else: reject(provenance(file, node), :unsupported_auth_mechanism)

        "listen" ->
          if Regex.match?(~r/\Aunix:(?:path|abstract)=[^,\x00]+\z/, text),
            do: text,
            else: reject(provenance(file, node), :unsupported_listen_address)

        "servicedir" ->
          path!(text, file, node)
      end

    key = Map.fetch!(@list_settings, name)
    values = Map.get(state.config.settings, key, []) ++ [value]
    setting(state, key, values, value, file, node)
  end

  defp element(%{name: name} = node, file, state, _depth) when is_map_key(@flags, name) do
    empty!(file, node, [])
    setting(state, Map.fetch!(@flags, name), true, true, file, node)
  end

  defp element(node, file, _state, _depth),
    do: reject(provenance(file, node), {:unsupported_element, node.name})

  defp selector(node, file, accounts) do
    case Map.to_list(node.attributes) do
      [{"context", "default"}] -> :default
      [{"context", "mandatory"}] -> :mandatory
      [{"user", value}] -> {:uid, account!(accounts, :users, value, file, node)}
      [{"group", value}] -> {:gid, account!(accounts, :groups, value, file, node)}
      [{"at_console", value}] -> {:at_console, boolean!(value, file, node)}
      _ -> reject(provenance(file, node), :invalid_policy_selector)
    end
  end

  defp rule(node, file, selector, accounts) do
    effect =
      case node.name do
        "allow" -> :allow
        "deny" -> :deny
        _ -> reject(provenance(file, node), :invalid_policy_element)
      end

    empty!(file, node, @send ++ @receive ++ @modifiers ++ @ownership ++ @admission)
    keys = Map.keys(node.attributes)
    send? = Enum.any?(keys, &(&1 in @send))
    receive? = Enum.any?(keys, &(&1 in @receive)) or keys == ["eavesdrop"]
    own? = Enum.any?(keys, &(&1 in @ownership))
    admission? = Enum.any?(keys, &(&1 in @admission))

    if Enum.count([send?, receive?, own?, admission?], & &1) != 1,
      do: reject(provenance(file, node), :mixed_or_missing_rule_family)

    if (own? or admission?) and length(keys) != 1,
      do: reject(provenance(file, node), :invalid_rule_modifiers)

    if "send_destination" in keys and "send_destination_prefix" in keys,
      do: reject(provenance(file, node), :conflicting_destination_attributes)

    if admission? and selector not in [:default, :mandatory],
      do: reject(provenance(file, node), :invalid_admission_policy_class)

    attributes =
      Map.new(node.attributes, fn {key, value} ->
        {key, attribute!(key, value, accounts, file, node)}
      end)

    if not valid_message_combination?(attributes),
      do: reject(provenance(file, node), :invalid_rule_combination)

    if Map.get(attributes, "min_fds", 0) > Map.get(attributes, "max_fds", 0xFFFFFFFF),
      do: reject(provenance(file, node), :invalid_fd_range)

    %{effect: effect, attributes: attributes, provenance: provenance(file, node)}
  end

  defp valid_message_combination?(attributes) do
    Enum.all?(["send", "receive"], fn direction ->
      member? = Map.has_key?(attributes, direction <> "_member")
      interface? = Map.has_key?(attributes, direction <> "_interface")
      path? = Map.has_key?(attributes, direction <> "_path")
      error? = Map.has_key?(attributes, direction <> "_error")
      (not member? or interface? or path?) and (not error? or (not member? and not interface?))
    end) and
      not (Map.get(attributes, "send_broadcast") == true and
             Map.get(attributes, "send_destination") not in [nil, "*"])
  end

  defp attribute!(key, value, _accounts, file, node) when key in @booleans,
    do: boolean!(value, file, node)

  defp attribute!(key, value, _accounts, file, node) when key in ["min_fds", "max_fds"],
    do: number!(value, file, node, 0xFFFFFFFF)

  defp attribute!(key, value, accounts, file, node) when key in @admission do
    if value == "*",
      do: value,
      else: account!(accounts, if(key == "user", do: :users, else: :groups), value, file, node)
  end

  defp attribute!(key, value, _accounts, file, node) when key in ["send_type", "receive_type"] do
    case value do
      "*" ->
        value

      value ->
        case Map.fetch(@types, value) do
          {:ok, type} -> type
          :error -> reject(provenance(file, node), :invalid_message_type)
        end
    end
  end

  defp attribute!(key, value, _accounts, file, node) do
    valid =
      byte_size(value) in 1..255 and String.valid?(value) and not String.contains?(value, <<0>>) and
        (value == "*" or valid_text_match?(key, value))

    if not valid or (key in ["own_prefix", "send_destination_prefix"] and value == "*"),
      do: reject(provenance(file, node), {:invalid_attribute_value, key})

    value
  end

  defp valid_text_match?(key, value) when key in ["send_member", "receive_member"],
    do: Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_]*\z/, value)

  defp valid_text_match?(key, value) when key in ["send_path", "receive_path"],
    do: value == "/" or Regex.match?(~r/\A(?:\/[A-Za-z0-9_]+)+\z/, value)

  defp valid_text_match?(key, value) when key in ["own_prefix", "send_destination_prefix"],
    do: Regex.match?(~r/\A[A-Za-z_-][A-Za-z0-9_-]*(?:\.[A-Za-z_-][A-Za-z0-9_-]*)*\z/, value)

  defp valid_text_match?(key, ":" <> value) when key in ["send_destination", "receive_sender"],
    do: Regex.match?(~r/\A[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\z/, value)

  defp valid_text_match?(_key, value),
    do: Regex.match?(~r/\A[A-Za-z_-][A-Za-z0-9_-]*(?:\.[A-Za-z_-][A-Za-z0-9_-]*)+\z/, value)

  defp boolean!("true", _file, _node), do: true
  defp boolean!("false", _file, _node), do: false
  defp boolean!(_value, file, node), do: reject(provenance(file, node), :invalid_boolean)

  defp number!(text, file, node, maximum) do
    case Integer.parse(text) do
      {value, ""} when value >= 0 and value <= maximum -> value
      _ -> reject(provenance(file, node), :invalid_finite_integer)
    end
  end

  defp account!(accounts, kind, value, file, node) do
    case Accounts.resolve(accounts, kind, value) do
      {:ok, id} -> id
      {:error, reason} -> reject(provenance(file, node), reason)
    end
  end

  defp path!(text, file, node) do
    if String.contains?(text, <<0>>), do: reject(provenance(file, node), :invalid_path)
    Path.expand(text, Path.dirname(file))
  end

  @doc "Effective directive origins in XML expansion order; shadowed declarations remain in directives."
  def directive_origins(%__MODULE__{} = config, kind, name) when not is_list(name),
    do: directive_origins(config, kind, [name])

  def directive_origins(%__MODULE__{directives: directives}, kind, names) when is_list(names) do
    indexed = Enum.with_index(directives)

    latest =
      Map.new(indexed, fn {directive, index} -> {{directive.kind, directive.name}, index} end)

    for {directive, index} <- indexed,
        directive.kind == kind and directive.name in names,
        (kind == :setting and directive.name in Map.values(@list_settings)) or
          Map.fetch!(latest, {kind, directive.name}) == index,
        do: directive.provenance
  end

  defp setting(state, key, value, declaration, file, node) do
    state = %{
      state
      | config: %{state.config | settings: Map.put(state.config.settings, key, value)}
    }

    directive(state, :setting, key, declaration, file, node)
  end

  defp directive(state, kind, name, value, file, node) do
    declaration = %{kind: kind, name: name, value: value, provenance: provenance(file, node)}
    %{state | config: %{state.config | directives: [declaration | state.config.directives]}}
  end

  defp source_context(node, occurrence, chain) do
    node
    |> Map.put(:occurrence, occurrence)
    |> Map.put(:include_chain, chain)
    |> Map.update!(
      :children,
      &Enum.map(&1, fn child -> source_context(child, occurrence, chain) end)
    )
  end

  defp container!(file, node, allowed) do
    attributes!(file, node, allowed)
    if String.trim(node.text) != "", do: reject(provenance(file, node), :unexpected_text)
  end

  defp leaf!(file, node, allowed) do
    attributes!(file, node, allowed)
    if node.children != [], do: reject(provenance(file, node), :unexpected_child)
    text = String.trim(node.text)
    if text == "", do: reject(provenance(file, node), :missing_text)
    text
  end

  defp empty!(file, node, allowed) do
    container!(file, node, allowed)
    if node.children != [], do: reject(provenance(file, node), :unexpected_child)
  end

  defp attributes!(file, node, allowed) do
    case Map.keys(node.attributes) -- allowed do
      [] -> :ok
      keys -> reject(provenance(file, node), {:unsupported_attributes, keys})
    end
  end

  defp provenance(file, node),
    do:
      Map.merge(
        %{file: file, line: node.line, element: node.name},
        Map.take(node, [:occurrence, :include_chain])
      )

  defp reject(origin, reason), do: throw({:config_error, Map.put(origin, :reason, reason)})

  defp config_path(path) do
    if byte_size(path) in 1..4096 and String.valid?(path) and
         :binary.match(path, <<0>>) == :nomatch do
      expanded = Path.expand(path)

      if byte_size(expanded) <= 4096,
        do: {:ok, expanded},
        else: {:error, %{file: nil, line: 1, element: "busconfig", reason: :invalid_path}}
    else
      {:error, %{file: nil, line: 1, element: "busconfig", reason: :invalid_path}}
    end
  end
end
