defmodule GaoBus.Policy.XML do
  @moduledoc """
  Pure evaluation of ordered dbus-daemon XML policy classes.

  Admission uses the frozen local account database. Per-connection group selectors
  prefer immutable kernel process groups, falling back to accounts when unsupported.
  Unexpected kernel group failures deny group-dependent operations.
  Message permissions start denied; system/session defaults come from their XML.
  Console policies are rejected until a trustworthy console identity is available.
  """

  defstruct [:blocks, :daemon_uid, :memberships, configuration: nil, needs_groups: false]

  @send [
    "send_interface",
    "send_member",
    "send_error",
    "send_broadcast",
    "send_destination",
    "send_destination_prefix",
    "send_type",
    "send_path",
    "send_requested_reply"
  ]
  @receive [
    "receive_interface",
    "receive_member",
    "receive_error",
    "receive_sender",
    "receive_type",
    "receive_path",
    "receive_requested_reply"
  ]
  @modifiers ["eavesdrop", "min_fds", "max_fds"]
  @attributes @send ++ @receive ++ @modifiers ++ ["own", "own_prefix", "user", "group"]
  @booleans ["eavesdrop", "send_broadcast", "send_requested_reply", "receive_requested_reply"]
  @types [:method_call, :method_return, :error, :signal]

  def compile(policies, opts) when is_list(policies) and length(policies) <= 10_000 do
    uid = Keyword.get(opts, :daemon_uid)
    memberships = Keyword.get(opts, :memberships, %{})

    if valid_id?(uid) and valid_memberships?(memberships) do
      policies
      |> Enum.reduce_while({:ok, [], 0}, fn block, {:ok, blocks, count} ->
        case compile_block(block, 10_000 - count) do
          {:ok, compiled} when count + length(compiled.rules) <= 10_000 ->
            {:cont, {:ok, [compiled | blocks], count + length(compiled.rules)}}

          {:ok, _} ->
            {:halt, error(block, :policy_limit)}

          {:error, _} = failure ->
            {:halt, failure}
        end
      end)
      |> case do
        {:ok, blocks, _} ->
          blocks = blocks |> Enum.reverse() |> Enum.sort_by(&class(&1.selector))
          needs_groups = Enum.any?(blocks, &group_block?/1)

          {:ok,
           %__MODULE__{
             blocks: blocks,
             daemon_uid: uid,
             memberships: memberships,
             needs_groups: needs_groups
           }}

        failure ->
          failure
      end
    else
      error(%{}, :invalid_account_snapshot)
    end
  end

  def compile(_, _), do: error(%{}, :invalid_policy)

  # dbus-daemon 1.14.10 driver.c applies no separate privileged-caller flag to
  # ReloadConfig. Its configured send permission is the authorization boundary.
  def authorize(
        %__MODULE__{} = policy,
        :control,
        %{
          control: :reload,
          message: %{
            type: :method_call,
            interface: "org.freedesktop.DBus",
            member: "ReloadConfig"
          }
        } = context
      ),
      do: authorize(policy, :send, context)

  def authorize(
        %__MODULE__{daemon_uid: daemon_uid} = policy,
        :control,
        %{
          control: :activation_environment,
          credentials: %{uid: uid},
          message: %{
            type: :method_call,
            interface: "org.freedesktop.DBus",
            member: "UpdateActivationEnvironment"
          }
        } = context
      )
      when uid in [0, daemon_uid],
      do: authorize(policy, :send, context)

  def authorize(
        %__MODULE__{daemon_uid: daemon_uid} = policy,
        :monitor,
        %{
          control: :monitor,
          credentials: %{uid: uid},
          message: %{
            type: :method_call,
            interface: "org.freedesktop.DBus.Monitoring",
            member: "BecomeMonitor"
          }
        } = context
      )
      when uid in [0, daemon_uid],
      do: authorize(policy, :send, context)

  def authorize(
        %__MODULE__{} = policy,
        :activate,
        %{
          control: :start_service,
          message: %{
            type: :method_call,
            interface: "org.freedesktop.DBus",
            member: "StartServiceByName"
          }
        } = context
      ),
      do: authorize(policy, :send, context)

  def authorize(
        %__MODULE__{
          blocks: blocks,
          memberships: memberships,
          daemon_uid: daemon_uid,
          needs_groups: needs_groups
        } = policy,
        action,
        %{credentials: %{uid: uid} = credentials} = context
      )
      when is_integer(uid) and uid >= 0 and uid < 0xFFFFFFFF and
             is_list(blocks) and length(blocks) <= 10_000 and is_map(memberships) and
             map_size(memberships) <= 65_536 and
             is_boolean(needs_groups) and is_integer(daemon_uid) and
             daemon_uid >= 0 and daemon_uid < 0xFFFFFFFF do
    process_groups_required =
      Enum.any?(blocks, fn block ->
        match?({:gid, _}, block.selector) and Enum.any?(block.rules, &(&1.action == action))
      end)

    if action != :connect and process_groups_required and
         Map.has_key?(credentials, :groups_error) do
      :deny
    else
      account_groups =
        Map.get(memberships, uid, if(action == :connect or needs_groups, do: nil, else: []))

      groups =
        if action == :connect,
          do: account_groups,
          else: Map.get(credentials, :groups, account_groups)

      if is_list(groups) and length(groups) <= 65_537 and Enum.all?(groups, &valid_id?/1) do
        evaluate(policy, action, context, groups)
      else
        :deny
      end
    end
  rescue
    _error in [ArgumentError, BadMapError, KeyError, FunctionClauseError, Protocol.UndefinedError] ->
      :deny
  end

  def authorize(_, _, _), do: :deny

  defp initial(:connect, uid, uid), do: :allow
  defp initial(_, _, _), do: :deny

  defp evaluate(policy, action, context, groups) do
    Enum.reduce_while(
      policy.blocks,
      {:ok, initial(action, context.credentials.uid, policy.daemon_uid), 0, false, -1},
      fn block, {:ok, decision, count, needs_groups, previous_class} ->
        if valid_compiled_block?(block, 10_000 - count) and
             class(block.selector) >= previous_class do
          required = needs_groups or group_block?(block)

          if required and not Map.has_key?(policy.memberships, context.credentials.uid) and
               (action == :connect or not Map.has_key?(context.credentials, :groups)) do
            {:halt, :deny}
          else
            decision =
              if selected?(block.selector, context.credentials.uid, groups) do
                Enum.reduce(block.rules, decision, fn rule, current ->
                  if rule.action == action and matches?(rule, context, groups),
                    do: rule.effect,
                    else: current
                end)
              else
                decision
              end

            {:cont, {:ok, decision, count + length(block.rules), required, class(block.selector)}}
          end
        else
          {:halt, :deny}
        end
      end
    )
    |> case do
      {:ok, decision, _, needs_groups, _} when needs_groups == policy.needs_groups -> decision
      _ -> :deny
    end
  end

  defp valid_compiled_block?(%{selector: selector, rules: rules} = block, budget)
       when map_size(block) in [2, 3] and is_list(rules) do
    metadata_keys?(block, [:selector, :rules]) and valid_selector?(selector) and
      length(rules) <= budget and
      Enum.all?(rules, &valid_compiled_rule?(&1, selector))
  end

  defp valid_compiled_block?(_block, _budget), do: false

  defp valid_compiled_rule?(%{action: action, effect: effect, attributes: attrs} = rule, selector)
       when map_size(rule) in [3, 4] and effect in [:allow, :deny] and is_map(attrs) do
    metadata_keys?(rule, [:action, :effect, :attributes]) and
      valid_rule_attributes?(attrs, action) and action(attrs) == {:ok, action} and
      (action != :connect or selector in [:default, :mandatory])
  end

  defp valid_compiled_rule?(_rule, _selector), do: false

  defp compile_block(%{selector: selector, rules: rules} = block, budget) when is_list(rules) do
    cond do
      match?({:at_console, _}, selector) ->
        error(block, :unsupported_console_identity)

      not valid_selector?(selector) ->
        error(block, :invalid_selector)

      length(rules) > budget ->
        error(block, :policy_limit)

      true ->
        Enum.reduce_while(rules, {:ok, []}, fn rule, {:ok, acc} ->
          case compile_rule(rule, selector) do
            {:ok, compiled} -> {:cont, {:ok, [compiled | acc]}}
            failure -> {:halt, failure}
          end
        end)
        |> case do
          {:ok, compiled} ->
            retain_origin(block, %{selector: selector, rules: Enum.reverse(compiled)})

          failure ->
            failure
        end
    end
  end

  defp compile_block(block, _budget), do: error(block, :invalid_policy_block)

  defp compile_rule(%{effect: effect, attributes: attrs} = rule, selector)
       when effect in [:allow, :deny] and is_map(attrs) do
    with {:ok, action} <- action(attrs),
         true <- valid_rule_attributes?(attrs, action) do
      if action == :connect and selector not in [:default, :mandatory],
        do: error(rule, :invalid_admission_policy_class),
        else: retain_origin(rule, %{action: action, effect: effect, attributes: attrs})
    else
      _ -> error(rule, :invalid_rule_attributes)
    end
  end

  defp compile_rule(rule, _selector), do: error(rule, :invalid_rule)

  defp valid_rule_attributes?(attrs, action) do
    map_size(attrs) > 0 and Map.keys(attrs) -- @attributes == [] and
      Enum.all?(attrs, &valid_attribute?/1) and legal_combination?(action, attrs)
  end

  defp action(attrs) do
    keys = Map.keys(attrs)

    families =
      for {action, fields} <- [
            connect: ["user", "group"],
            own: ["own", "own_prefix"],
            send: @send,
            receive: @receive
          ],
          Enum.any?(fields, &(&1 in keys)),
          do: action

    case families do
      [action] -> {:ok, action}
      [] when keys == ["eavesdrop"] -> {:ok, :receive}
      _ -> {:error, :mixed_action_families}
    end
  end

  defp legal_combination?(:connect, attrs), do: map_size(attrs) == 1
  defp legal_combination?(:own, attrs), do: map_size(attrs) == 1

  defp legal_combination?(:send, attrs),
    do:
      valid_message_combination?(attrs) and
        not (Map.has_key?(attrs, "send_destination") and
               Map.has_key?(attrs, "send_destination_prefix"))

  defp legal_combination?(:receive, attrs), do: valid_message_combination?(attrs)
  defp legal_combination?(_action, _attrs), do: false

  defp valid_message_combination?(attrs) do
    Enum.all?(["send", "receive"], fn direction ->
      member? = Map.has_key?(attrs, direction <> "_member")
      interface? = Map.has_key?(attrs, direction <> "_interface")
      path? = Map.has_key?(attrs, direction <> "_path")
      error? = Map.has_key?(attrs, direction <> "_error")
      (not member? or interface? or path?) and (not error? or (not member? and not interface?))
    end) and
      not (Map.get(attrs, "send_broadcast") == true and
             Map.get(attrs, "send_destination") not in [nil, "*"]) and
      Map.get(attrs, "min_fds", 0) <= Map.get(attrs, "max_fds", 0xFFFFFFFF)
  end

  defp valid_attribute?({key, value}) when key in @booleans, do: is_boolean(value)

  defp valid_attribute?({key, value}) when key in ["min_fds", "max_fds"],
    do: is_integer(value) and value >= 0 and value <= 0xFFFFFFFF

  defp valid_attribute?({key, value}) when key in ["user", "group"],
    do: value == "*" or valid_id?(value)

  defp valid_attribute?({key, value}) when key in ["send_type", "receive_type"],
    do: value == "*" or value in @types

  defp valid_attribute?({_key, value}),
    do:
      is_binary(value) and byte_size(value) in 1..255 and String.valid?(value) and
        not String.contains?(value, <<0>>)

  defp valid_selector?(selector) when selector in [:default, :mandatory], do: true
  defp valid_selector?({type, value}) when type in [:uid, :gid], do: valid_id?(value)
  defp valid_selector?(_), do: false
  defp valid_id?(value), do: is_integer(value) and value >= 0 and value < 0xFFFFFFFF

  defp valid_memberships?(memberships) when is_map(memberships),
    do:
      map_size(memberships) <= 65_536 and
        Enum.all?(memberships, fn {uid, gids} ->
          valid_id?(uid) and is_list(gids) and length(gids) <= 65_536 and
            Enum.all?(gids, &valid_id?/1)
        end)

  defp valid_memberships?(_), do: false

  defp class(:default), do: 0
  defp class({:gid, _}), do: 1
  defp class({:uid, _}), do: 2
  defp class(:mandatory), do: 3
  defp selected?(:default, _, _), do: true
  defp selected?(:mandatory, _, _), do: true
  defp selected?({:uid, uid}, uid, _), do: true
  defp selected?({:gid, gid}, _, groups), do: gid in groups
  defp selected?(_, _, _), do: false

  defp group_block?(%{selector: {:gid, _}}), do: true
  defp group_block?(block), do: Enum.any?(block.rules, &Map.has_key?(&1.attributes, "group"))

  defp matches?(%{action: :connect, attributes: attrs}, context, groups) do
    Enum.all?(attrs, fn
      {_, "*"} -> true
      {"user", uid} -> uid == context.credentials.uid
      {"group", gid} -> gid in groups
    end)
  end

  defp matches?(%{action: :own, attributes: attrs}, context, _groups) do
    Enum.all?(attrs, fn
      {"own", expected} -> textual?(Map.get(context, :name), expected)
      {"own_prefix", prefix} -> prefix?(Map.get(context, :name), prefix)
    end)
  end

  defp matches?(rule, %{message: message} = context, _groups) when is_map(message) do
    Enum.all?(rule.attributes, &match_attribute?(&1, rule, context)) and reply?(rule, context) and
      eavesdrop?(rule, context)
  end

  defp matches?(_, _, _), do: false

  defp match_attribute?({key, _value}, _rule, _context)
       when key in ["send_requested_reply", "receive_requested_reply", "eavesdrop"],
       do: true

  defp match_attribute?({"user", _}, _, _), do: false
  defp match_attribute?({"group", _}, _, _), do: false

  defp match_attribute?({"min_fds", min}, _, context),
    do: length(Map.get(context.message, :fds, [])) >= min

  defp match_attribute?({"max_fds", max}, _, context),
    do: length(Map.get(context.message, :fds, [])) <= max

  defp match_attribute?({"send_broadcast", expected}, _, context),
    do:
      (context.message.type == :signal and Map.get(context.message, :destination) == nil) ==
        expected

  defp match_attribute?({"send_destination", expected}, _, context),
    do:
      names?(
        Map.get(context, :destination_policy_names, Map.get(context, :destination_names, [])),
        expected
      )

  defp match_attribute?({"send_destination_prefix", prefix}, _, context),
    do:
      Enum.any?(
        Map.get(context, :destination_policy_names, Map.get(context, :destination_names, [])),
        &prefix?(&1, prefix)
      )

  defp match_attribute?({"receive_sender", expected}, _, context),
    do:
      names?(
        Map.get(context, :sender_policy_names, Map.get(context, :sender_names, [])),
        expected
      )

  defp match_attribute?({key, expected}, rule, context) do
    field = field(key)
    actual = Map.get(context.message, field)

    cond do
      expected == "*" -> true
      field == :interface and actual == nil -> rule.effect == :deny
      field in [:path, :member, :error_name] and actual == nil -> true
      true -> actual == expected
    end
  end

  defp field(key) when key in ["send_interface", "receive_interface"], do: :interface
  defp field(key) when key in ["send_member", "receive_member"], do: :member
  defp field(key) when key in ["send_path", "receive_path"], do: :path
  defp field(key) when key in ["send_error", "receive_error"], do: :error_name
  defp field(key) when key in ["send_type", "receive_type"], do: :type

  defp reply?(rule, context) do
    if context.message.type in [:method_return, :error] do
      key = if rule.action == :send, do: "send_requested_reply", else: "receive_requested_reply"
      modifier = Map.get(rule.attributes, key, rule.effect == :allow)
      requested = Map.get(context, :requested_reply, false)

      case rule.effect do
        :allow -> requested or not modifier or Map.get(rule.attributes, "eavesdrop", false)
        :deny -> not requested or modifier
      end
    else
      true
    end
  end

  defp eavesdrop?(%{action: :send}, _context), do: true

  defp eavesdrop?(rule, context) do
    eavesdrop = Map.get(context, :eavesdrop, false)
    modifier = Map.get(rule.attributes, "eavesdrop", false)
    if rule.effect == :allow, do: not eavesdrop or modifier, else: eavesdrop or not modifier
  end

  defp textual?(_actual, "*"), do: true
  defp textual?(actual, expected), do: actual == expected
  defp names?(_names, "*"), do: true
  defp names?(names, expected), do: expected in names

  defp prefix?(value, prefix) when is_binary(value),
    do: value == prefix or String.starts_with?(value, prefix <> ".")

  defp prefix?(_, _), do: false

  defp error(source, reason) do
    provenance = if is_map(source), do: Map.get(source, :provenance, %{}), else: %{}

    provenance =
      cond do
        valid_origin?(provenance) ->
          provenance

        is_map(provenance) ->
          legacy = Map.take(provenance, [:file, :line])
          if valid_origin?(legacy), do: legacy, else: %{}

        true ->
          %{}
      end

    {:error, Map.merge(%{file: nil, line: nil, element: "policy", reason: reason}, provenance)}
  end

  defp retain_origin(source, compiled) do
    case Map.fetch(source, :provenance) do
      :error ->
        {:ok, compiled}

      {:ok, origin} ->
        if valid_origin?(origin),
          do: {:ok, Map.put(compiled, :provenance, origin)},
          else: error(source, :invalid_provenance)
    end
  end

  defp metadata_keys?(compiled, keys) do
    Map.keys(compiled) -- (keys ++ [:provenance]) == [] and
      (not Map.has_key?(compiled, :provenance) or valid_origin?(compiled.provenance))
  end

  defp valid_origin?(%{file: file, line: line} = origin) when map_size(origin) == 2,
    do: origin_location?(file, line)

  defp valid_origin?(
         %{file: file, line: line, element: element, occurrence: occurrence, include_chain: chain} =
           origin
       )
       when map_size(origin) == 5 do
    origin_location?(file, line) and origin_element?(element) and
      is_integer(occurrence) and occurrence in 1..1024 and valid_chain?(chain, 32)
  end

  defp valid_origin?(_), do: false

  defp origin_location?(file, line),
    do:
      is_binary(file) and byte_size(file) in 1..4096 and String.valid?(file) and
        :binary.match(file, <<0>>) == :nomatch and is_integer(line) and line in 1..1_048_577

  defp origin_element?(element),
    do:
      is_binary(element) and byte_size(element) in 1..255 and String.valid?(element) and
        :binary.match(element, <<0>>) == :nomatch

  defp valid_chain?([], _remaining), do: true

  defp valid_chain?(
         [%{file: file, line: line, element: element, occurrence: occurrence} = origin | rest],
         remaining
       )
       when remaining > 0 and map_size(origin) == 4 do
    origin_location?(file, line) and origin_element?(element) and
      is_integer(occurrence) and occurrence in 1..1024 and valid_chain?(rest, remaining - 1)
  end

  defp valid_chain?(_, _remaining), do: false
end
