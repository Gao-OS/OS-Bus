# Scoped disposable-guest adapter: original quota daemon bytes remain unchanged.
[socket, _collector, original_path] = System.argv()
"/run/osbus-fd-quotas/bus" = socket
"isolated-vm\n" = File.read!("/etc/osbus-security-guest")
source = File.read!(original_path)
source_sha = Base.encode16(:crypto.hash(:sha256, source), case: :lower)
"b9b62c9d3cf98cfb49f5dbbf571c2dd2afb865bdaddb2aadb24dfeb103edc815" = source_sha
provenance = %{
  original_sha256: source_sha,
  executed_sha256: Base.encode16(:crypto.hash(:sha256, File.read!(__ENV__.file)), case: :lower),
  exact_replacements: %{rules: 1, snapshot: 1, ready: 1}
}

rules_before = ~S"""
rules =
  for uid <- [0, 1100, 1101],
      action <- [:connect, :send, :receive],
      do: %{action: action, effect: :allow, match: %{uid: uid}}
"""
rules_after = ~S"""
rules =
  (for uid <- [0, 1100, 1101],
       action <- [:connect, :send, :receive],
       do: %{action: action, effect: :allow, match: %{uid: uid}}) ++
    [%{action: :send, effect: :deny,
       match: %{uid: 1100, type: :method_call, interface: "org.foundation.Broadcast"}}]
"""
snapshot_before = ~S"""
{:ok, _} = Application.ensure_all_started(:gao_bus)
"""
snapshot_after = ~S"""
{:ok, _} = Application.ensure_all_started(:gao_bus)
{:ok, policy_generation, effective_rules} = GaoBus.Policy.snapshot()
true = effective_rules == rules
"""
ready_before = ~S"""
emit(%{
  event: "ready",
  pid: System.pid(),
  config_file: nil,
  profile: "system",
  resource_limits: limits,
  send_timeout_ms: 5000,
  watcher: watcher_ready
})
"""
ready_after = ~S"""
emit(%{
  event: "ready",
  pid: System.pid(),
  config_file: nil,
  profile: "system",
  resource_limits: limits,
  send_timeout_ms: 5000,
  watcher: watcher_ready,
  policy_generation: policy_generation,
  policy_rules: Enum.map(effective_rules, fn rule ->
    %{action: Atom.to_string(rule.action), effect: Atom.to_string(rule.effect),
      match: Map.new(rule.match, fn {key, value} ->
        {key, if(is_atom(value), do: Atom.to_string(value), else: value)}
      end)}
  end),
  policy_adapter: __policy_provenance__
})
"""
normalize = fn ast ->
  Macro.prewalk(ast, fn
    {name, metadata, arguments} when is_list(metadata) -> {name, [], arguments}
    other -> other
  end)
end
replacements =
  Enum.map([{:rules, rules_before, rules_after}, {:snapshot, snapshot_before, snapshot_after},
            {:ready, ready_before, ready_after}], fn {key, before, after_source} ->
    replacement = Code.string_to_quoted!(after_source)
    replacement =
      if key == :ready do
        {replacement, 1} = Macro.postwalk(replacement, 0, fn
          {:__policy_provenance__, _, nil}, count -> {Macro.escape(provenance), count + 1}
          node, count -> {node, count}
        end)
        replacement
      else
        replacement
      end
    {key, normalize.(Code.string_to_quoted!(before)), replacement}
  end)
{adapted, counts} =
  Macro.postwalk(Code.string_to_quoted!(source), %{rules: 0, snapshot: 0, ready: 0}, fn node, counts ->
    case Enum.find(replacements, fn {_key, before, _after} -> normalize.(node) == before end) do
      {key, _before, replacement} -> {replacement, Map.update!(counts, key, &(&1 + 1))}
      nil -> {node, counts}
    end
  end)
%{rules: 1, snapshot: 1, ready: 1} = counts
Code.eval_quoted(adapted, [], file: original_path)
