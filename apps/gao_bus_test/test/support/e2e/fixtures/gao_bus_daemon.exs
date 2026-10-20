[socket_path] = System.argv()

unless Path.type(socket_path) == :absolute and Path.basename(socket_path) == "s" and
         String.starts_with?(Path.basename(Path.dirname(socket_path)), "gp") do
  raise "private Gao harness socket required"
end

Application.put_env(:gao_bus, :socket_path, socket_path)
Application.put_env(:gao_bus, :cluster, false)
Application.put_env(:gao_bus, :profile, :session)
rules = GaoBus.Policy.session_rules()
Application.put_env(:gao_bus, :policy_rules, rules)
policy_config = inspect(rules, limit: :infinity)
policy_sha256 = Base.encode16(:crypto.hash(:sha256, policy_config), case: :lower)
{:ok, _} = Application.ensure_all_started(:gao_bus)
IO.puts("E2E_GAO_READY #{policy_sha256} #{System.pid()} #{socket_path}")

receive do
  :never -> :ok
end
