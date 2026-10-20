# H-04 uses the accepted SEC01 system-fixture startup, without its stdin channel.
[socket, policy, original] = System.argv()
source = File.read!(Path.join(original, "daemon.exs"))
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
"cba75169efa99be884ae758d64a690cc3a6e5fd28576adc5faf06260cdcd88fb" = digest.(source)
[prefix, _channel] = String.split(source, "Stream.repeatedly(fn -> IO.read(:stdio, :line) end)\n")
"44f0c5e68e97f7d2822830b85cbe4ca75126b14d34835fea52a7939922a24f59" = digest.(prefix)
System.argv([socket, policy])

for key <- [:config_file, :inherited_listener, :lifecycle],
    do: Application.delete_env(:gao_bus, key)

Application.put_env(:gao_bus, :lifecycle, :embedded)
Application.put_env(:gao_bus, :inherited_listener, false)
Application.put_env(:gao_bus, :max_connections, 256)
Code.eval_string(prefix, [], file: Path.join(original, "daemon.exs"))

receive do
  :never -> :ok
end
