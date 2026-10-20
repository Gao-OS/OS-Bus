defmodule GaoBus.BroadcastDeliveryTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry}

  @moduletag timeout: 20_000
  @actor Path.expand("fixtures/broadcast_delivery_actor.py", __DIR__)
  @interface "org.foundation.Broadcast"

  setup tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(System.tmp_dir!(), "gb-broadcast-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    uid = GaoBus.Unix.Native.identity().uid

    rules =
      Enum.map([:connect, :own, :send, :receive], fn action ->
        %{action: action, effect: :allow, match: %{uid: uid}}
      end)

    rules =
      if tags[:deny_broadcast] do
        rules ++
          [
            %{
              action: :receive,
              effect: :deny,
              match: %{uid: uid, type: :signal, interface: @interface}
            }
          ]
      else
        rules
      end

    rules =
      if action = tags[:deny_call] do
        rules ++
          [
            %{
              action: action,
              effect: :deny,
              match: %{uid: uid, type: :method_call, interface: @interface}
            }
          ]
      else
        rules
      end

    settings = [
      socket_path: path,
      config_file: nil,
      profile: :session,
      cluster: false,
      capability_restrictions: false,
      policy_rules: rules,
      resource_limits: %{}
    ]

    previous =
      Enum.map(settings, fn {key, _value} -> {key, Application.fetch_env(:gao_bus, key)} end)

    for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, saved} -> Application.put_env(:gao_bus, key, saved)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end

      File.rm_rf!(directory)
    end)

    start_supervised!(%{id: :broadcast_bus, start: {GaoBus.Application, :start, [:normal, []]}})
    %{path: path}
  end

  test "FD broadcast reaches negotiated recipient and rights0 reaches both negotiated and ordinary peers",
       ctx do
    run_actor(ctx, "mixed", 1, 2)
  end

  @tag deny_broadcast: true
  test "receive-denied broadcasts deliver no rights or payload and keep matched peers healthy",
       ctx do
    run_actor(ctx, "denied", 0, 0)
  end

  test "resource-bearing missing destination returns an error and reclaims actual descriptors",
       ctx do
    run_actor(ctx, "missing", 0, 0)
  end

  @tag deny_call: :send
  test "send-denied resource-bearing call delivers no descriptor and preserves healthy peers",
       ctx do
    run_actor(ctx, "send_denied", 0, 0)
  end

  @tag deny_call: :receive
  test "receive-denied resource-bearing call delivers no descriptor and preserves healthy peers",
       ctx do
    run_actor(ctx, "receive_denied", 0, 0)
  end

  defp run_actor(ctx, mode, resource_count, plain_count) do
    python = System.find_executable("python3") || flunk("required Python actor unavailable")

    actor =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 4096},
        args: ["-B", @actor, ctx.path, mode]
      ])

    on_exit(fn -> if Port.info(actor), do: Port.close(actor) end)

    assert %{"event" => "ready", "names" => names, "mode" => ^mode, "resource_name" => name} =
             actor_event(actor)

    assert length(names) == 3

    peers =
      Enum.map(names, fn name ->
        assert {:ok, pid} = NameRegistry.resolve(name)
        pid
      end)

    monitors = Map.new(peers, &{&1, Process.monitor(&1)})
    authorities = Map.new([GaoBus.Router, Limits, NameRegistry], &{&1, Process.whereis(&1)})
    await(fn -> idle_credits?(stats()) end)
    assert :ets.info(:gao_bus_match_rules, :size) == 2
    refute memfd_open?(name)
    before_fds = length(File.ls!("/proc/self/fd"))
    assert Port.command(actor, "continue\n")

    assert %{
             "event" => "checked",
             "mode" => ^mode,
             "resource_deliveries" => ^resource_count,
             "rights0_deliveries" => ^plain_count,
             "healthy_replies" => 6,
             "actor_fd_growth" => 0
           } = actor_event(actor)

    await(fn -> idle_credits?(stats()) end)
    for pid <- peers, do: :sys.get_state(pid)
    refute memfd_open?(name)
    assert length(File.ls!("/proc/self/fd")) == before_fds
    assert Map.new(Map.keys(authorities), &{&1, Process.whereis(&1)}) == authorities
    assert :sys.get_state(GaoBus.Router).pending.entries == %{}
    assert Port.command(actor, "continue\n")
    assert %{"event" => "closed"} = actor_event(actor)
    assert_receive {^actor, {:exit_status, 0}}, 5000

    for {pid, reference} <- monitors do
      assert_receive {:DOWN, ^reference, :process, ^pid, :normal}, 5000
    end

    await(fn ->
      usage = stats()

      usage.peers == %{} and usage.uids == %{} and usage.global.connections == 0 and
        idle_credits?(usage) and :ets.info(:gao_bus_match_rules, :size) == 0 and
        :sys.get_state(GaoBus.Router).pending.entries == %{}
    end)

    refute memfd_open?(name)
  end

  defp memfd_open?(name) do
    Enum.any?(File.ls!("/proc/self/fd"), fn descriptor ->
      case File.read_link("/proc/self/fd/" <> descriptor) do
        {:ok, target} -> String.contains?(target, "memfd:" <> name)
        {:error, :enoent} -> false
      end
    end)
  end

  defp stats do
    assert {:ok, usage} = Limits.snapshot()
    usage
  end

  defp idle_credits?(usage) do
    usage.reservations == 0 and
      Enum.all?(usage.global, fn {metric, count} -> metric == :connections or count == 0 end)
  end

  defp await(check), do: await(check, System.monotonic_time(:millisecond) + 1500)

  defp await(check, deadline) do
    unless check.() do
      assert System.monotonic_time(:millisecond) < deadline, "broadcast cleanup barrier deadline"
      await(check, deadline)
    end
  end

  defp actor_event(actor) do
    assert_receive {^actor, {:data, {:eol, line}}}, 5000
    Jason.decode!(line)
  end
end
