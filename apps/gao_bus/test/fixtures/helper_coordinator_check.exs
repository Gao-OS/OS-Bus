ExUnit.start()

defmodule GaoBus.HelperCoordinatorFixtureTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Activation, Limits}

  @definition %{key: :fixture, backend: :helper, unit: nil}
  @suite System.fetch_env!("GAO_HELPER_COORDINATOR_SUITE")

  setup do
    assert List.to_string(:code.priv_dir(:gao_bus)) ==
             System.fetch_env!("GAO_HELPER_FIXTURE_PRIV")

    limits = start_supervised!({Limits, name: nil})
    workers = start_supervised!({DynamicSupervisor, strategy: :one_for_one})

    coordinator =
      start_supervised!(
        {Activation,
         name: nil,
         router: self(),
         limits: limits,
         helper_supervisor: workers,
         state_options: [max_live_children: 1, max_pending_service_starts: 1]}
      )

    assert {:ok, epoch} = Activation.epoch(coordinator)
    assert :ok = Limits.acquire(self(), %{uid: 1000, gid: 1000, pid: 123}, limits)

    %{
      limits: limits,
      coordinator: coordinator,
      workers: workers,
      epoch: epoch,
      incarnation: {make_ref(), ":1.1"}
    }
  end

  if @suite == "real" do
    test "unissued and non-Router attempts cannot create an observer", ctx do
      {waiter, message} = waiting(ctx, "org.fixture.Exit0")
      assert {:ok, key} = Activation.admit(waiter, message, @definition, ctx.coordinator)
      assert {:error, :not_issued} = invoke(:launch_helper, [key, ctx.coordinator])
      assert DynamicSupervisor.which_children(ctx.workers) == []
      parent = self()

      intruder =
        start_supervised!(
          {Task,
           fn ->
             send(parent, {:intruder, invoke(:launch_helper, [key, ctx.coordinator])})
           end}
        )

      assert_receive {:intruder, {:error, :not_router}}
      assert is_pid(intruder)
      assert DynamicSupervisor.which_children(ctx.workers) == []
      assert :ok = Activation.finish(key, waiter.request, {:terminal, :denied}, ctx.coordinator)
    end

    test "exact exit waits for Router acknowledgement and is not name readiness", ctx do
      {waiter, key} = issued(ctx, "org.fixture.Exit0")
      assert :ok = invoke(:launch_helper, [key, ctx.coordinator])
      assert_receive {:activation_event, coordinator, epoch, {:helper_result, ^key, token}}, 5000
      assert coordinator == ctx.coordinator
      assert epoch == ctx.epoch
      assert snapshot(ctx).bookkeeping.children[key].phase == :reserved
      assert snapshot(ctx).messages == 1
      assert DynamicSupervisor.which_children(ctx.workers) == []

      assert {:error, :unknown_helper_result} =
               invoke(:helper_result, [key, make_ref(), ctx.coordinator])

      assert snapshot(ctx).bookkeeping.children[key].phase == :reserved
      assert :ok = invoke(:helper_result, [key, token, ctx.coordinator])
      assert snapshot(ctx).bookkeeping.children == %{}
      assert snapshot(ctx).messages == 1

      assert {:error, :unknown_helper_result} =
               invoke(:helper_result, [key, token, ctx.coordinator])

      assert :ok = Activation.name_available(waiter.destination, ctx.coordinator)
      assert_receive {:activation_event, _, _, {:resolve, ^key, request, _, _}}, 5000
      assert request == waiter.request
      assert :ok = Activation.finish(key, request, :delivered, ctx.coordinator)
      assert_drained(ctx)
    end

    test "actual signal is drained only through the ordered registered-worker fact", ctx do
      {waiter, key} = issued(ctx, "org.fixture.Kill")
      assert :ok = invoke(:launch_helper, [key, ctx.coordinator])
      assert_receive {:activation_event, _, _, {:helper_result, ^key, token}}, 5000
      assert snapshot(ctx).messages == 1
      assert :ok = invoke(:helper_result, [key, token, ctx.coordinator])
      assert_receive {:activation_event, _, _, {:terminal, ^key, request, _, _, reason}}, 5000
      assert request == waiter.request
      assert reason == {:backend_signaled, 9}
      assert snapshot(ctx).bookkeeping.children == %{}
      assert_drained(ctx)
    end
  else
    test "a result without normal observer DOWN cannot release a launch slot", ctx do
      {_waiter, key} = issued(ctx, "org.fixture.Fragmented")
      assert :ok = invoke(:launch_helper, [key, ctx.coordinator])
      helper = :sys.get_state(ctx.coordinator).helpers[key]
      monitor = Process.monitor(helper.pid)

      send(
        ctx.coordinator,
        {:helper_result, helper.pid, ctx.epoch, key, helper.token, {:exited, 0}}
      )

      assert {:error, :unknown_helper_result} =
               invoke(:helper_result, [key, helper.token, ctx.coordinator])

      assert {:error, :helper_observation_required} =
               Activation.backend_result(key, {:exited, 0}, ctx.coordinator)

      assert snapshot(ctx).bookkeeping.children[key].phase == :reserved
      assert snapshot(ctx).messages == 1
      Process.exit(helper.pid, :kill)
      assert_receive {:DOWN, ^monitor, :process, _, :killed}, 5000
      assert_receive {:activation_event, _, _, {:helper_result, ^key, token}}, 5000
      assert :ok = invoke(:helper_result, [key, token, ctx.coordinator])

      assert_receive {:activation_event, _, _,
                      {:terminal, ^key, _, _, _, {:observation_lost, :worker_down}}},
                     5000

      assert_drained(ctx)
      assert snapshot(ctx).bookkeeping.children[key].phase == :uncertain
    end

    test "lost observation keeps launch credit and name barrier after message drain", ctx do
      {waiter, key} = issued(ctx, "org.fixture.Missing")
      assert :ok = invoke(:launch_helper, [key, ctx.coordinator])
      assert_receive {:activation_event, _, _, {:helper_result, ^key, token}}, 5000
      assert :ok = invoke(:helper_result, [key, token, ctx.coordinator])

      assert_receive {:activation_event, _, _,
                      {:terminal, ^key, _, _, _, {:observation_lost, :invalid_record}}},
                     5000

      assert_drained(ctx)
      assert snapshot(ctx).bookkeeping.children[key].phase == :uncertain
      assert snapshot(ctx).bookkeeping.names[waiter.destination] == key
      assert :ok = Activation.name_owned(waiter.destination, ctx.coordinator)
      assert snapshot(ctx).bookkeeping.attempts == %{}
      assert snapshot(ctx).bookkeeping.children[key].phase == :uncertain
      {next, message} = waiting(ctx, "org.fixture.Fragmented")
      assert {:ok, replacement} = Activation.admit(next, message, @definition, ctx.coordinator)
      assert {:error, :limits_exceeded} = Activation.commit(replacement, 1, ctx.coordinator)
    end

    test "uncorrelated worker and monitor notifications leave authority unchanged", ctx do
      {_waiter, key} = issued(ctx, "org.fixture.Missing")
      before = snapshot(ctx)
      send(ctx.coordinator, {:helper_result, self(), ctx.epoch, key, key, {:exited, 0}})
      send(ctx.coordinator, {:DOWN, make_ref(), :process, self(), :normal})
      send(ctx.coordinator, {:helper_result, self(), make_ref(), key, key, {:signaled, 9}})
      assert snapshot(ctx) == before
      assert DynamicSupervisor.which_children(ctx.workers) == []
    end
  end

  defp invoke(function, arguments), do: apply(Activation, function, arguments)

  defp snapshot(ctx) do
    assert {:ok, snapshot} = Activation.snapshot(ctx.coordinator)
    snapshot
  end

  defp assert_drained(ctx) do
    deadline = System.monotonic_time(:millisecond) + 2000

    await(
      fn ->
        assert {:ok, usage} = Limits.snapshot(ctx.limits)
        usage.global.activation_messages == 0 and snapshot(ctx).messages == 0
      end,
      deadline
    )
  end

  defp await(predicate, deadline) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(predicate, deadline)
    end
  end

  defp issued(ctx, name) do
    {waiter, message} = waiting(ctx, name)
    assert {:ok, key} = Activation.admit(waiter, message, @definition, ctx.coordinator)
    assert {:ok, :issued} = Activation.commit(key, 1, ctx.coordinator)
    assert_receive {:activation_event, _, _, {:launch, ^key, @definition}}, 5000
    {waiter, key}
  end

  defp waiting(ctx, name) do
    request = {ctx.epoch, make_ref()}
    assert {:ok, ingress} = Limits.reserve_ingress(self(), 256, ctx.limits)
    deadline = System.monotonic_time(:millisecond) + 10_000

    assert {:ok, lease} =
             Limits.reserve_activation(
               ingress,
               %{
                 caller: self(),
                 caller_incarnation: ctx.incarnation,
                 request_key: request,
                 deadline: deadline
               },
               256,
               [],
               ctx.coordinator,
               ctx.limits
             )

    waiter = %{
      caller: self(),
      caller_incarnation: ctx.incarnation,
      request: request,
      serial: {ctx.epoch, ctx.incarnation, 1},
      kind: :automatic,
      message_type: :method_call,
      flags: 0,
      destination: name,
      generation: 1,
      definition: @definition.key,
      deadline: deadline,
      lease: lease
    }

    message =
      Message.method_call("/fixture", "org.fixture.Service", "Call",
        destination: name,
        serial: 1,
        signature: "s",
        body: ["payload"]
      )

    assert :ok = Limits.release(ingress, ctx.limits)
    {waiter, message}
  end
end
