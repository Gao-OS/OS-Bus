defmodule GaoBus.RequestedRepliesTest do
  use ExUnit.Case, async: false
  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, Policy, Router}

  setup tags do
    Application.stop(:gao_bus)
    start_supervised!(Limits)
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)

    rules =
      for action <- [:send, :receive], type <- [:method_call, :signal, :method_return, :error] do
        match =
          if type in [:method_return, :error],
            do: %{type: type, requested_reply: true},
            else: %{type: type}

        %{action: action, effect: :allow, match: match}
      end

    start_supervised!({Policy, rules: rules})
    start_supervised!({Router, pending_limits: Map.get(tags, :pending_limits, %{})})
    caller = peer(":1.100", 1100)
    callee = peer(":1.101", 1101)
    attacker = peer(":1.102", 1101)
    %{caller: caller, callee: callee, attacker: attacker, rules: rules}
  end

  test "SEM-10 only the actual callee can use requested-reply authorization once", ctx do
    forwarded(ctx, 10)
    send_reply(ctx.attacker, ctx.caller, 10)
    refute_receive {:delivered, _, %Message{type: :method_return}}, 30
    send_reply(ctx.callee, ctx.caller, 10)

    assert_receive {:delivered, caller,
                    %Message{type: :method_return, reply_serial: 10, sender: ":1.101"}}

    assert caller == ctx.caller.pid
    send_reply(ctx.callee, ctx.caller, 10)
    refute_receive {:delivered, _, %Message{type: :method_return}}, 30
  end

  test "SEM-10 service replacement cannot inherit permission to answer an earlier call", ctx do
    assert {:ok, 1} =
             NameRegistry.request_name(
               "org.foundation.Pending",
               1,
               ctx.callee.pid,
               ctx.callee.name
             )

    forwarded(ctx, 10, "org.foundation.Pending")

    assert {:ok, 1} =
             NameRegistry.request_name(
               "org.foundation.Pending",
               2,
               ctx.attacker.pid,
               ctx.attacker.name
             )

    send_reply(ctx.attacker, ctx.caller, 10)
    refute_receive {:delivered, _, %Message{type: :method_return}}, 30
    send_reply(ctx.callee, ctx.caller, 10)

    assert_receive {:delivered, _,
                    %Message{type: :method_return, reply_serial: 10, sender: ":1.101"}}
  end

  test "SEM-10 identical serials on distinct callers remain independent", ctx do
    second = peer(":1.103", 1100)
    forwarded(ctx, 10)
    forwarded(%{ctx | caller: second}, 10)
    send_reply(ctx.callee, ctx.caller, 10)
    send_reply(ctx.callee, second, 10)
    first_pid = ctx.caller.pid
    second_pid = second.pid
    assert_receive {:delivered, ^first_pid, %Message{type: :method_return, reply_serial: 10}}
    assert_receive {:delivered, ^second_pid, %Message{type: :method_return, reply_serial: 10}}
  end

  test "SEM-10 duplicate outstanding serial is denied without forwarding or replacing correlation",
       ctx do
    forwarded(ctx, 10)
    call(ctx.caller, ctx.attacker.name, 10)

    assert_receive {:delivered, _,
                    %Message{
                      type: :error,
                      error_name: "org.freedesktop.DBus.Error.AccessDenied",
                      reply_serial: 10
                    }}

    refute_receive {:delivered, _, %Message{type: :method_call, serial: 10}}, 30
    send_reply(ctx.callee, ctx.caller, 10)
    assert_receive {:delivered, _, %Message{type: :method_return, reply_serial: 10}}
  end

  @tag pending_limits: %{per_peer: 1}
  test "SEM-11 pending budget is acquired before delivery and returned after reply", ctx do
    forwarded(ctx, 10)
    call(ctx.caller, ctx.callee.name, 11)

    assert_receive {:delivered, _,
                    %Message{
                      type: :error,
                      error_name: "org.freedesktop.DBus.Error.LimitsExceeded",
                      reply_serial: 11
                    }}

    refute_receive {:delivered, _, %Message{type: :method_call, serial: 11}}, 30
    send_reply(ctx.callee, ctx.caller, 10)
    assert_receive {:delivered, _, %Message{type: :method_return, reply_serial: 10}}
    forwarded(ctx, 12)
  end

  @tag pending_limits: %{per_peer: 1}
  test "SEM-11 NO_REPLY_EXPECTED neither reserves permission nor emits failure replies", ctx do
    call(ctx.caller, ctx.callee.name, 10, 1)
    assert_receive {:delivered, _, %Message{type: :method_call, serial: 10, flags: 1}}
    send_reply(ctx.callee, ctx.caller, 10)
    refute_receive {:delivered, _, %Message{type: :method_return}}, 30
    forwarded(ctx, 11)
    call(ctx.caller, "org.foundation.Missing", 12, 3)
    refute_receive {:delivered, _, %Message{reply_serial: 12}}, 30
  end

  @tag :pending_scope_limits
  @tag pending_limits: %{per_peer: 4, per_uid: 2, global: 8, timeout_ms: :infinity}
  test "P05/R-09/RES-02 pending UID budget is shared and one completed call returns one slot",
       ctx do
    second = peer(":1.103", 1100)
    other_uid = peer(":1.104", 1102)
    first_pid = ctx.caller.pid
    second_pid = second.pid
    second_name = second.name
    other_pid = other_uid.pid
    callee_pid = ctx.callee.pid

    forwarded(ctx, 10)
    forwarded(%{ctx | caller: second}, 10)
    pending = :sys.get_state(Router).pending
    call(second, ctx.callee.name, 11)

    assert_receive {:delivered, ^second_pid,
                    %Message{
                      type: :error,
                      destination: ^second_name,
                      error_name: "org.freedesktop.DBus.Error.LimitsExceeded",
                      reply_serial: 11
                    }}

    call(second, ctx.callee.name, 10011, 1)

    assert_receive {:delivered, ^callee_pid,
                    %Message{type: :method_call, serial: 10011, flags: 1}}

    refute_receive {:delivered, _, %Message{type: :method_call, serial: 11}}, 30
    assert :sys.get_state(Router).pending == pending
    forwarded(%{ctx | caller: other_uid}, 20)

    send_reply(ctx.callee, ctx.caller, 10)
    assert_receive {:delivered, ^first_pid, %Message{type: :method_return, reply_serial: 10}}
    forwarded(%{ctx | caller: second}, 12)
    call(second, ctx.callee.name, 13)

    assert_receive {:delivered, ^second_pid,
                    %Message{
                      type: :error,
                      destination: ^second_name,
                      error_name: "org.freedesktop.DBus.Error.LimitsExceeded",
                      reply_serial: 13
                    }}

    call(second, ctx.callee.name, 10013, 1)

    assert_receive {:delivered, ^callee_pid,
                    %Message{type: :method_call, serial: 10013, flags: 1}}

    refute_receive {:delivered, _, %Message{type: :method_call, serial: 13}}, 30
    send_reply(ctx.callee, second, 10)
    assert_receive {:delivered, ^second_pid, %Message{type: :method_return, reply_serial: 10}}
    send_reply(ctx.callee, other_uid, 20)
    assert_receive {:delivered, ^other_pid, %Message{type: :method_return, reply_serial: 20}}
    send_reply(ctx.callee, second, 12)
    assert_receive {:delivered, ^second_pid, %Message{type: :method_return, reply_serial: 12}}
  end

  @tag :pending_scope_limits
  @tag pending_limits: %{per_peer: 4, per_uid: 4, global: 2, timeout_ms: :infinity}
  test "P05/R-09/RES-02 pending global budget spans UIDs and reuses exactly one returned slot",
       ctx do
    second = peer(":1.103", 1102)
    third = peer(":1.104", 1103)
    first_pid = ctx.caller.pid
    first_name = ctx.caller.name
    second_pid = second.pid
    third_pid = third.pid
    third_name = third.name
    callee_pid = ctx.callee.pid

    forwarded(ctx, 10)
    forwarded(%{ctx | caller: second}, 10)
    pending = :sys.get_state(Router).pending
    call(third, ctx.callee.name, 11)

    assert_receive {:delivered, ^third_pid,
                    %Message{
                      type: :error,
                      destination: ^third_name,
                      error_name: "org.freedesktop.DBus.Error.LimitsExceeded",
                      reply_serial: 11
                    }}

    call(third, ctx.callee.name, 10011, 1)

    assert_receive {:delivered, ^callee_pid,
                    %Message{type: :method_call, serial: 10011, flags: 1}}

    refute_receive {:delivered, _, %Message{type: :method_call, serial: 11}}, 30
    assert :sys.get_state(Router).pending == pending
    send_reply(ctx.callee, ctx.caller, 10)
    assert_receive {:delivered, ^first_pid, %Message{type: :method_return, reply_serial: 10}}
    forwarded(%{ctx | caller: third}, 12)
    call(ctx.caller, ctx.callee.name, 13)

    assert_receive {:delivered, ^first_pid,
                    %Message{
                      type: :error,
                      destination: ^first_name,
                      error_name: "org.freedesktop.DBus.Error.LimitsExceeded",
                      reply_serial: 13
                    }}

    call(ctx.caller, ctx.callee.name, 10013, 1)

    assert_receive {:delivered, ^callee_pid,
                    %Message{type: :method_call, serial: 10013, flags: 1}}

    refute_receive {:delivered, _, %Message{type: :method_call, serial: 13}}, 30
    send_reply(ctx.callee, second, 10)
    assert_receive {:delivered, ^second_pid, %Message{type: :method_return, reply_serial: 10}}
    send_reply(ctx.callee, third, 12)
    assert_receive {:delivered, ^third_pid, %Message{type: :method_return, reply_serial: 12}}
  end

  @tag pending_limits: %{per_peer: 1, timeout_ms: 40}
  test "SEM-11 timeout sends one NoReply, rejects stale response, and reclaims capacity", ctx do
    forwarded(ctx, 10)

    assert_receive {:delivered, _,
                    %Message{
                      type: :error,
                      reply_serial: 10,
                      error_name: "org.freedesktop.DBus.Error.NoReply"
                    }},
                   1000

    send_reply(ctx.callee, ctx.caller, 10)
    refute_receive {:delivered, _, %Message{type: :method_return}}, 30
    forwarded(ctx, 11)
  end

  @tag pending_limits: %{per_peer: 1}
  test "SEM-11 callee death sends NoReply and leaves caller usable", ctx do
    forwarded(ctx, 10)
    monitor = Process.monitor(ctx.callee.pid)
    Process.exit(ctx.callee.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}

    assert_receive {:delivered, _,
                    %Message{
                      type: :error,
                      reply_serial: 10,
                      error_name: "org.freedesktop.DBus.Error.NoReply"
                    }}

    forwarded(%{ctx | callee: ctx.attacker}, 11)
  end

  @tag pending_limits: %{global: 1}
  test "SEM-11 caller death retires its pending requests without disclosing a reply", ctx do
    forwarded(ctx, 10)
    monitor = Process.monitor(ctx.caller.pid)
    Process.exit(ctx.caller.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}
    await_removed(ctx.caller.pid, System.monotonic_time(:millisecond) + 1000)
    next = peer(":1.103", 1100)
    forwarded(%{ctx | caller: next}, 11)
    send_reply(ctx.callee, next, 10)
    refute_receive {:delivered, _, %Message{type: :method_return}}, 30
  end

  @tag pending_limits: %{per_peer: 1}
  test "SEM-11 failed receive authorization does not consume pending capacity", ctx do
    {:ok, _} =
      Policy.reload(
        ctx.rules ++
          [%{action: :receive, effect: :deny, match: %{interface: "org.foundation.Denied"}}]
      )

    call(ctx.caller, ctx.callee.name, 10, 0, "org.foundation.Denied")
    assert_receive {:delivered, _, %Message{type: :error, reply_serial: 10}}
    forwarded(ctx, 11)
  end

  test "SEM-12 explicit unsolicited policy remains effective without causal state", ctx do
    {:ok, _} =
      Policy.reload(
        ctx.rules ++
          for(
            action <- [:send, :receive],
            do: %{
              action: action,
              effect: :allow,
              match: %{type: :method_return, requested_reply: false}
            }
          )
      )

    send_reply(ctx.attacker, ctx.caller, 99)

    assert_receive {:delivered, _,
                    %Message{type: :method_return, reply_serial: 99, sender: ":1.102"}}
  end

  defp peer(name, uid) do
    owner = self()
    pid = start_supervised!({Task, fn -> forward(owner) end}, id: make_ref(), restart: :temporary)
    credentials = %{uid: uid, gid: 100, pid: 42, unique_name: name}
    :ok = Limits.acquire(pid, credentials)
    :ok = Limits.auth_completed(pid)
    :ok = Router.register_peer(pid, name, credentials)
    :ok = NameRegistry.register_unique(name, pid)
    _ = :sys.get_state(Router)
    assert_receive {:delivered, ^pid, %Message{member: "NameAcquired"}}
    %{pid: pid, name: name}
  end

  defp forward(owner) do
    receive do
      {:send_message, message, {token, _queued_at}} ->
        :ok = Limits.release(token)
        send(owner, {:delivered, self(), message})

      _ ->
        :ok
    end

    forward(owner)
  end

  defp call(caller, destination, serial, flags \\ 0, interface \\ "org.foundation.Pending") do
    message =
      Message.method_call("/pending", interface, "Call", destination: destination, serial: serial)

    :ok = Router.route(%{message | flags: flags}, caller.pid)
    _ = :sys.get_state(Router)
  end

  defp forwarded(ctx, serial, destination \\ nil) do
    call(ctx.caller, destination || ctx.callee.name, serial)
    pid = ctx.callee.pid
    assert_receive {:delivered, ^pid, %Message{type: :method_call, serial: ^serial}}
  end

  defp send_reply(callee, caller, serial) do
    :ok =
      Router.route(
        Message.method_return(serial, destination: caller.name, serial: 90),
        callee.pid
      )

    _ = :sys.get_state(Router)
  end

  defp await_removed(peer, deadline) do
    if Map.has_key?(:sys.get_state(Router).peers, peer) do
      assert System.monotonic_time(:millisecond) < deadline
      await_removed(peer, deadline)
    end
  end
end
