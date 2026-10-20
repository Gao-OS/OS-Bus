defmodule GaoBus.Config.RuntimeTest do
  use ExUnit.Case, async: true

  alias GaoBus.Config
  alias GaoBus.Config.Runtime

  test "omitted XML limits retain pinned defaults while safety budgets admit a maximum frame" do
    assert {:ok, plan} = Runtime.compile(config(), invocation(), %{uid: 42})
    assert plan.xml_limits["max_message_size"] == 33_554_432
    assert plan.xml_limits["auth_timeout"] == 30_000
    assert plan.xml_limits["reply_timeout"] == :infinity
    assert plan.safety_limits.peer.frame_bytes >= plan.xml_limits["max_message_size"]

    assert plan.safety_limits.peer.egress_bytes >=
             plan.xml_limits["max_outgoing_bytes"] + plan.xml_limits["max_message_size"]
  end

  test "compiled XML listener peers have a finite frame deadline and retain XML limits" do
    limits = %{
      "max_message_size" => 8192,
      "max_message_unix_fds" => 17,
      "pending_fd_timeout" => 1234,
      "auth_timeout" => 30_000
    }

    for profile <- [:system, :session] do
      candidate = %{config() | settings: %{type: profile}, limits: limits}

      assert {:ok, plan} =
               Runtime.compile(candidate, Map.put(invocation(), :profile, profile), %{uid: 42})

      options = Keyword.put(plan.listener_options[:peer_options], :socket, :unused)
      assert {:ok, peer} = GaoBus.Peer.init(options)

      try do
        assert peer.frame_timeout_ms == 5000
        assert plan.peer_options == plan.listener_options[:peer_options]
        assert Map.take(plan.xml_limits, Map.keys(limits)) == limits
        assert peer.frame_options.max_bytes == limits["max_message_size"]
        assert peer.frame_options.max_fds == limits["max_message_unix_fds"]
        assert peer.frame_options.pending_fd_timeout == limits["pending_fd_timeout"]
        assert peer.xml_limits["auth_timeout"] == limits["auth_timeout"]
      after
        Process.cancel_timer(elem(peer.registration_timer, 0))
      end
    end
  end

  test "explicit listener and lifecycle overrides do not suppress unrelated activation errors" do
    candidate = %{
      config()
      | settings: %{
          type: :system,
          fork: true,
          pidfile: "/run/dbus/pid",
          syslog: true,
          listen: ["unix:abstract=/run/dbus/system_bus_socket"]
        }
    }

    assert {:error, {:unsupported_runtime_setting, :fork}} =
             Runtime.compile(candidate, %{profile: :system}, %{uid: 42})

    assert {:ok, plan} =
             Runtime.compile(
               candidate,
               Map.merge(invocation(), %{nofork: true, nopidfile: true, log_target: :stderr}),
               %{uid: 42}
             )

    assert plan.listener_options[:socket_path] == "/tmp/runtime-private-bus"
    assert plan.logging == :stderr

    candidate = %{
      candidate
      | settings: Map.put(candidate.settings, :servicedir, ["/etc/dbus-1/system-services"])
    }

    assert {:error, {:unimplemented_activation_settings, [:servicedir]}} =
             Runtime.compile(
               candidate,
               Map.merge(invocation(), %{nofork: true, nopidfile: true, log_target: :stderr}),
               %{uid: 42}
             )
  end

  test "UID profile and malformed runtime candidates cannot produce a plan" do
    assert {:error, :daemon_uid_mismatch} = Runtime.compile(config(), invocation(), %{uid: 0})

    assert {:error, :configuration_profile_mismatch} =
             Runtime.compile(config(), %{profile: :session}, %{uid: 42})

    assert {:error, :invalid_runtime_configuration} =
             Runtime.compile(%{config() | limits: nil}, invocation(), %{uid: 42})

    assert {:error, {:unsupported_runtime_setting, :silent_grant}} =
             Runtime.compile(%{config() | settings: %{silent_grant: true}}, invocation(), %{
               uid: 42
             })
  end

  test "unrepresentable descriptors protocol frames and activation limits fail explicitly" do
    for {limits, error} <- [
          {%{"max_message_unix_fds" => 254}, {:unsupported_message_fd_limit, 254}},
          {%{"max_message_size" => 134_217_729}, {:unsupported_message_size, 134_217_729}},
          {%{"service_start_timeout" => 1},
           {:unimplemented_runtime_limits, ["service_start_timeout"]}},
          {%{"auth_timeout" => 2_147_483_648}, {:invalid_runtime_limit, "auth_timeout"}}
        ] do
      assert {:error, ^error} =
               Runtime.compile(%{config() | limits: limits}, invocation(), %{uid: 42})
    end
  end

  test "zero connection limits remain zero while unsupported zero frame semantics are rejected" do
    candidate = %{
      config()
      | limits: %{"max_completed_connections" => 0, "max_connections_per_user" => 0}
    }

    assert {:ok, plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
    assert plan.xml_limits["max_completed_connections"] == 0
    assert plan.xml_limits["max_connections_per_user"] == 0

    assert {:error, {:unsupported_zero_limit, "max_message_size"}} =
             Runtime.compile(%{config() | limits: %{"max_message_size" => 0}}, invocation(), %{
               uid: 42
             })
  end

  test "safety budgets cannot silently clamp a configured legal maximum message" do
    invocation = Map.put(invocation(), :safety_limits, %{peer: %{frame_bytes: 1024}})

    assert {:error, {:inconsistent_safety_limit, :peer, :frame_bytes}} =
             Runtime.compile(config(), invocation, %{uid: 42})
  end

  test "unknown safety scopes and requested logging modes cannot be silently ignored" do
    assert {:error, :invalid_safety_limits} =
             Runtime.compile(
               config(),
               Map.put(invocation(), :safety_limits, %{ignored: %{frame_bytes: 1}}),
               %{uid: 42}
             )

    assert {:error, {:unsupported_runtime_setting, :log_target}} =
             Runtime.compile(config(), Map.put(invocation(), :log_target, :syslog), %{uid: 42})
  end

  test "manually constructed lifecycle flags fail closed instead of raising" do
    assert {:error, :invalid_runtime_configuration} =
             Runtime.compile(%{config() | settings: %{fork: "yes"}}, invocation(), %{uid: 42})

    assert {:error, :daemon_uid_mismatch} =
             Runtime.compile(%{config() | settings: %{user: 0}}, invocation(), %{uid: 42})
  end

  test "XML zero reply timeout disables timed expiry without rewriting the source value" do
    candidate = %{config() | limits: %{"reply_timeout" => 0}}
    assert {:ok, plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
    assert plan.xml_limits["reply_timeout"] == 0
    assert plan.router_options[:pending_limits].timeout_ms == :infinity
  end

  test "queue zeros retain threshold semantics and output budgets admit protocol-sized replies" do
    candidate = %{config() | limits: %{"max_incoming_bytes" => 0, "max_outgoing_unix_fds" => 0}}
    assert {:ok, plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
    assert plan.xml_limits["max_incoming_bytes"] == 0
    assert plan.xml_limits["max_outgoing_unix_fds"] == 0
    assert plan.router_options[:max_output_bytes] == 134_217_728

    assert plan.safety_limits.peer.egress_bytes >=
             plan.xml_limits["max_outgoing_bytes"] + 134_217_728
  end

  test "internal aggregate reply budgets accommodate a legal XML per-connection maximum" do
    candidate = %{config() | limits: %{"max_replies_per_connection" => 2000}}
    assert {:ok, plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
    pending = plan.router_options[:pending_limits]
    assert pending.per_uid >= pending.per_peer
    assert pending.global >= pending.per_peer
  end

  test "overrides cannot suppress a legal FD frame or permitted queue overshoot" do
    for metric <- [:ingress_fds, :egress_fds] do
      invocation = Map.put(invocation(), :safety_limits, %{peer: %{metric => 1}})

      assert {:error, {:inconsistent_safety_limit, :peer, ^metric}} =
               Runtime.compile(config(), invocation, %{uid: 42})
    end
  end

  test "XML plans retain native FD safety floors for concurrent reads" do
    assert {:ok, plan} = Runtime.compile(config(), invocation(), %{uid: 42})

    for {scope, defaults} <- GaoBus.Limits.defaults() do
      assert plan.safety_limits[scope].frame_fds >= defaults.frame_fds
    end
  end

  defp config, do: %Config{daemon_uid: 42, settings: %{type: :system}}
  defp invocation, do: %{profile: :system, socket_path: "/tmp/runtime-private-bus"}
end
