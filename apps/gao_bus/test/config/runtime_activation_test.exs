defmodule GaoBus.Config.RuntimeActivationTest do
  use ExUnit.Case, async: true

  alias GaoBus.Config
  alias GaoBus.Config.Runtime

  @name "org.example.Activated"

  test "explicit systemd mode binds XML activation limits to both enforcing consumers" do
    for {timeout, pending} <- [{0, 0}, {1234, 7}] do
      candidate = %{
        config()
        | limits: %{
            "service_start_timeout" => timeout,
            "max_pending_service_starts" => pending
          }
      }

      assert {:ok, plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
      assert plan.activation_mode == :systemd
      assert plan.router_options[:activation] == %{
               mode: :systemd,
               backends: [:systemd, :wait],
               service_start_timeout: timeout
             }

      assert plan.activation_options[:state_options] == [
               service_start_timeout: timeout,
               max_pending_service_starts: pending
             ]
    end
  end

  test "activation stays disabled unless explicitly selected" do
    assert {:error, {:unimplemented_activation_settings, [:servicedir]}} =
             Runtime.compile(config(), Map.delete(invocation(), :activation), %{uid: 42})

    assert {:error, {:unsupported_runtime_setting, :activation}} =
             Runtime.compile(config(), %{invocation() | activation: :helper}, %{uid: 42})
  end

  test "systemd1 bootstrap waits for normal ownership without a helper definition" do
    candidate = config("org.freedesktop.systemd1", nil)
    assert :ok = Runtime.validate_activation(candidate, :systemd)
    assert {:ok, _plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
  end

  test "traditional entries and invalid systemd units retain service field provenance" do
    assert {:error, %{reason: {:unsupported_activation_backend, @name, :helper}, origins: origins}} =
             Runtime.compile(config(@name, nil), invocation(), %{uid: 42})

    assert Enum.map(origins, & &1.element) == ["Exec", "User"]

    assert {:error, %{reason: {:invalid_systemd_service, @name}, origins: [origin]}} =
             Runtime.compile(config(@name, String.duplicate("x", 256)), invocation(), %{uid: 42})

    assert origin.element == "SystemdService"
  end

  test "systemd activation is limited to the system profile" do
    candidate = %{config() | settings: %{type: :session}}

    assert {:error, :systemd_activation_requires_system_profile} =
             Runtime.compile(candidate, %{invocation() | profile: :session}, %{uid: 42})
  end

  test "absolute servicehelper metadata is retained without enabling its backend" do
    candidate = %{config() | settings: Map.put(config().settings, :servicehelper, "/helper")}
    assert {:ok, plan} = Runtime.compile(candidate, invocation(), %{uid: 42})
    assert plan.configuration.settings.servicehelper == "/helper"
    assert plan.router_options[:activation].backends == [:systemd, :wait]

    for path <- ["relative/helper", "", "/helper" <> <<0>>, String.duplicate("/", 4097)] do
      candidate = %{candidate | settings: Map.put(candidate.settings, :servicehelper, path)}

      assert {:error, {:unsupported_runtime_setting, :servicehelper}} =
               Runtime.compile(candidate, invocation(), %{uid: 42})
    end
  end

  defp config(name \\ @name, unit \\ "example.service") do
    entry = %{
      name: name,
      systemd_service: unit,
      field_origins: %{
        exec: origin("Exec"),
        user: origin("User"),
        systemd_service: origin("SystemdService")
      }
    }

    %Config{
      daemon_uid: 42,
      settings: %{type: :system, servicedir: ["/example/system-services"]},
      services: %{directories: [], occurrences: [entry], selected: %{name => entry}}
    }
  end

  defp invocation,
    do: %{profile: :system, socket_path: "/tmp/runtime-activation-bus", activation: :systemd}

  defp origin(element),
    do: %{file: "/example/service", line: 1, element: element, occurrence: 1, include_chain: []}
end
