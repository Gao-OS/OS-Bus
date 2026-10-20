defmodule GaoBus.Activation.SystemdTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message

  @interface "org.freedesktop.systemd1.Activator"
  @unit "example.service"
  @error "org.freedesktop.DBus.Error.Spawn.Failed"

  defp request(unit, serial), do: apply(GaoBus.Activation.Systemd, :request, [unit, serial])

  defp failure(message, context),
    do: apply(GaoBus.Activation.Systemd, :failure, [message, context])

  defp context(overrides \\ %{}) do
    epoch = make_ref()
    incarnation = {make_ref(), ":1.5"}

    Map.merge(
      %{
        systemd_mode: true,
        epoch: epoch,
        current_epoch: epoch,
        current_owner: self(),
        current_owner_incarnation: incarnation,
        peer: self(),
        peer_incarnation: incarnation,
        uid: 0,
        daemon_uid: 81,
        container_checked: true,
        container: false,
        authorized: true
      },
      overrides
    )
  end

  defp failure_message(overrides \\ %{}) do
    struct!(
      Message,
      Map.merge(
        %{
          type: :signal,
          serial: 10,
          sender: ":1.5",
          destination: "org.freedesktop.DBus",
          path: "/org/freedesktop/systemd1",
          interface: @interface,
          member: "ActivationFailure",
          signature: "sss",
          body: [@unit, @error, "missing unit"]
        },
        overrides
      )
    )
  end

  test "request builds the exact authority directed ActivationRequest signal" do
    assert {:ok, %Message{} = message} = request(@unit, 7)

    assert message == %Message{
             type: :signal,
             serial: 7,
             sender: "org.freedesktop.DBus",
             destination: "org.freedesktop.systemd1",
             path: "/org/freedesktop/DBus",
             interface: @interface,
             member: "ActivationRequest",
             signature: "s",
             body: [@unit]
           }

    assert {:ok, decoded, <<>>} = Message.decode_message(Message.encode_message(message))
    assert decoded == message
  end

  test "request preserves bounded unit strings literally and accepts uint32 serial limits" do
    for unit <- [
          "dbus-org.example.Service.service",
          "example@instance.service",
          "example\\x2dservice.service",
          "example.socket",
          "unit without a service suffix",
          "/literal/systemd/unit",
          "example;whoami.service",
          "é.service",
          String.duplicate("a", 247) <> ".service"
        ],
        serial <- [1, 0xFFFFFFFF] do
      assert {:ok, %Message{body: [^unit], serial: ^serial}} = request(unit, serial)
    end
  end

  test "request rejects invalid or unbounded unit names before constructing a wire message" do
    for unit <- [
          nil,
          1,
          "",
          "example\0.service",
          <<255>>,
          String.duplicate("a", 248) <> ".service"
        ] do
      assert {:error, :invalid_unit} = request(unit, 1)
    end
  end

  test "request refuses zero negative oversized and noninteger serials" do
    for serial <- [nil, 0, -1, 0x1_0000_0000, 1.5, "1"] do
      assert {:error, :invalid_serial} = request(@unit, serial)
    end
  end

  test "failure accepts current authenticated root and daemon-UID owner with unit-only correlation" do
    for uid <- [0, 81], unix_fds <- [nil, 0] do
      assert {:ok, %{unit: @unit, error_name: @error, error_text: "missing unit"} = result} =
               failure(failure_message(%{unix_fds: unix_fds}), context(%{uid: uid}))

      assert Enum.sort(Map.keys(result)) == [:error_name, :error_text, :unit]
    end
  end

  test "failure never grants mode policy or privileged authority from wire fields" do
    message = failure_message()

    for value <- [false, nil, :truthy] do
      assert {:error, :not_systemd_mode} = failure(message, context(%{systemd_mode: value}))
      assert {:error, :unauthorized} = failure(message, context(%{authorized: value}))
    end

    for uid <- [82, 1000, -1, nil, "0", 0xFFFFFFFF] do
      assert {:error, :unauthorized} = failure(message, context(%{uid: uid}))
    end

    assert {:error, :unauthorized} = failure(message, context(%{daemon_uid: nil}))

    for fields <- [
          %{container_checked: false},
          %{container_checked: nil},
          %{container: true},
          %{container: nil}
        ] do
      assert {:error, :unauthorized} = failure(message, context(fields))
    end
  end

  test "failure requires exact current owner PID incarnation sender and local epoch" do
    valid = context()

    for invalid <- [
          %{valid | current_epoch: make_ref()},
          %{valid | current_owner: :not_a_pid},
          %{valid | peer: :erlang.group_leader()},
          %{valid | current_owner_incarnation: {make_ref(), ":1.5"}},
          %{valid | current_owner_incarnation: {elem(valid.peer_incarnation, 0), ":1.6"}},
          %{
            valid
            | peer_incarnation: {:not_a_reference, ":1.5"},
              current_owner_incarnation: {:not_a_reference, ":1.5"}
          },
          %{valid | peer_incarnation: {make_ref(), "org.freedesktop.systemd1"}},
          %{valid | peer_incarnation: {make_ref(), ":missing_dot"}}
        ] do
      assert {:error, :invalid_identity} = failure(failure_message(), invalid)
    end

    for sender <- [nil, "org.freedesktop.systemd1", ":1.6"] do
      assert {:error, :invalid_identity} = failure(failure_message(%{sender: sender}), valid)
    end
  end

  test "failure fails closed when trusted context is incomplete" do
    valid = context()

    for key <- Map.keys(valid) do
      assert {:error, _reason} = failure(failure_message(), Map.delete(valid, key))
    end

    assert {:error, _reason} = failure(failure_message(), nil)
  end

  test "failure rejects unrelated envelopes malformed signatures and descriptor-bearing signals" do
    for fields <- [
          %{type: :method_call},
          %{type: :method_return},
          %{type: :error},
          %{destination: nil},
          %{destination: ":1.0"},
          %{destination: "org.example.Other"},
          %{path: "/org/freedesktop/DBus"},
          %{interface: "org.freedesktop.systemd1.Manager"},
          %{member: "ActivationRequest"},
          %{signature: "ss"},
          %{signature: "sssv"},
          %{serial: 0},
          %{reply_serial: 7},
          %{error_name: @error},
          %{unix_fds: 1},
          %{unix_fds: -1},
          %{fds: [42]},
          %{unix_fds: 0, fds: [42]}
        ] do
      assert {:error, :invalid_envelope} = failure(failure_message(fields), context())
    end

    assert {:error, :invalid_envelope} = failure(%{}, context())
  end

  test "failure validates exact three-string body and finite unit error-name and UTF8 text bounds" do
    for body <- [
          [],
          [@unit, @error],
          [@unit, @error, "text", "extra"],
          [@unit, @error, nil],
          [@unit, @error, <<255>>],
          [@unit, @error, "text\0"],
          [@unit, @error, String.duplicate("x", 4097)],
          [@unit, "NoDot", "text"],
          [@unit, "org.1Invalid", "text"],
          [@unit, "org.invalid-name", "text"],
          [@unit, String.duplicate("x", 256), "text"],
          ["", @error, "text"],
          [String.duplicate("x", 256), @error, "text"]
        ] do
      assert {:error, :invalid_arguments} = failure(failure_message(%{body: body}), context())
    end

    for text <- ["", String.duplicate("é", 2048)] do
      assert {:ok, %{error_text: ^text}} =
               failure(failure_message(%{body: [@unit, @error, text]}), context())
    end

    name = "org." <> String.duplicate("a", 251)

    assert {:ok, %{error_name: ^name}} =
             failure(failure_message(%{body: [@unit, name, "text"]}), context())
  end
end
