defmodule GaoBus.AuthTest do
  use ExUnit.Case, async: true

  alias GaoBus.Auth

  @credentials %{uid: 1000, gid: 100, pid: 42}
  @guid "0123456789abcdef0123456789abcdef"
  @uid_hex Base.encode16("1000", case: :lower)
  @ok "OK #{@guid}\r\n"
  @rejected "REJECTED EXTERNAL\r\n"

  test "requires a complete trusted socket identity" do
    for credentials <- [
          nil,
          %{},
          %{uid: 1000},
          %{uid: 1000, gid: 100, pid: 0},
          %{uid: -1, gid: 100, pid: 42}
        ] do
      assert {:error, :invalid_peer_credentials} = Auth.new(credentials, @guid, 0)
    end
  end

  test "valid inline EXTERNAL preserves the whole trusted identity and binary tail" do
    auth = new_auth()

    assert {:ok, auth, [{:send, @ok}, {:authenticated, @credentials}, {:begin, <<1, 2, 3>>}]} =
             Auth.feed(
               auth,
               <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\nBEGIN\r\n", 1, 2, 3>>,
               1
             )

    assert auth.phase == :connected
    assert auth.credentials == @credentials
  end

  test "a legitimate root socket identity can authenticate as root" do
    credentials = %{uid: 0, gid: 0, pid: 42}
    {:ok, auth} = Auth.new(credentials, @guid, 0)

    assert {:ok, _auth, [{:send, @ok}, {:authenticated, ^credentials}]} =
             Auth.feed(auth, <<0, "AUTH EXTERNAL 30\r\n">>, 1)
  end

  test "two-step EXTERNAL authenticates the assertion against socket identity" do
    assert {:ok, auth, [{:send, "DATA\r\n"}]} =
             Auth.feed(new_auth(), <<0, "AUTH EXTERNAL\r\n">>, 1)

    assert {:ok, _auth, [{:send, @ok}, {:authenticated, @credentials}]} =
             Auth.feed(auth, "DATA #{@uid_hex}\r\n", 2)
  end

  test "empty DATA uses the known socket identity" do
    assert {:ok, auth, [{:send, "DATA\r\n"}]} =
             Auth.feed(new_auth(), <<0, "AUTH EXTERNAL\r\n">>, 1)

    assert {:ok, _auth, [{:send, @ok}, {:authenticated, @credentials}]} =
             Auth.feed(auth, "DATA\r\n", 2)
  end

  test "discovery exposes only the supported EXTERNAL mechanism" do
    assert {:ok, auth, [{:send, @rejected}]} = Auth.feed(new_auth(), <<0, "AUTH\r\n">>, 1)
    assert auth.phase == :auth
  end

  test "every split point preserves a valid pipelined handshake" do
    input = <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\nBEGIN\r\n", 1, 2, 3>>
    expected = [{:send, @ok}, {:authenticated, @credentials}, {:begin, <<1, 2, 3>>}]

    for split <- 0..(byte_size(input) - 4) do
      <<first::binary-size(split), rest::binary>> = input
      assert {:ok, auth, first_actions} = Auth.feed(new_auth(), first, 1)
      assert {:ok, auth, rest_actions} = Auth.feed(auth, rest, 2)
      assert auth.phase == :connected
      assert first_actions ++ rest_actions == expected
    end
  end

  test "missing initial NUL is a terminal protocol error" do
    assert {:error, :missing_initial_nul, auth, []} =
             Auth.feed(new_auth(), "AUTH EXTERNAL #{@uid_hex}\r\n", 1)

    assert auth.phase == :failed
  end

  test "a repeated NUL is rejected instead of stripped again" do
    assert {:ok, auth, [{:send, @rejected}]} = Auth.feed(new_auth(), <<0, "AUTH\r\n">>, 1)

    assert {:error, :invalid_auth_byte, _auth, []} =
             Auth.feed(auth, <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\n">>, 2)
  end

  test "forged root and other-user assertions cannot authenticate" do
    for asserted_uid <- ["0", "999", "1001"] do
      hex = Base.encode16(asserted_uid)

      assert {:ok, auth, [{:send, @rejected}]} =
               Auth.feed(new_auth(), <<0, "AUTH EXTERNAL ", hex::binary, "\r\n">>, 1)

      assert auth.phase == :auth
      assert auth.credentials == @credentials
    end
  end

  test "malformed, negative and out-of-range assertions never authenticate" do
    for hex <- [
          "z0",
          "3",
          Base.encode16("-1"),
          Base.encode16("4294967296"),
          Base.encode16("1000x"),
          "00"
        ] do
      assert {:ok, auth, [{:send, @rejected}]} =
               Auth.feed(new_auth(), <<0, "AUTH EXTERNAL ", hex::binary, "\r\n">>, 1)

      assert auth.phase == :auth
    end
  end

  test "an all-decimal UID with leading zeros identifies the same socket user" do
    for asserted_uid <- ["01000", "0001000"] do
      hex = Base.encode16(asserted_uid)

      assert {:ok, _auth, [{:send, @ok}, {:authenticated, @credentials}]} =
               Auth.feed(new_auth(), <<0, "AUTH EXTERNAL ", hex::binary, "\r\n">>, 1)
    end
  end

  test "ERROR rejects the exchange in every authentication state" do
    initial = new_auth()
    {:ok, waiting, _actions} = Auth.feed(initial, <<0, "AUTH\r\n">>, 1)
    {:ok, waiting_data, _actions} = Auth.feed(initial, <<0, "AUTH EXTERNAL\r\n">>, 1)

    for auth <- [waiting, waiting_data, authenticated()], command <- ["ERROR", "ERROR detail"] do
      assert {:ok, auth, [{:send, @rejected}]} = Auth.feed(auth, command <> "\r\n", 2)
      assert auth.phase == :auth
    end
  end

  test "ERRORBOGUS is an unknown command and preserves the state" do
    initial = new_auth()
    {:ok, waiting, _actions} = Auth.feed(initial, <<0, "AUTH\r\n">>, 1)
    {:ok, waiting_data, _actions} = Auth.feed(initial, <<0, "AUTH EXTERNAL\r\n">>, 1)

    for auth <- [waiting, waiting_data, authenticated()] do
      phase = auth.phase
      assert {:ok, auth, [{:send, response}]} = Auth.feed(auth, "ERRORBOGUS\r\n", 2)
      assert String.starts_with?(response, "ERROR")
      assert auth.phase == phase
    end
  end

  test "AUTH and CANCEL in the wrong state return ERROR without restarting an exchange" do
    {:ok, waiting_data, _actions} =
      Auth.feed(new_auth(), <<0, "AUTH EXTERNAL\r\n">>, 1)

    for command <- ["AUTH", "AUTH EXTERNAL #{@uid_hex}", "AUTH BOGUS"] do
      assert {:ok, auth, [{:send, response}]} = Auth.feed(waiting_data, command <> "\r\n", 2)
      assert String.starts_with?(response, "ERROR")
      assert auth.phase == :external_data
    end

    assert {:ok, auth, [{:send, response}]} = Auth.feed(new_auth(), <<0, "CANCEL\r\n">>, 1)
    assert String.starts_with?(response, "ERROR")
    assert auth.phase == :auth
  end

  test "BEGIN cannot bypass authentication directly or after rejection and CANCEL" do
    for prefix <- [
          "",
          "AUTH BOGUS\r\n",
          "CANCEL\r\n",
          "AUTH\r\n",
          "AUTH EXTERNAL\r\n",
          "AUTH EXTERNAL 30\r\n"
        ] do
      assert {:error, :begin_before_authentication, auth, actions} =
               Auth.feed(new_auth(), <<0, prefix::binary, "BEGIN\r\n", 1, 2, 3>>, 1)

      assert auth.phase == :failed
      refute Enum.any?(actions, &match?({:begin, _}, &1))
      refute Enum.any?(actions, &match?({:authenticated, _}, &1))
    end
  end

  test "split rejection followed by BEGIN cannot enter binary mode" do
    assert {:ok, auth, [{:send, @rejected}]} =
             Auth.feed(new_auth(), <<0, "AUTH BOGUS\r\n">>, 1)

    assert {:error, :begin_before_authentication, _auth, []} = Auth.feed(auth, "BEGIN\r\n", 2)
  end

  test "CANCEL after success revokes the handshake before BEGIN" do
    auth = authenticated()
    assert {:ok, auth, [{:send, @rejected}]} = Auth.feed(auth, "CANCEL\r\n", 2)
    assert {:error, :begin_before_authentication, _auth, []} = Auth.feed(auth, "BEGIN\r\n", 3)
  end

  test "ANONYMOUS cannot authenticate a system-bus connection" do
    for line <- ["AUTH ANONYMOUS", "AUTH ANONYMOUS 7472616365"] do
      assert {:ok, auth, [{:send, @rejected}]} =
               Auth.feed(new_auth(), <<0, line::binary, "\r\n">>, 1)

      assert auth.phase == :auth
    end
  end

  test "early FD negotiation and unsolicited DATA do not change authentication state" do
    for line <- ["NEGOTIATE_UNIX_FD", "DATA #{@uid_hex}"] do
      assert {:ok, auth, [{:send, response}]} =
               Auth.feed(new_auth(), <<0, line::binary, "\r\n">>, 1)

      assert String.starts_with?(response, "ERROR")
      assert auth.phase == :auth
    end
  end

  test "unsupported FD negotiation after authentication does not advertise agreement" do
    assert {:ok, auth, [{:send, response}]} =
             Auth.feed(authenticated(), "NEGOTIATE_UNIX_FD\r\n", 2)

    assert String.starts_with?(response, "ERROR")
    assert {:ok, _auth, [{:begin, <<>>}]} = Auth.feed(auth, "BEGIN\r\n", 3)
  end

  test "line budget permits N bytes and rejects N plus one for incomplete or complete lines" do
    auth = new_auth(max_line_bytes: 8)
    assert {:ok, auth, []} = Auth.feed(auth, <<0, "12345678">>, 1)
    assert {:error, :auth_line_too_long, _auth, []} = Auth.feed(auth, "9", 2)

    assert {:ok, _auth, [{:send, @rejected}]} =
             Auth.feed(new_auth(max_line_bytes: 6), <<0, "AUTH\r\n">>, 1)

    assert {:error, :auth_line_too_long, _auth, []} =
             Auth.feed(new_auth(max_line_bytes: 5), <<0, "AUTH\r\n">>, 1)
  end

  test "cumulative auth bytes are bounded even when each line fits" do
    auth = new_auth(max_auth_bytes: 13)

    assert {:ok, auth, [{:send, @rejected}, {:send, @rejected}]} =
             Auth.feed(auth, <<0, "AUTH\r\nAUTH\r\n">>, 1)

    assert {:error, :auth_bytes_exceeded, _auth, []} = Auth.feed(auth, "A", 2)
  end

  test "binary bytes following BEGIN are not charged as authentication bytes" do
    handshake = <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\nBEGIN\r\n">>
    tail = :binary.copy(<<0>>, 9_000)
    auth = new_auth(max_auth_bytes: byte_size(handshake))

    assert {:ok, _auth, [{:send, @ok}, {:authenticated, @credentials}, {:begin, ^tail}]} =
             Auth.feed(auth, handshake <> tail, 1)
  end

  test "failure budget terminates repeated rejected mechanisms at the configured boundary" do
    auth = new_auth(max_failures: 3)

    assert {:ok, auth, [{:send, @rejected}, {:send, @rejected}]} =
             Auth.feed(auth, <<0, "AUTH BOGUS\r\nAUTH BOGUS\r\n">>, 1)

    assert {:error, :auth_failures_exceeded, auth, [{:send, @rejected}]} =
             Auth.feed(auth, "AUTH BOGUS\r\n", 2)

    assert auth.phase == :failed
  end

  test "processing yields after the configured number of lines" do
    auth = new_auth(max_lines_per_turn: 2)

    assert {:ok, auth, [{:send, @rejected}, {:send, @rejected}, :continue]} =
             Auth.feed(auth, <<0, "AUTH\r\nAUTH\r\nAUTH\r\n">>, 1)

    assert {:ok, _auth, [{:send, @rejected}]} = Auth.feed(auth, <<>>, 2)
  end

  test "pending complete lines cannot retain more than the cumulative auth budget" do
    auth = new_auth(max_auth_bytes: 13, max_lines_per_turn: 1)

    assert {:error, :auth_bytes_exceeded, auth, [{:send, @rejected}]} =
             Auth.feed(auth, <<0, "AUTH\r\nAUTH\r\nAUTH\r\n">>, 1)

    assert auth.buffer == <<>>
  end

  test "yielding does not retain an oversized next line" do
    auth = new_auth(max_line_bytes: 6, max_lines_per_turn: 1)

    assert {:error, :auth_line_too_long, auth, [{:send, @rejected}]} =
             Auth.feed(auth, <<0, "AUTH\r\n1234567\r\n">>, 1)

    assert auth.buffer == <<>>
  end

  test "yielding preserves a legitimate binary tail without charging it to auth limits" do
    handshake = <<0, "AUTH EXTERNAL\r\nDATA ", @uid_hex::binary, "\r\nBEGIN\r\n">>
    tail = :binary.copy(<<0>>, 9_000)
    auth = new_auth(max_auth_bytes: byte_size(handshake), max_lines_per_turn: 1)

    assert {:ok, auth, [{:send, "DATA\r\n"}, :continue]} =
             Auth.feed(auth, handshake <> tail, 1)

    assert {:ok, auth, [{:send, @ok}, {:authenticated, @credentials}, :continue]} =
             Auth.feed(auth, <<>>, 2)

    assert {:ok, _auth, [{:begin, ^tail}]} = Auth.feed(auth, <<>>, 3)
  end

  test "idle expiry and absolute expiry use explicit time even during a slow trickle" do
    auth = new_auth(idle_timeout_ms: 500, timeout_ms: 1_000)
    assert {:ok, _auth} = Auth.expire(auth, 499)
    assert {:error, :auth_idle_timeout, _auth} = Auth.expire(auth, 500)

    auth = new_auth(idle_timeout_ms: 500, timeout_ms: 1_000)
    assert {:ok, auth, []} = Auth.feed(auth, <<0>>, 400)
    assert {:ok, auth, []} = Auth.feed(auth, "A", 800)
    assert {:error, :auth_timeout, _auth} = Auth.expire(auth, 1_000)
  end

  test "input arriving at the deadline does not revive an expired handshake" do
    auth = new_auth(idle_timeout_ms: 500)

    assert {:error, :auth_idle_timeout, _auth, []} =
             Auth.feed(auth, <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\n">>, 500)
  end

  test "authentication failure is terminal" do
    assert {:error, :missing_initial_nul, auth, []} = Auth.feed(new_auth(), "AUTH\r\n", 1)

    assert {:error, :authentication_failed, _auth, []} =
             Auth.feed(auth, <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\n">>, 2)
  end

  test "invalid limits fail configuration validation" do
    for opts <- [
          [max_line_bytes: 0],
          [max_auth_bytes: -1],
          [max_failures: 0],
          [max_lines_per_turn: 0],
          [timeout_ms: 0],
          [idle_timeout_ms: 0]
        ] do
      assert {:error, :invalid_auth_limits} = Auth.new(@credentials, @guid, 0, opts)
    end
  end

  defp new_auth(opts \\ []) do
    {:ok, auth} = Auth.new(@credentials, @guid, 0, opts)
    auth
  end

  defp authenticated do
    {:ok, auth, [{:send, @ok}, {:authenticated, @credentials}]} =
      Auth.feed(new_auth(), <<0, "AUTH EXTERNAL ", @uid_hex::binary, "\r\n">>, 1)

    auth
  end
end
