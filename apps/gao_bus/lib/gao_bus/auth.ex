defmodule GaoBus.Auth do
  @moduledoc """
  Pure system-bus SASL authentication using a trusted socket identity.

  `feed/3` returns ordered actions: `{:send, bytes}`, `{:authenticated,
  credentials}`, and `{:begin, remaining_binary}`. `:continue` asks the caller
  to schedule another turn with empty input when complete auth lines remain.
  The caller must close the connection on an error and enforce `expire/2`
  using a timer even when no new bytes arrive.

  Line and total byte limits include CRLF; the total also includes the initial
  NUL. Binary protocol bytes after BEGIN are excluded. Unix FD negotiation is
  available only after authentication and when the transport enables it.
  """

  @rejected "REJECTED EXTERNAL\r\n"
  @defaults [
    max_line_bytes: 4096,
    max_auth_bytes: 8192,
    max_failures: 8,
    max_lines_per_turn: 32,
    timeout_ms: 5000,
    idle_timeout_ms: 1000
  ]

  defstruct [
    :credentials,
    :guid,
    :started_at,
    :last_received_at,
    :limits,
    phase: :initial,
    buffer: <<>>,
    total_bytes: 0,
    failures: 0,
    unix_fd_supported: false,
    unix_fd_negotiated: false
  ]

  @spec new(map(), String.t(), integer(), keyword()) :: {:ok, %__MODULE__{}} | {:error, atom()}
  def new(credentials, guid, now_ms, opts \\ []) do
    {unix_fd, opts} = Keyword.pop(opts, :unix_fd, false)
    limits = Keyword.merge(@defaults, opts)

    cond do
      not valid_credentials?(credentials) ->
        {:error, :invalid_peer_credentials}

      not is_boolean(unix_fd) ->
        {:error, :invalid_unix_fd_support}

      not (is_binary(guid) and Regex.match?(~r/\A[0-9a-fA-F]{32}\z/, guid)) ->
        {:error, :invalid_auth_guid}

      not Enum.all?(limits, fn {key, value} ->
        Keyword.has_key?(@defaults, key) and is_integer(value) and value > 0
      end) ->
        {:error, :invalid_auth_limits}

      true ->
        {:ok,
         %__MODULE__{
           credentials: credentials,
           guid: guid,
           started_at: now_ms,
           last_received_at: now_ms,
           unix_fd_supported: unix_fd,
           limits: Map.new(limits)
         }}
    end
  end

  @spec expire(%__MODULE__{}, integer()) :: {:ok, %__MODULE__{}} | {:error, atom(), %__MODULE__{}}
  def expire(%{phase: :connected} = auth, _now_ms), do: {:ok, auth}
  def expire(%{phase: :failed} = auth, _now_ms), do: {:error, :authentication_failed, auth}

  def expire(auth, now_ms) do
    cond do
      now_ms - auth.started_at >= auth.limits.timeout_ms ->
        {:error, :auth_timeout, failed(auth)}

      now_ms - auth.last_received_at >= auth.limits.idle_timeout_ms ->
        {:error, :auth_idle_timeout, failed(auth)}

      true ->
        {:ok, auth}
    end
  end

  @spec feed(%__MODULE__{}, binary(), integer()) ::
          {:ok, %__MODULE__{}, list()} | {:error, atom(), %__MODULE__{}, list()}
  def feed(%{phase: :connected} = auth, _data, _now_ms),
    do: {:error, :already_connected, auth, []}

  def feed(auth, data, now_ms) when is_binary(data) do
    case expire(auth, now_ms) do
      {:ok, auth} ->
        auth = if data == <<>>, do: auth, else: %{auth | last_received_at: now_ms}
        process(auth, auth.buffer <> data, auth.limits.max_lines_per_turn, [])

      {:error, reason, auth} ->
        {:error, reason, auth, []}
    end
  end

  defp process(%{phase: :initial} = auth, <<>>, _budget, actions),
    do: success(auth, <<>>, actions)

  defp process(%{phase: :initial} = auth, <<0, rest::binary>>, budget, actions) do
    process(%{auth | phase: :auth, total_bytes: 1}, rest, budget, actions)
  end

  defp process(%{phase: :initial} = auth, _buffer, _budget, actions),
    do: failure(auth, :missing_initial_nul, actions)

  defp process(auth, buffer, budget, actions) do
    case :binary.match(buffer, "\r\n") do
      :nomatch ->
        retain_incomplete(auth, buffer, actions)

      {length, 2} ->
        <<line::binary-size(length), "\r\n", rest::binary>> = buffer
        consumed = length + 2

        cond do
          consumed > auth.limits.max_line_bytes ->
            failure(auth, :auth_line_too_long, actions)

          auth.total_bytes + consumed > auth.limits.max_auth_bytes ->
            failure(auth, :auth_bytes_exceeded, actions)

          not printable?(line) ->
            failure(auth, :invalid_auth_byte, actions)

          budget == 0 ->
            retain_pending(auth, buffer, actions)

          true ->
            auth = %{auth | total_bytes: auth.total_bytes + consumed, buffer: <<>>}

            case command(auth, line) do
              {:ok, auth, emitted} ->
                process(auth, rest, budget - 1, Enum.reverse(emitted, actions))

              {:begin, auth} ->
                success(auth, <<>>, [{:begin, rest} | actions])

              {:error, reason, auth, emitted} ->
                failure(auth, reason, Enum.reverse(emitted, actions))
            end
        end
    end
  end

  defp retain_pending(auth, buffer, actions) do
    remaining = auth.limits.max_auth_bytes - auth.total_bytes

    if pending_auth_size(buffer, remaining) > remaining do
      failure(auth, :auth_bytes_exceeded, actions)
    else
      success(auth, buffer, [:continue | actions])
    end
  end

  # Only scan the bounded auth prefix. A possible BEGIN separates a binary
  # tail for accounting; its legality is still checked when that line runs.
  defp pending_auth_size(<<"BEGIN\r\n", _tail::binary>>, _remaining), do: 7

  defp pending_auth_size(buffer, remaining) do
    prefix = binary_part(buffer, 0, min(byte_size(buffer), remaining + 1))

    case :binary.match(prefix, "\r\nBEGIN\r\n") do
      {position, 9} -> position + 9
      :nomatch -> byte_size(buffer)
    end
  end

  defp retain_incomplete(auth, buffer, actions) do
    line =
      if String.ends_with?(buffer, "\r"),
        do: binary_part(buffer, 0, byte_size(buffer) - 1),
        else: buffer

    cond do
      byte_size(buffer) > auth.limits.max_line_bytes ->
        failure(auth, :auth_line_too_long, actions)

      auth.total_bytes + byte_size(buffer) > auth.limits.max_auth_bytes ->
        failure(auth, :auth_bytes_exceeded, actions)

      not printable?(line) ->
        failure(auth, :invalid_auth_byte, actions)

      true ->
        success(auth, buffer, actions)
    end
  end

  defp command(%{phase: :authenticated} = auth, "BEGIN"),
    do: {:begin, %{auth | phase: :connected}}

  defp command(auth, "BEGIN"), do: {:error, :begin_before_authentication, auth, []}

  defp command(%{phase: phase} = auth, "CANCEL") when phase in [:external_data, :authenticated],
    do: reject(auth)

  defp command(auth, "ERROR"), do: reject(auth)
  defp command(auth, "ERROR " <> _message), do: reject(auth)

  defp command(%{phase: :authenticated, unix_fd_supported: true} = auth, "NEGOTIATE_UNIX_FD"),
    do: {:ok, %{auth | unix_fd_negotiated: true}, [{:send, "AGREE_UNIX_FD\r\n"}]}

  defp command(auth, "NEGOTIATE_UNIX_FD"),
    do: {:ok, auth, [{:send, "ERROR Unix FD passing is not supported\r\n"}]}

  defp command(%{phase: :authenticated} = auth, _line),
    do: {:ok, auth, [{:send, "ERROR Expected BEGIN or CANCEL\r\n"}]}

  defp command(%{phase: :auth} = auth, "AUTH"),
    do: {:ok, auth, [{:send, @rejected}]}

  defp command(%{phase: :auth} = auth, "AUTH EXTERNAL"),
    do: {:ok, %{auth | phase: :external_data}, [{:send, "DATA\r\n"}]}

  defp command(%{phase: :auth} = auth, "AUTH EXTERNAL " <> assertion) do
    if assertion == "" do
      command(auth, "AUTH EXTERNAL")
    else
      external(auth, assertion)
    end
  end

  defp command(%{phase: :external_data} = auth, "DATA"), do: accept(auth)
  defp command(%{phase: :external_data} = auth, "DATA " <> ""), do: accept(auth)

  defp command(%{phase: :external_data} = auth, "DATA " <> assertion),
    do: external(auth, assertion)

  defp command(%{phase: :auth} = auth, "AUTH " <> _mechanism), do: reject(auth)

  defp command(auth, _line) do
    count_failure(auth, [{:send, "ERROR Unknown or out-of-sequence command\r\n"}])
  end

  defp external(auth, assertion) do
    case Base.decode16(assertion, case: :mixed) do
      {:ok, identity} ->
        if Regex.match?(~r/\A[0-9]+\z/, identity) do
          {uid, ""} = Integer.parse(identity)
          if uid == auth.credentials.uid, do: accept(auth), else: reject(auth)
        else
          reject(auth)
        end

      :error ->
        reject(auth)
    end
  end

  defp accept(auth) do
    {:ok, %{auth | phase: :authenticated},
     [{:send, "OK #{auth.guid}\r\n"}, {:authenticated, auth.credentials}]}
  end

  defp reject(auth),
    do: count_failure(%{auth | phase: :auth, unix_fd_negotiated: false}, [{:send, @rejected}])

  defp count_failure(auth, emitted) do
    auth = %{auth | failures: auth.failures + 1}

    if auth.failures >= auth.limits.max_failures,
      do: {:error, :auth_failures_exceeded, auth, emitted},
      else: {:ok, auth, emitted}
  end

  defp printable?(binary), do: printable_bytes?(binary)
  defp printable_bytes?(<<>>), do: true
  defp printable_bytes?(<<byte, rest::binary>>) when byte in 32..126, do: printable_bytes?(rest)
  defp printable_bytes?(_binary), do: false

  defp valid_credentials?(%{uid: uid, gid: gid, pid: pid})
       when is_integer(pid) and pid > 0 and is_integer(uid) and uid >= 0 and uid < 0xFFFFFFFF and
              is_integer(gid) and gid >= 0 and gid < 0xFFFFFFFF,
       do: true

  defp valid_credentials?(_credentials), do: false
  defp failed(auth), do: %{auth | phase: :failed, buffer: <<>>}
  defp success(auth, buffer, actions), do: {:ok, %{auth | buffer: buffer}, Enum.reverse(actions)}
  defp failure(auth, reason, actions), do: {:error, reason, failed(auth), Enum.reverse(actions)}
end
