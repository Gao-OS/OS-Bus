defmodule GaoBus.Unix.Credentials do
  @moduledoc """
  Reads the immutable peer identity of an accepted Linux Unix socket.

  Linux SO_PEERCRED is read through OTP's public native socket option API.
  SO_PEERGROUPS supplies an optional complete process-group snapshot; the primary
  GID is included and the list is sorted without discarding kernel duplicates.
  Unsupported group queries omit the snapshot. Other group-query failures are
  marked so group-dependent policy can fail closed without a later PID lookup.
  No client assertion or default identity is used when the query fails.
  """

  @so_peercred 17
  @so_peergroups 59
  @ucred_size 12
  @max_group_bytes 65_536 * 4
  @unset_id 0xFFFFFFFF

  @spec read(:socket.socket()) :: {:ok, map()} | {:error, term()}
  def read(socket) do
    case :os.type() do
      {:unix, :linux} -> read_linux(socket)
      _ -> {:error, :unsupported_platform}
    end
  end

  @doc "Decodes exactly one Linux ucred record; UID/GID fields are unsigned."
  @spec decode(binary()) :: {:ok, map()} | {:error, :invalid_peer_credentials}
  def decode(<<pid::native-signed-32, uid::native-unsigned-32, gid::native-unsigned-32>>)
      when pid > 0 and uid != @unset_id and gid != @unset_id do
    {:ok, %{pid: pid, uid: uid, gid: gid}}
  end

  def decode(_record), do: {:error, :invalid_peer_credentials}

  @doc "Decodes a complete Linux gid_t array and includes the captured primary GID."
  def decode_groups(record, primary)
      when is_binary(record) and byte_size(record) <= @max_group_bytes and
             rem(byte_size(record), 4) == 0 and is_integer(primary) and
             primary >= 0 and primary < @unset_id do
    groups = for <<gid::native-unsigned-32 <- record>>, do: gid

    if @unset_id in groups do
      {:error, :invalid_peer_groups}
    else
      groups = if primary in groups, do: groups, else: [primary | groups]
      {:ok, Enum.sort(groups)}
    end
  end

  def decode_groups(_record, _primary), do: {:error, :invalid_peer_groups}

  @doc false
  def with_groups(credentials, {:ok, record}) do
    case decode_groups(record, credentials.gid) do
      {:ok, groups} -> Map.put(credentials, :groups, groups)
      {:error, _reason} -> Map.put(credentials, :groups_error, :peer_groups_unavailable)
    end
  end

  def with_groups(credentials, {:error, reason}) when reason in [:enoprotoopt, :eopnotsupp],
    do: credentials

  def with_groups(credentials, _failure),
    do: Map.put(credentials, :groups_error, :peer_groups_unavailable)

  defp read_linux(socket) do
    case :socket.getopt_native(socket, {:socket, @so_peercred}, @ucred_size) do
      {:ok, record} ->
        with {:ok, credentials} <- decode(record) do
          groups = :socket.getopt_native(socket, {:socket, @so_peergroups}, @max_group_bytes)
          {:ok, with_groups(credentials, groups)}
        end

      {:error, reason} ->
        {:error, {:peer_credentials, reason}}
    end
  rescue
    _error in [ArgumentError, FunctionClauseError] ->
      {:error, :invalid_socket}
  catch
    :error, :badarg -> {:error, :invalid_socket}
  end
end
