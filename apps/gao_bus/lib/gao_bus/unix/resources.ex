defmodule GaoBus.Unix.Resources do
  @moduledoc """
  Linux ancillary-resource boundary. Received rights become opaque owned resources
  in the same native call that receives them. Explicit close is idempotent; the
  resource destructor also closes when the last reference is destroyed (including
  death of its sole holder). A handle shared with another process stays live until
  explicitly closed or its last reference is destroyed. Raw descriptor integers never
  escape this boundary. Capture an independently owned CLOEXEC socket resource
  while the caller owns the OTP socket. Dirty I/O and close share its mutex, so
  OTP owner death cannot close or reuse the descriptor used by an in-flight call.
  Direct OTP-socket callers capture a temporary resource for each operation.
  """
  alias GaoBus.Unix.Native

  @doc "Capture a private CLOEXEC socket resource while the caller owns its OTP socket."
  def capture(socket) do
    with {:ok, owner} <- :socket.getopt(socket, {:otp, :controlling_process}),
         true <- owner == self() or {:error, :not_socket_owner},
         {:ok, fd} <- :socket.getopt(socket, {:otp, :fd}) do
      Native.capture(fd)
    end
  end

  def recv(socket, max_bytes, max_fds \\ 16),
    do: with_socket(socket, &Native.recv(&1, max_bytes, max_fds))

  def send(socket, bytes, handles \\ []),
    do: with_socket(socket, &Native.send(&1, bytes, handles))

  def info(handle), do: Native.info(handle)

  @doc "Create independently closable CLOEXEC copies, rolling back on any failure."
  def duplicate(handles), do: Native.duplicate(handles)

  @doc "Poll write readiness without waiting using an owned socket resource."
  def writable?(socket), do: with_socket(socket, &Native.writable/1)

  # Compatibility for direct OTP-socket callers. Production Peers retain one
  # captured resource instead; dirty operations never receive a borrowed integer.
  defp with_socket({:"$socket", _reference} = socket, operation) do
    with {:ok, owned} <- capture(socket) do
      try do
        operation.(owned)
      after
        case Native.close(owned) do
          :ok -> :ok
          {:error, reason} -> exit({:resource_cleanup_failed, reason})
        end
      end
    end
  end

  defp with_socket(owned, operation), do: operation.(owned)

  def close(handles) when is_list(handles) do
    Enum.reduce(handles, :ok, fn handle, result ->
      case Native.close(handle) do
        :ok -> result
        {:error, _} = error -> error
      end
    end)
  end
end
