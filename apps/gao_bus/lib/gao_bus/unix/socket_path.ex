defmodule GaoBus.Unix.SocketPath do
  @moduledoc "Validation and inode-bound cleanup for daemon-owned Unix endpoints."
  import Bitwise
  alias GaoBus.Unix.Native

  def prepare(path) when is_binary(path) do
    uid = Native.identity().uid

    if Path.type(path) == :absolute and Path.expand(path) == path do
      with :ok <- directories(Path.dirname(path), uid, true),
           {:error, :enoent} <- File.lstat(path) do
        :ok
      else
        {:ok, _existing} -> {:error, :endpoint_exists}
        error -> error
      end
    else
      {:error, :invalid_socket_path}
    end
  end

  def prepare(_path), do: {:error, :invalid_socket_path}

  def capture(path) do
    with {:ok, stat} <- File.lstat(path),
         true <- socket?(stat) and stat.uid == Native.identity().uid do
      {:ok, {stat.major_device, stat.minor_device, stat.inode}}
    else
      false -> {:error, :endpoint_ownership_changed}
      error -> error
    end
  end

  def remove(path, expected) do
    case capture(path) do
      {:ok, ^expected} -> File.rm(path)
      {:error, :enoent} -> :ok
      _ -> {:error, :endpoint_ownership_changed}
    end
  end

  defp directories(path, uid, endpoint_parent?) do
    with {:ok, stat} <- File.lstat(path),
         true <- stat.type == :directory and stat.uid in [0, uid],
         true <- safe_mode?(stat, endpoint_parent?) do
      if path == "/", do: :ok, else: directories(Path.dirname(path), uid, false)
    else
      false -> {:error, :unsafe_socket_directory}
      error -> error
    end
  end

  # Root-owned sticky ancestors such as /tmp are safe above a private directory.
  # The endpoint itself is never created in a shared writable directory.
  defp safe_mode?(stat, endpoint_parent?) do
    (stat.mode &&& 0o022) == 0 or
      (not endpoint_parent? and stat.uid == 0 and (stat.mode &&& 0o1000) != 0)
  end

  defp socket?(stat), do: (stat.mode &&& 0o170000) == 0o140000
end
