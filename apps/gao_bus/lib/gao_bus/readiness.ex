defmodule GaoBus.Readiness do
  @moduledoc "Bounded systemd notification from the main BEAM process after core startup."

  def notify(destination, required \\ false)
  def notify(nil, false), do: :ok
  def notify(nil, true), do: {:error, :missing_notify_socket}

  def notify(destination, _required) when is_binary(destination) do
    with {:ok, path} <- address(destination),
         {:ok, socket} <- :socket.open(:local, :dgram, :default) do
      try do
        :socket.sendto(socket, "READY=1", %{family: :local, path: path}, [], 1_000)
      after
        :socket.close(socket)
      end
    end
  end

  def notify(_destination, _required), do: {:error, :invalid_notify_socket}

  defp address(destination) do
    if byte_size(destination) in 2..107 and not String.contains?(destination, <<0>>) do
      case destination do
        "/" <> _ -> {:ok, destination}
        "@" <> name -> {:ok, <<0>> <> name}
        _ -> {:error, :invalid_notify_socket}
      end
    else
      {:error, :invalid_notify_socket}
    end
  end
end
