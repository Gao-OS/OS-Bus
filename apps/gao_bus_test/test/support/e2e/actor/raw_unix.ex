defmodule GaoBusTest.E2E.Actor.RawUnix do
  @moduledoc "Independent byte-oriented Unix actor; never authenticates or registers implicitly."

  alias GaoBusTest.E2E.{Context, Qualification}

  def start(%Context{} = context) do
    with {:ok, path} <- private_path(context),
         {:ok, socket} <- :socket.open(:local, :stream, :default) do
      case :socket.connect(socket, %{family: :local, path: path}, 2_000) do
        :ok ->
          Qualification.actor(context, :raw, %{path: path, protocol: :independent_bytes})
          {:ok, Context.put_actor(context, :raw, %{socket: socket})}

        {:error, reason} ->
          :socket.close(socket)
          {:error, reason, context}
      end
    else
      {:error, reason} -> {:error, reason, context}
    end
  end

  def send(%Context{actors: %{raw: %{socket: socket}}}, bytes),
    do: :socket.send(socket, bytes, 2_000)

  def recv(%Context{actors: %{raw: %{socket: socket}}}, length, timeout),
    do: :socket.recv(socket, length, timeout)

  def stop(%Context{} = context) do
    case Context.get_actor(context, :raw) do
      {:ok, %{socket: socket}} -> :socket.close(socket)
      :error -> :ok
    end

    {:ok, Context.delete_actor(context, :raw)}
  end

  def external_auth(uid) when is_integer(uid) and uid >= 0,
    do: <<0>> <> "AUTH EXTERNAL " <> Base.encode16(to_string(uid)) <> "\r\n"

  defp private_path(%Context{bus_address: "unix:path=" <> path, tmpdir: dir})
       when is_binary(dir) do
    path = path |> String.split(",", parts: 2) |> hd()

    if Path.type(path) == :absolute and Path.dirname(path) == Path.expand(dir) and
         Path.expand(dir) not in ["/", "/run/dbus"] do
      {:ok, path}
    else
      {:error, :private_unix_address_required}
    end
  end

  defp private_path(_), do: {:error, :private_unix_address_required}
end
