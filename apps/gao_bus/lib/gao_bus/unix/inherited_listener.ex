defmodule GaoBus.Unix.InheritedListener do
  @moduledoc """
  Duplicates the manager's single named fd3 listener through public OTP APIs.
  The adopting process owns its public OTP copy; the pathname and manager
  endpoint are never bound, chmodded, shut down or removed here. A successful
  native handoff releases raw fd3. Failed permanent daemon startup exits,
  releasing any raw fd3 remaining after closing the public owned duplicate.
  """
  alias GaoBus.Unix.Native

  @environment ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]

  def adopt(expected_path) when is_binary(expected_path) do
    if System.get_env("LISTEN_PID") == System.pid() and
         System.get_env("LISTEN_FDS") == "1" and System.get_env("LISTEN_FDNAMES") == "dbus" do
      case :socket.open(3, %{dup: true}) do
        {:ok, socket} ->
          Enum.each(@environment, &System.delete_env/1)

          case validate_and_handoff(socket, expected_path) do
            :ok ->
              {:ok, socket}

            {:error, _reason} = error ->
              :socket.close(socket)
              error
          end

        {:error, _reason} = error ->
          error
      end
    else
      {:error, :invalid_inherited_environment}
    end
  end

  defp validate_and_handoff(socket, expected_path) do
    with {:ok, fd} when is_integer(fd) and fd >= 0 and fd != 3 <-
           :socket.getopt(socket, {:otp, :fd}),
         {:ok, :local} <- :socket.getopt(socket, {:socket, :domain}),
         {:ok, :stream} <- :socket.getopt(socket, {:socket, :type}),
         {:ok, true} <- :socket.getopt(socket, {:socket, :acceptconn}),
         {:ok, %{family: :local, path: ^expected_path}} <- :socket.sockname(socket),
         :ok <- Native.inherited_listener_handoff(fd) do
      :ok
    else
      {:error, _reason} = error -> error
      _mismatch -> {:error, :invalid_inherited_listener}
    end
  end
end
