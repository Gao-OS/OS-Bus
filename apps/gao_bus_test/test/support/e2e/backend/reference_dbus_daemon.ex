defmodule GaoBusTest.E2E.Backend.ReferenceDBusDaemon do
  @moduledoc """
  Isolated reference backend powered by dbus-daemon.
  """

  @behaviour GaoBusTest.E2E.Backend

  alias ExDBus.{Connection, Message}
  alias GaoBusTest.E2E.ChildProcess

  @startup_timeout 10_000
  @call_timeout 5_000

  defstruct [
    :tmpdir,
    :socket_path,
    :config_path,
    :bus_address,
    :daemon_path,
    :daemon_port,
    :daemon_pid,
    :worker,
    stdout: "",
    stderr: ""
  ]

  @impl true
  def start(opts \\ []) do
    with {:ok, daemon_path} <- find_daemon(),
         {:ok, state} <- build_state(daemon_path, opts),
         :ok <- write_config(state),
         {:ok, state} <- start_daemon(state),
         :ok <- probe_started(state) do
      {:ok, state}
    else
      {:error, reason, %__MODULE__{} = state} ->
        stop(state)
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def address(%__MODULE__{bus_address: address}), do: address

  @impl true
  def probe(%__MODULE__{bus_address: address}) when is_binary(address) do
    with {:ok, conn} <- start_probe_connection(address) do
      try do
        with {:ok, hello} <- call_bus(conn, "Hello"),
             true <- unique_name?(hello),
             {:ok, list_names} <- call_bus(conn, "ListNames"),
             true <- dbus_name_present?(list_names) do
          :ok
        else
          false -> {:error, :protocol_probe_failed}
          {:error, reason} -> {:error, {:protocol_probe_failed, reason}}
        end
      after
        Connection.disconnect(conn)
      end
    end
  end

  def probe(_state), do: {:error, :missing_bus_address}

  @impl true
  def diagnostics(%__MODULE__{} = state) do
    log = if state.worker, do: ChildProcess.snapshot(state.worker).output, else: state.stdout
    config = File.read!(state.config_path)

    %{
      backend: "reference",
      tmpdir: state.tmpdir,
      socket_path: state.socket_path,
      bus_address: state.bus_address,
      daemon_path: state.daemon_path,
      daemon_pid: state.daemon_pid,
      profile: "session",
      config: config,
      config_sha256: Base.encode16(:crypto.hash(:sha256, config), case: :lower),
      log: """
      backend=reference
      socket_path=#{state.socket_path}
      bus_address=#{state.bus_address}
      daemon_path=#{state.daemon_path}
      daemon_pid=#{inspect(state.daemon_pid)}
      daemon_output=#{inspect(log)}
      """
    }
  end

  @impl true
  def stop(%__MODULE__{} = state) do
    if state.worker, do: ChildProcess.stop(state.worker)
    if state.tmpdir, do: File.rm_rf(state.tmpdir)
    :ok
  end

  def stop(_), do: :ok

  defp find_daemon do
    case System.find_executable("dbus-daemon") do
      nil -> {:error, {:missing_executable, "dbus-daemon"}}
      path -> {:ok, path}
    end
  end

  defp build_state(daemon_path, opts) do
    base = Keyword.get(opts, :tmp_base, System.tmp_dir!())
    tmpdir = Path.join(base, "e2e_dbus_#{System.unique_integer([:positive])}")
    socket_path = Path.join(tmpdir, "bus.sock")
    config_path = Path.join(tmpdir, "session.conf")

    File.mkdir_p!(tmpdir)

    {:ok,
     %__MODULE__{
       tmpdir: tmpdir,
       socket_path: socket_path,
       config_path: config_path,
       daemon_path: daemon_path
     }}
  rescue
    exception -> {:error, Exception.message(exception)}
  end

  defp write_config(%__MODULE__{} = state) do
    File.write!(state.config_path, config_xml(state.socket_path))
    :ok
  rescue
    exception -> {:error, Exception.message(exception), state}
  end

  defp start_daemon(%__MODULE__{} = state) do
    case ChildProcess.start(
           command: state.daemon_path,
           args: ["--config-file=#{state.config_path}", "--nofork", "--print-address"]
         ) do
      {:ok, worker} ->
        state = %{state | worker: worker}

        case ChildProcess.await_ready(worker, &Regex.match?(~r/^unix:/m, &1), @startup_timeout) do
          {:ok, output} ->
            address =
              output.output
              |> String.split("\n")
              |> Enum.find(&String.starts_with?(&1, "unix:"))
              |> String.trim()

            {:ok, %{state | daemon_pid: output.pid, bus_address: address, stdout: output.output}}

          {:error, reason} ->
            {:error, reason, state}
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp config_xml(socket_path) do
    """
    <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
     "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
    <busconfig>
      <type>custom</type>
      <listen>unix:path=#{socket_path}</listen>
      <auth>EXTERNAL</auth>
      <allow_anonymous/>
      <policy context="default">
        <allow send_destination="*" eavesdrop="true"/>
        <allow eavesdrop="true"/>
        <allow own="*"/>
        <allow send_type="method_call"/>
        <allow send_type="signal"/>
        <allow send_interface="org.freedesktop.DBus.Monitoring"/>
      </policy>
    </busconfig>
    """
  end

  defp start_probe_connection(address) do
    case Connection.start_link(address: address, auth_mod: ExDBus.Auth.External, owner: self()) do
      {:ok, conn} ->
        receive do
          {:ex_d_bus, {:connected, _guid}} -> {:ok, conn}
        after
          @startup_timeout ->
            Connection.disconnect(conn)
            {:error, :connection_timeout}
        end

      {:error, _} = error ->
        error
    end
  end

  defp call_bus(conn, member) do
    msg =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus"
      )

    Connection.call(conn, msg, @call_timeout)
  end

  defp unique_name?(%Message{body: [":" <> _]}), do: true
  defp unique_name?(_), do: false

  defp dbus_name_present?(%Message{body: [names]}) when is_list(names) do
    "org.freedesktop.DBus" in names
  end

  defp dbus_name_present?(_), do: false

  defp probe_started(state) do
    case probe(state) do
      :ok ->
        :ok

      {:error, reason} ->
        stop(state)
        {:error, reason}
    end
  end
end
