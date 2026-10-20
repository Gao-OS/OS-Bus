defmodule GaoBusTest.E2E.Actor.ExDBusClient do
  @moduledoc """
  ExDBus client actor for conformance scenarios.
  """

  alias GaoBusTest.E2E.{Context, Qualification}
  alias ExDBus.{Connection, Message, Proxy}

  @startup_timeout 10_000
  @call_timeout 5_000

  def start(%Context{} = context, opts \\ []) do
    actor_name = Keyword.get(opts, :name, :ex_dbus_client)

    with {:ok, conn} <- connect(context.bus_address),
         {:ok, reply} <- hello(conn) do
      state = %{conn: conn, unique_name: List.first(reply.body)}
      Qualification.actor(context, :ex_dbus, %{unique_name: state.unique_name})
      {:ok, Context.put_actor(context, actor_name, state)}
    else
      {:error, reason} -> {:error, reason, context}
    end
  end

  def stop(%Context{} = context, opts \\ []) do
    actor_name = Keyword.get(opts, :name, :ex_dbus_client)

    case Context.get_actor(context, actor_name) do
      {:ok, %{conn: conn}} -> disconnect(conn)
      :error -> :ok
    end

    {:ok, Context.delete_actor(context, actor_name)}
  end

  def conn(%Context{} = context, actor_name \\ :ex_dbus_client) do
    with {:ok, %{conn: conn}} <- Context.get_actor(context, actor_name), do: {:ok, conn}
  end

  def unique_name(%Context{} = context, actor_name \\ :ex_dbus_client) do
    with {:ok, %{unique_name: unique_name}} <- Context.get_actor(context, actor_name),
         do: unique_name
  end

  def connect(address) do
    case Connection.start_link(address: address, auth_mod: ExDBus.Auth.External, owner: self()) do
      {:ok, conn} ->
        receive do
          {:ex_d_bus, {:connected, _guid}} -> {:ok, conn}
        after
          @startup_timeout ->
            disconnect(conn)
            {:error, :connection_timeout}
        end

      {:error, _} = error ->
        error
    end
  end

  def hello(conn), do: call_bus(conn, "Hello")
  def list_names(conn), do: call_bus(conn, "ListNames")

  def request_name(conn, name, flags \\ 0) do
    call_bus(conn, "RequestName", signature: "su", body: [name, flags])
  end

  def release_name(conn, name) do
    call_bus(conn, "ReleaseName", signature: "s", body: [name])
  end

  def name_has_owner(conn, name) do
    call_bus(conn, "NameHasOwner", signature: "s", body: [name])
  end

  def get_name_owner(conn, name) do
    call_bus(conn, "GetNameOwner", signature: "s", body: [name])
  end

  def add_match(conn, rule) do
    call_bus(conn, "AddMatch", signature: "s", body: [rule])
  end

  def call(conn, destination, path, interface, member, opts \\ []) do
    proxy = Proxy.new(conn, destination, path)
    Proxy.call(proxy, interface, member, opts)
  end

  def listen_for_signal(interface, member, timeout \\ 2_000) do
    receive do
      {:ex_d_bus, {:message, %{type: :signal, interface: ^interface, member: ^member} = msg}} ->
        {:ok, msg}
    after
      timeout -> {:error, :timeout}
    end
  end

  def await_signal(interface, member, body, timeout \\ 2_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_signal_until(interface, member, body, deadline)
  end

  def refute_signal(interface, member, timeout \\ 300) do
    receive do
      {:ex_d_bus, {:message, %{type: :signal, interface: ^interface, member: ^member} = msg}} ->
        {:error, {:unexpected_signal, msg}}
    after
      timeout -> :ok
    end
  end

  def await_signal_matching(interface, member, predicate, timeout \\ 2_000)
      when is_function(predicate, 1) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_signal_matching_until(interface, member, predicate, deadline)
  end

  def abrupt_disconnect(conn) when is_pid(conn) do
    ref = Process.monitor(conn)
    Process.unlink(conn)
    Process.exit(conn, :kill)

    receive do
      {:DOWN, ^ref, :process, ^conn, _reason} -> :ok
    after
      2_000 -> {:error, :disconnect_timeout}
    end
  end

  def disconnect(conn) do
    Connection.disconnect(conn)
  catch
    _, _ -> :ok
  end

  defp call_bus(conn, member, opts \\ []) do
    msg =
      Message.method_call(
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        member,
        [destination: "org.freedesktop.DBus"] ++ opts
      )

    Connection.call(conn, msg, @call_timeout)
  end

  defp await_signal_until(interface, member, body, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {:ex_d_bus,
       {:message, %{type: :signal, interface: ^interface, member: ^member, body: ^body} = msg}} ->
        {:ok, msg}

      {:ex_d_bus, {:message, %{type: :signal}}} ->
        await_signal_until(interface, member, body, deadline)
    after
      remaining -> {:error, :timeout}
    end
  end

  defp await_signal_matching_until(interface, member, predicate, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {:ex_d_bus, {:message, %{type: :signal, interface: ^interface, member: ^member} = msg}} ->
        if predicate.(msg) do
          {:ok, msg}
        else
          await_signal_matching_until(interface, member, predicate, deadline)
        end

      {:ex_d_bus, {:message, %{type: :signal}}} ->
        await_signal_matching_until(interface, member, predicate, deadline)
    after
      remaining -> {:error, :timeout}
    end
  end
end
