defmodule GaoBusTest.E2E.Actor.GLibFixture do
  @moduledoc """
  Actor wrapper for the C/GLib external fixture.
  """

  alias GaoBusTest.E2E.{ChildProcess, Context, Qualification}

  @fixture_binary Path.expand(
                    Path.join([__DIR__, "..", "..", "..", "fixture", "external_fixture"])
                  )
  @startup_timeout 10_000

  @bus_name "com.test.ExternalFixture"
  @object_path "/com/test/ExternalFixture"
  @interface "com.test.ExternalFixture"

  def bus_name, do: @bus_name
  def object_path, do: @object_path
  def interface, do: @interface
  def fixture_binary, do: @fixture_binary

  def available?, do: File.exists?(@fixture_binary) and ChildProcess.available?()

  def missing_reason do
    "GLib fixture/process guard unavailable. Run: make -C apps/gao_bus_test/test/fixture"
  end

  def start(%Context{} = context, _opts \\ []) do
    if available?() do
      {:ok, worker} =
        ChildProcess.start(
          command: @fixture_binary,
          args: ["--bus-address=#{context.bus_address}"],
          env: [{"DBUS_SESSION_BUS_ADDRESS", context.bus_address}]
        )

      case ChildProcess.await_ready(worker, &String.contains?(&1, "READY"), @startup_timeout) do
        {:ok, %{pid: pid, output: log}} ->
          actor = %{worker: worker, pid: pid, log: log, binary: @fixture_binary}

          Qualification.actor(context, :glib_fixture, %{
            pid: pid,
            binary: @fixture_binary,
            log: log
          })

          {:ok, Context.put_actor(context, :glib_fixture, actor)}

        {:error, reason} ->
          log = ChildProcess.snapshot(worker).output
          ChildProcess.stop(worker)
          context = put_failed_actor(context, reason, log)
          {:error, {reason, log}, context}
      end
    else
      {:error, {:skip, missing_reason()}, context}
    end
  end

  def stop(%Context{} = context) do
    case Context.get_actor(context, :glib_fixture) do
      {:ok, %{worker: worker} = actor} when is_pid(worker) ->
        try do
          snapshot = ChildProcess.snapshot(worker)
          Context.remember_actor(context, :glib_fixture, %{actor | log: snapshot.output})
        catch
          :exit, {:noproc, _} -> :ok
        end

        ChildProcess.stop(worker)

      {:ok, _failed_actor} ->
        :ok

      :error ->
        :ok
    end

    {:ok, Context.delete_actor(context, :glib_fixture)}
  end

  defp put_failed_actor(%Context{} = context, reason, log) do
    actor = %{
      worker: nil,
      pid: nil,
      log: log,
      binary: @fixture_binary,
      start_error: reason
    }

    Context.put_actor(context, :glib_fixture, actor)
  end
end
