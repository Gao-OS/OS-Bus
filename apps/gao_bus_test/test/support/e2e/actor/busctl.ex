defmodule GaoBusTest.E2E.Actor.Busctl do
  @moduledoc """
  busctl command actor.
  """

  alias GaoBusTest.E2E.{Command, Context, Qualification}

  def available?, do: System.find_executable("busctl") != nil
  def missing_reason, do: "busctl not found on PATH"

  def run(%Context{} = context, args, opts \\ []) do
    env = [
      {"DBUS_SESSION_BUS_ADDRESS", context.bus_address},
      {"DBUS_SYSTEM_BUS_ADDRESS", context.bus_address}
    ]

    result =
      Command.run(
        "busctl",
        ["--address=#{context.bus_address}" | args],
        Keyword.merge(opts, env: env)
      )

    if result.exit_status != 127,
      do: Qualification.actor(context, :busctl, %{command: result.command})

    {result, Context.add_command(context, result)}
  end
end
