defmodule GaoBus.Activation.Systemd do
  @moduledoc """
  Pure systemd Activator wire boundary. Router routes the authority-generated
  request through its bounded policy and recipient checks.

  Failure context is an ordered, trusted Router snapshot: actual source PID,
  UID and monitor incarnation, current systemd1 owner PID/incarnation, local
  epoch/current_epoch, daemon UID, policy approval and a checked non-container
  status. Incarnations are `{monitor_ref, unique_name}`; the monitor reference
  is distinct from the authority epoch. `container_checked: true, container:
  false` means the source is not a registered D-Bus container instance, not a
  claim about OS namespaces. This module implements no container facility.

  ActivationFailure has no wire epoch or attempt token. Its correlation is
  unit-only under the current authenticated owner and local authority epoch.
  Pure validation does not establish runtime or disposable-VM acceptance.
  """

  alias ExDBus.Message

  @bus "org.freedesktop.DBus"
  @systemd "org.freedesktop.systemd1"
  @interface "org.freedesktop.systemd1.Activator"
  @uint32_max 0xFFFFFFFF
  @unique_name ~r/\A:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\z/
  @error_name ~r/\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\z/

  def request(unit, serial) do
    cond do
      not bounded_string?(unit, 255, false) ->
        {:error, :invalid_unit}

      not valid_serial?(serial) ->
        {:error, :invalid_serial}

      true ->
        {:ok,
         %Message{
           type: :signal,
           serial: serial,
           sender: @bus,
           destination: @systemd,
           path: "/org/freedesktop/DBus",
           interface: @interface,
           member: "ActivationRequest",
           signature: "s",
           body: [unit]
         }}
    end
  end

  def failure(%Message{} = message, context) do
    cond do
      not systemd_mode?(context) -> {:error, :not_systemd_mode}
      not authorized?(context) -> {:error, :unauthorized}
      not current_owner?(context, message.sender) -> {:error, :invalid_identity}
      not failure_envelope?(message) -> {:error, :invalid_envelope}
      true -> failure_arguments(message.body)
    end
  end

  def failure(_message, _context), do: {:error, :invalid_envelope}

  defp systemd_mode?(%{systemd_mode: true}), do: true
  defp systemd_mode?(_context), do: false

  defp authorized?(%{
         authorized: true,
         container_checked: true,
         container: false,
         uid: uid,
         daemon_uid: daemon_uid
       })
       when is_integer(uid) and uid >= 0 and uid < @uint32_max and
              is_integer(daemon_uid) and daemon_uid >= 0 and daemon_uid < @uint32_max do
    uid == 0 or uid == daemon_uid
  end

  defp authorized?(_context), do: false

  defp current_owner?(
         %{
           epoch: epoch,
           current_epoch: epoch,
           current_owner: owner,
           peer: owner,
           current_owner_incarnation: {monitor, name},
           peer_incarnation: {monitor, name}
         },
         sender
       )
       when is_pid(owner) and is_reference(monitor) and not is_nil(epoch) do
    name == sender and bounded_string?(name, 255, false) and Regex.match?(@unique_name, name)
  end

  defp current_owner?(_context, _sender), do: false

  defp failure_envelope?(%Message{
         type: :signal,
         serial: serial,
         flags: flags,
         destination: @bus,
         path: "/org/freedesktop/systemd1",
         interface: @interface,
         member: "ActivationFailure",
         signature: "sss",
         unix_fds: unix_fds,
         fds: [],
         reply_serial: nil,
         error_name: nil
       }) do
    valid_serial?(serial) and is_integer(flags) and flags >= 0 and flags <= 255 and
      unix_fds in [nil, 0]
  end

  defp failure_envelope?(_message), do: false

  defp failure_arguments([unit, name, text]) do
    if bounded_string?(unit, 255, false) and bounded_string?(name, 255, false) and
         Regex.match?(@error_name, name) and bounded_string?(text, 4096, true) do
      {:ok, %{unit: unit, error_name: name, error_text: text}}
    else
      {:error, :invalid_arguments}
    end
  end

  defp failure_arguments(_body), do: {:error, :invalid_arguments}

  defp bounded_string?(value, limit, empty?) when is_binary(value) do
    byte_size(value) <= limit and (empty? or byte_size(value) > 0) and
      String.valid?(value) and :binary.match(value, <<0>>) == :nomatch
  end

  defp bounded_string?(_value, _limit, _empty?), do: false
  defp valid_serial?(serial), do: is_integer(serial) and serial > 0 and serial <= @uint32_max
end
