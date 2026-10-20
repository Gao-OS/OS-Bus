defmodule GaoBus.PendingCalls do
  @moduledoc """
  Bounded causal reply state owned by Router. Entries contain only connection
  incarnations, serial, trusted UID, and deadline; no message bodies or FDs.
  """

  @defaults %{per_peer: 128, per_uid: 256, global: 1024, timeout_ms: 25_000}

  def new(overrides \\ %{}) do
    if is_map(overrides) and Map.keys(overrides) -- Map.keys(@defaults) == [] and
         Enum.all?(overrides, fn
           {:timeout_ms, :infinity} -> true
           {_key, value} -> is_integer(value) and value in 0..0x7FFFFFFF
         end) do
      {:ok, %{entries: %{}, limits: Map.merge(@defaults, overrides)}}
    else
      {:error, :invalid_pending_limits}
    end
  end

  def add(state, message, caller, callee, uid, now) do
    key = {caller, message.serial}
    entries = Map.values(state.entries)

    cond do
      Map.has_key?(state.entries, key) ->
        {:error, :duplicate_serial}

      length(entries) >= state.limits.global ->
        {:error, :limits_exceeded}

      Enum.count(entries, &(&1.caller == caller)) >= state.limits.per_peer ->
        {:error, :limits_exceeded}

      Enum.count(entries, &(&1.uid == uid)) >= state.limits.per_uid ->
        {:error, :limits_exceeded}

      true ->
        entry = %{
          caller: caller,
          caller_name: message.sender,
          callee: callee,
          serial: message.serial,
          uid: uid,
          deadline: deadline(now, state.limits.timeout_ms)
        }

        {:ok, %{state | entries: Map.put(state.entries, key, entry)}}
    end
  end

  def requested?(state, caller, callee, serial, now) do
    case state.entries[{caller, serial}] do
      %{callee: ^callee, deadline: :infinity} -> true
      %{callee: ^callee, deadline: deadline} when is_integer(deadline) and deadline > now -> true
      _ -> false
    end
  end

  def complete(state, caller, callee, serial) do
    case state.entries[{caller, serial}] do
      %{callee: ^callee} -> %{state | entries: Map.delete(state.entries, {caller, serial})}
      _ -> state
    end
  end

  def expire(state, now),
    do: remove_where(state, &(&1.deadline != :infinity and &1.deadline <= now))

  def disconnected(state, peer) do
    {removed, state} = remove_where(state, &(&1.caller == peer or &1.callee == peer))
    {Enum.reject(removed, &(&1.caller == peer)), state}
  end

  def next_deadline(%{entries: entries}) when map_size(entries) == 0, do: nil

  def next_deadline(state),
    do:
      state.entries
      |> Map.values()
      |> Enum.map(& &1.deadline)
      |> Enum.reject(&(&1 == :infinity))
      |> Enum.min(fn -> :infinity end)

  defp deadline(_now, :infinity), do: :infinity
  defp deadline(now, timeout), do: now + timeout

  defp remove_where(state, predicate) do
    {removed, retained} =
      Enum.split_with(state.entries, fn {_key, entry} -> predicate.(entry) end)

    {Enum.map(removed, &elem(&1, 1)), %{state | entries: Map.new(retained)}}
  end
end
