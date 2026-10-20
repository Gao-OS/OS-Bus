defmodule GaoBus.Unix.Writer do
  @moduledoc """
  Nonblocking continuation for one immutable byte stream and its owned rights.

  Each step performs at most one 64 KiB send. Rights commit only on a positive
  byte count and are never resent with the tail. A blocked step polls readiness
  without waiting; its caller schedules one bounded tick and keeps the absolute
  deadline. The delivery owner closes handles on completion/error, never here.
  """

  alias GaoBus.Unix.Resources

  defstruct [:bytes, :handles, :deadline, offset: 0, rights_sent: false, blocked: false]

  def new(bytes, handles, now, options \\ []) do
    if Keyword.keyword?(options) and Keyword.keys(options) -- [:timeout_ms, :max_bytes] == [] and
         length(options) <= 2 do
      timeout = Keyword.get(options, :timeout_ms, 5000)
      max_bytes = Keyword.get(options, :max_bytes, 1_048_576)

      if is_binary(bytes) and is_integer(max_bytes) and max_bytes in 1..134_217_728 and
           byte_size(bytes) in 1..max_bytes and is_list(handles) and length(handles) <= 253 and
           is_integer(now) and is_integer(timeout) and timeout in 1..60_000,
         do: {:ok, %__MODULE__{bytes: bytes, handles: handles, deadline: now + timeout}},
         else: {:error, :invalid_writer}
    else
      {:error, :invalid_writer}
    end
  end

  def step(socket, %__MODULE__{} = state, now) do
    cond do
      state.offset == byte_size(state.bytes) ->
        {:done, state}

      now >= state.deadline ->
        {:error, :send_timeout, state}

      state.blocked ->
        case Resources.writable?(socket) do
          {:ok, true} -> send_chunk(socket, %{state | blocked: false})
          {:ok, false} -> {:wait, state}
          {:error, :eintr} -> {:wait, state}
          {:error, reason} -> {:error, reason, state}
        end

      true ->
        send_chunk(socket, state)
    end
  end

  defp send_chunk(socket, state) do
    length = min(65_536, byte_size(state.bytes) - state.offset)
    chunk = binary_part(state.bytes, state.offset, length)
    handles = if state.rights_sent, do: [], else: state.handles

    case Resources.send(socket, chunk, handles) do
      {:ok, count} when count > 0 ->
        next = %{state | offset: state.offset + count, rights_sent: true}
        if next.offset == byte_size(next.bytes), do: {:done, next}, else: {:wait, next}

      {:ok, 0} ->
        {:error, :zero_send, state}

      {:error, :eagain} ->
        {:wait, %{state | blocked: true}}

      {:error, :eintr} ->
        {:wait, state}

      {:error, reason} ->
        {:error, reason, state}
    end
  end
end
