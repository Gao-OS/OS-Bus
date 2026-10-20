defmodule GaoBusFairnessCollector do
  @moduledoc false

  def start do
    spawn_link(fn ->
      loop(%{
        rows: [],
        failures: [],
        reservation: nil,
        seen: 0,
        peak_queue: 0,
        peak_router_mailbox: 0
      })
    end)
  end

  def snapshot(pid) do
    ref = make_ref()
    send(pid, {:snapshot, self(), ref})

    receive do
      {^ref, state} -> state
    after
      3000 -> raise "trace collector deadline"
    end
  end

  defp loop(state) do
    {:message_queue_len, queue} = Process.info(self(), :message_queue_len)

    router_queue =
      case Process.info(Process.whereis(GaoBus.Router), :message_queue_len) do
        {:message_queue_len, count} -> count
        nil -> 0
      end

    state = %{
      state
      | peak_queue: max(state.peak_queue, queue),
        peak_router_mailbox: max(state.peak_router_mailbox, router_queue)
    }

    if queue > 1100, do: raise("trace queue ceiling")

    receive do
      {:trace, _router, :call,
       {GaoBus.Limits, :reserve_egress, [target, bytes, fds, _server, _source]}} ->
        loop(%{state | reservation: %{target: inspect(target), bytes: bytes, fds: fds}})

      {:trace, _router, :return_from, {GaoBus.Limits, :reserve_egress, 5}, result} ->
        state =
          case result do
            {:ok, _token} ->
              state

            {:error, {:limit_exceeded, scope, metric}} ->
              row =
                Map.merge(state.reservation, %{scope: to_string(scope), metric: to_string(metric)})

              %{state | failures: [row | state.failures], seen: state.seen + 1}

            other ->
              raise "unexpected reservation disposition #{inspect(other)}"
          end

        if state.seen > 1100, do: raise("trace summary row ceiling")
        loop(%{state | reservation: nil})

      {:trace, _router, :send, {:send_message, message, {_token, _queued}}, target} ->
        selected =
          message.member in ["FairPulse", "Hold"] or
            (message.type == :method_return and message.reply_serial in 200_000..202_000)

        state =
          if selected do
            body =
              case message.body do
                [value] when is_binary(value) -> value
                _ -> <<>>
              end

            row = %{
              target: inspect(target),
              sender: message.sender,
              serial: message.serial,
              type: to_string(message.type),
              member: message.member,
              reply_serial: message.reply_serial,
              bytes: byte_size(body),
              sha256: Base.encode16(:crypto.hash(:sha256, body), case: :lower)
            }

            %{state | rows: [row | state.rows], seen: state.seen + 1}
          else
            state
          end

        if state.seen > 1100, do: raise("trace summary row ceiling")
        # Retain only fixed-size identity/hash summaries, never the traced body.
        loop(state)

      {:snapshot, from, ref} ->
        :erlang.garbage_collect()

        send(
          from,
          {ref, %{state | rows: Enum.reverse(state.rows), failures: Enum.reverse(state.failures)}}
        )

        loop(state)

      :stop ->
        :ok

      _ ->
        loop(state)
    end
  end
end
