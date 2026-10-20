defmodule GaoBusFairnessTimingSampler do
  @moduledoc false
  @period_ns 50_000_000
  @duration_ns 8_000_000_000
  @max_samples 160
  @max_targets 15

  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :temporary}
  end

  def start_link(opts),
    do: {:ok, start(Keyword.fetch!(opts, :path), Keyword.fetch!(opts, :targets))}

  def due?(index, started_ns, actual_ns) do
    index < @max_samples and actual_ns < started_ns + @duration_ns
  end

  def sanitize_stack(stack) do
    Enum.take(stack, 12)
    |> Enum.map(fn {module, function, arity, location} ->
      safe_location =
        for {key, value} <- Keyword.take(location, [:file, :line]), into: %{} do
          value =
            if key == :file, do: value |> List.to_string() |> String.slice(0, 256), else: value

          {Atom.to_string(key), value}
        end

      %{
        module: Atom.to_string(module),
        function: Atom.to_string(function),
        arity: if(is_integer(arity), do: arity, else: length(arity)),
        location: safe_location
      }
    end)
  end

  def process_row(pid, label) do
    case Process.info(pid, [:status, :current_stacktrace, :reductions, :message_queue_len]) do
      nil ->
        %{peer: inspect(pid), label: label, departed: true}

      fields ->
        %{
          peer: inspect(pid),
          label: label,
          status: Atom.to_string(fields[:status]),
          stack: sanitize_stack(fields[:current_stacktrace]),
          reductions: fields[:reductions],
          mailbox: fields[:message_queue_len]
        }
    end
  end

  def start(path, targets) do
    if length(targets) > @max_targets or
         length(Enum.uniq_by(targets, &elem(&1, 0))) != length(targets),
       do: raise("timing target bound or duplicate")

    started_ns = System.monotonic_time(:nanosecond)

    spawn_link(fn ->
      append(path, %{
        event: "sampler_start",
        started_ns: started_ns,
        realtime_ns: System.os_time(:nanosecond),
        period_ns: @period_ns,
        max_samples: @max_samples,
        duration_ns: @duration_ns,
        targets: length(targets)
      })

      send(self(), {:tick, 0})
      loop(path, targets, started_ns, 0, nil, nil)
    end)
  end

  def stop(pid) do
    ref = Process.monitor(pid)
    send(pid, {:stop, self(), ref})

    result =
      receive do
        {^ref, result} -> result
      after
        3000 -> raise "timing sampler stop deadline"
      end

    receive do
      {:DOWN, ^ref, :process, ^pid, :normal} -> result
    after
      3000 -> raise "timing sampler DOWN deadline"
    end
  end

  defp loop(path, targets, started_ns, index, first_ns, last_ns) do
    receive do
      {:tick, ^index} ->
        actual_ns = System.monotonic_time(:nanosecond)
        actual_realtime_ns = System.os_time(:nanosecond)

        if due?(index, started_ns, actual_ns) do
          rows = Enum.map(targets, fn {pid, label} -> process_row(pid, label) end)
          completed_ns = System.monotonic_time(:nanosecond)

          append(path, %{
            event: "sample",
            index: index,
            scheduled_ns: started_ns + index * @period_ns,
            actual_ns: actual_ns,
            actual_realtime_ns: actual_realtime_ns,
            completed_ns: completed_ns,
            realtime_ns: System.os_time(:nanosecond),
            rows: rows
          })

          next = index + 1

          if due?(next, started_ns, completed_ns) do
            delay_ms =
              max(div(started_ns + next * @period_ns - completed_ns + 999_999, 1_000_000), 0)

            Process.send_after(self(), {:tick, next}, delay_ms)
          end

          loop(path, targets, started_ns, next, first_ns || actual_ns, completed_ns)
        else
          loop(path, targets, started_ns, index, first_ns, last_ns)
        end

      {:stop, from, ref} ->
        result = %{
          event: "sampler_stop",
          samples: index,
          first_ns: first_ns,
          last_ns: last_ns,
          stopped_ns: System.monotonic_time(:nanosecond),
          realtime_ns: System.os_time(:nanosecond)
        }

        append(path, result)
        send(from, {ref, result})
    end
  end

  defp append(path, row) do
    File.write!(path, IO.iodata_to_binary(:json.encode(row)) <> "\n", [:append])
  end
end
