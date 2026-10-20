defmodule GaoBus.Activation.State do
  @moduledoc """
  Pure, bounded activation bookkeeping. The caller supplies monotonic time,
  authority identities and opaque leases, and executes returned ordered effects.

  Name hints only request Router resolution. A successful helper exit never
  establishes readiness. Verified ownership can retire an attempt while its
  separately charged child record remains until the exact backend exit.
  Lost observation retains an uncertain charge until the release's manager
  clears its cgroup; ownership and elapsed time cannot establish termination.
  """

  import Bitwise, only: [band: 2]

  @defaults [
    max_pending_service_starts: 512,
    service_start_timeout: 25_000,
    max_attempts: 512,
    max_units: 128,
    max_live_children: 64
  ]
  @waiter_fields ~w(caller caller_incarnation request serial kind message_type flags destination generation definition deadline lease)a

  defstruct [
    :epoch,
    :options,
    :generation,
    :definitions,
    attempts: %{},
    names: %{},
    requests: %{},
    serials: %{},
    units: %{},
    children: %{},
    sequence: 0
  ]

  def new(epoch, options) do
    limits = Map.new(Keyword.merge(@defaults, Keyword.take(options, Keyword.keys(@defaults))))

    unless Enum.all?(limits, fn {_key, value} -> is_integer(value) and value >= 0 end) do
      raise ArgumentError, "activation limits must be finite nonnegative integers"
    end

    %__MODULE__{epoch: epoch, options: limits, generation: Keyword.get(options, :generation, 1)}
  end

  @doc "Returns updated metadata and effects without performing any process or resource operation."
  def transition(state, {:admit, waiter, reference, selected}, now) do
    with :ok <- validate_admission(state, waiter, reference, selected, now),
         :ok <- validate_unit_deadline(state, selected, now),
         :ok <- admission_capacity(state, waiter, selected) do
      admit(state, waiter, reference, selected, now)
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  def transition(state, {:commit_issue, key, generation}, now) do
    case Map.get(state.attempts, key) do
      nil ->
        ignored(state)

      %{issued: true} ->
        ignored(state)

      %{owned: true} ->
        ignored(state)

      attempt ->
        cond do
          generation != state.generation ->
            {:error, :stale_generation, state}

          not current_definition?(state, attempt.name, attempt.definition) ->
            {next, effects} =
              remove_waiters(state, key, Map.keys(attempt.waiters), :definition_changed)

            ok(next, effects)

          true ->
            commit(state, key, now)
        end
    end
  end

  def transition(state, {:name_available, name}, now) do
    matching =
      state.attempts
      |> Enum.filter(fn {_key, attempt} -> attempt.name == name end)
      |> Enum.sort_by(fn {_key, attempt} -> attempt.sequence end)

    {next, effects} =
      Enum.reduce(matching, {state, []}, fn {key, _attempt}, {current, effects} ->
        {current, expired} = expire(current, key, now)
        {current, resolutions} = resolve(current, key)
        {current, effects ++ expired ++ resolutions}
      end)

    ok(next, effects)
  end

  def transition(state, {:finish_waiter, key, request, outcome}, _now) do
    case get_in(state.attempts, [key, :waiters, request]) do
      nil -> ignored(state)
      waiter -> finish(state, key, waiter, outcome)
    end
  end

  def transition(state, {:caller_down, incarnation}, _now) do
    affected = state.attempts |> Enum.sort_by(fn {_key, attempt} -> attempt.sequence end)

    {next, effects} =
      Enum.reduce(affected, {state, []}, fn {key, attempt}, {current, effects} ->
        requests =
          attempt.waiters
          |> Enum.filter(fn {_request, waiter} ->
            waiter.caller_incarnation == incarnation
          end)
          |> Enum.map(&elem(&1, 0))

        {current, retired} = remove_waiters(current, key, requests, :caller_down)
        {current, effects ++ retired}
      end)

    ok(next, effects)
  end

  def transition(state, {:expire, key}, now) do
    if Map.has_key?(state.attempts, key) do
      {next, effects} = expire(state, key, now)
      ok(next, effects)
    else
      ignored(state)
    end
  end

  def transition(state, {:backend_result, key, result}, _now) do
    case Map.get(state.children, key) do
      %{phase: :uncertain} when result != :owned ->
        ignored(state)

      _ ->
        if Map.has_key?(state.attempts, key) or Map.has_key?(state.children, key),
          do: backend_result(state, key, result),
          else: ignored(state)
    end
  end

  def transition(state, {:reload, generation, definitions}, _now) do
    if generation > state.generation do
      effects =
        state.attempts
        |> Enum.filter(fn {_key, attempt} ->
          not attempt.issued and not attempt.owned
        end)
        |> Enum.sort_by(fn {_key, attempt} -> attempt.sequence end)
        |> Enum.map(fn {key, _attempt} -> {:request_launch_commit, key} end)

      ok(%{state | generation: generation, definitions: definitions}, effects)
    else
      ignored(state)
    end
  end

  defp validate_admission(state, waiter, reference, selected, now) do
    cond do
      not valid_identity?(state.epoch, waiter, reference) ->
        {:error, :invalid_identity}

      waiter.kind == :automatic and band(waiter.flags, 0x2) != 0 ->
        {:error, :no_auto_start}

      Map.has_key?(state.requests, waiter.request) ->
        {:error, :duplicate_request}

      Map.has_key?(state.serials, waiter.serial) ->
        {:error, :duplicate_serial}

      waiter.generation != state.generation ->
        {:error, :stale_generation}

      waiter.deadline <= now ->
        {:error, :deadline_expired}

      waiter.definition != selected.key ->
        {:error, :definition_changed}

      not current_definition?(state, waiter.destination, selected) ->
        {:error, :definition_changed}

      true ->
        validate_join(state, waiter.destination, selected, now)
    end
  end

  defp valid_identity?(
         epoch,
         %{
           caller: caller,
           caller_incarnation: incarnation,
           request: {epoch, request},
           serial: {epoch, incarnation, serial},
           kind: kind,
           message_type: type,
           flags: flags,
           destination: destination,
           generation: _generation,
           definition: _definition,
           deadline: deadline,
           lease: _lease
         },
         reference
       ) do
    is_pid(caller) and is_reference(request) and is_reference(reference) and
      is_integer(serial) and serial > 0 and serial <= 0xFFFFFFFF and
      kind in [:automatic, :explicit] and type in [:method_call, :signal] and
      is_integer(flags) and flags >= 0 and is_binary(destination) and is_integer(deadline)
  end

  defp valid_identity?(_epoch, _waiter, _reference), do: false

  defp validate_join(state, name, selected, now) do
    case Map.get(state.attempts, Map.get(state.names, name)) do
      nil ->
        :ok

      attempt ->
        cond do
          not same_definition?(attempt.definition, selected) -> {:error, :definition_changed}
          map_size(attempt.waiters) == 0 -> {:error, :attempt_unresolved}
          not active_waiters?(attempt) -> {:error, :attempt_unresolved}
          attempt.deadline <= now -> {:error, :deadline_expired}
          true -> :ok
        end
    end
  end

  defp validate_unit_deadline(state, %{backend: :systemd, unit: unit}, now) do
    case Map.get(state.units, {state.epoch, unit}) do
      %{failed: true} -> {:error, :attempt_unresolved}
      %{deadline: deadline} when deadline <= now -> {:error, :deadline_expired}
      _ -> :ok
    end
  end

  defp validate_unit_deadline(_state, _selected, _now), do: :ok

  defp unit_deadline(state, %{backend: :systemd, unit: unit}, fallback) do
    case Map.get(state.units, {state.epoch, unit}) do
      nil -> fallback
      record -> min(record.deadline, fallback)
    end
  end

  defp unit_deadline(_state, _selected, fallback), do: fallback

  defp admission_capacity(state, waiter, selected) do
    new_attempt? = not Map.has_key?(state.names, waiter.destination)

    new_unit? =
      selected.backend == :systemd and
        not Map.has_key?(state.units, {state.epoch, selected.unit})

    if map_size(state.requests) >= state.options.max_pending_service_starts or
         (new_attempt? and map_size(state.attempts) >= state.options.max_attempts) or
         (new_attempt? and new_unit? and map_size(state.units) >= state.options.max_units) do
      {:error, :limits_exceeded}
    else
      :ok
    end
  end

  defp admit(state, input, reference, selected, now) do
    key = Map.get(state.names, input.destination, {state.epoch, reference})
    fresh? = not Map.has_key?(state.attempts, key)

    attempt =
      Map.get(state.attempts, key, %{
        name: input.destination,
        definition: selected,
        deadline: unit_deadline(state, selected, now + state.options.service_start_timeout),
        timer_deadline: nil,
        issued: false,
        owned: false,
        backend_done: false,
        sequence: state.sequence,
        waiters: %{}
      })

    waiter =
      input
      |> Map.take(@waiter_fields)
      |> Map.put(:sequence, state.sequence)
      |> Map.put(:resolving, false)
      |> Map.put(:pending_terminal, nil)
      |> Map.put(:deadline, min(input.deadline, attempt.deadline))

    attempt = %{attempt | waiters: Map.put(attempt.waiters, waiter.request, waiter)}

    next = %{
      state
      | attempts: Map.put(state.attempts, key, attempt),
        names: Map.put(state.names, input.destination, key),
        requests: Map.put(state.requests, waiter.request, key),
        serials: Map.put(state.serials, waiter.serial, waiter.request),
        sequence: state.sequence + 1
    }

    next = if fresh?, do: attach_unit(next, key, selected), else: next
    {next, effects} = reconcile(next, key)
    effects = if fresh?, do: effects ++ [{:request_launch_commit, key}], else: effects
    {:ok, next, {:admitted, key}, effects}
  end

  defp attach_unit(state, key, %{backend: :systemd, unit: unit}) do
    identity = {state.epoch, unit}

    record =
      Map.get(state.units, identity, %{
        issued: false,
        issuer: nil,
        failed: false,
        attempts: MapSet.new(),
        deadline: state.attempts[key].deadline
      })

    %{
      state
      | units:
          Map.put(state.units, identity, %{record | attempts: MapSet.put(record.attempts, key)})
    }
  end

  defp attach_unit(state, _key, _selected), do: state

  defp commit(state, key, now) do
    {next, effects} = expire(state, key, now)

    case Map.get(next.attempts, key) do
      nil ->
        ok(next, effects)

      attempt ->
        if active_waiters?(attempt) do
          case issue(next, key, attempt, effects) do
            {:error, reason, _next} -> {:error, reason, state}
            result -> result
          end
        else
          ok(next, effects)
        end
    end
  end

  defp issue(state, key, %{definition: %{backend: :wait}} = attempt, effects) do
    next = %{state | attempts: Map.put(state.attempts, key, %{attempt | issued: true})}
    {:ok, next, :waiting, effects}
  end

  defp issue(state, key, %{definition: %{backend: :helper}} = attempt, effects) do
    if map_size(state.children) >= state.options.max_live_children do
      {:error, :limits_exceeded, state}
    else
      next = %{
        state
        | attempts: Map.put(state.attempts, key, %{attempt | issued: true}),
          children:
            Map.put(state.children, key, %{
              name: attempt.name,
              definition: attempt.definition,
              token: key,
              phase: :reserved
            })
      }

      {:ok, next, :issued, effects ++ [{:launch, key, attempt.definition}]}
    end
  end

  defp issue(state, key, %{definition: %{backend: :systemd, unit: unit}} = attempt, effects) do
    identity = {state.epoch, unit}
    record = Map.fetch!(state.units, identity)

    next = %{
      state
      | attempts: Map.put(state.attempts, key, %{attempt | issued: true}),
        units:
          Map.put(
            state.units,
            identity,
            if(record.issued, do: record, else: %{record | issued: true, issuer: key})
          )
    }

    if record.issued do
      {:ok, next, :coalesced, effects}
    else
      {:ok, next, :issued, effects ++ [{:launch, key, attempt.definition}]}
    end
  end

  defp resolve(state, key) do
    case Map.get(state.attempts, key) do
      nil ->
        {state, []}

      attempt ->
        waiting = ordered_waiters(attempt) |> Enum.reject(& &1.resolving)

        waiters =
          Enum.reduce(waiting, attempt.waiters, fn waiter, waiters ->
            Map.put(waiters, waiter.request, %{waiter | resolving: true})
          end)

        effects = Enum.map(waiting, &{:resolve_waiter, key, &1.request})

        {%{state | attempts: Map.put(state.attempts, key, %{attempt | waiters: waiters})},
         effects}
    end
  end

  defp finish(state, key, waiter, :retry) do
    cond do
      not waiter.resolving ->
        ignored(state)

      waiter.pending_terminal != nil ->
        {next, effects} =
          remove_waiters(state, key, [waiter.request], waiter.pending_terminal, true)

        ok(next, effects)

      true ->
        ok(put_in(state.attempts[key].waiters[waiter.request].resolving, false), [])
    end
  end

  defp finish(state, key, waiter, :delivered) do
    if waiter.resolving do
      state = put_in(state.attempts[key].owned, true)
      {next, effects} = remove_waiters(state, key, [waiter.request], :delivered)
      ok(next, effects)
    else
      ignored(state)
    end
  end

  defp finish(state, key, waiter, {:terminal, reason}) do
    {next, effects} = remove_waiters(state, key, [waiter.request], reason, true)
    ok(next, effects)
  end

  defp expire(state, key, now) do
    case Map.get(state.attempts, key) do
      nil ->
        {state, []}

      attempt ->
        # Systemd has no child exit to observe. Its fixed launch deadline also
        # retires an issued attempt after its last caller has gone away.
        state =
          if attempt.definition.backend == :systemd and attempt.deadline <= now,
            do: put_in(state.attempts[key].backend_done, true),
            else: state

        expired =
          ordered_waiters(attempt)
          |> Enum.filter(&(&1.deadline <= now and &1.pending_terminal == nil))
          |> Enum.map(& &1.request)

        if expired == [],
          do: reconcile(state, key),
          else: remove_waiters(state, key, expired, :timed_out)
    end
  end

  defp remove_waiters(state, key, requests, reason, acknowledged? \\ false)

  defp remove_waiters(state, _key, [], _reason, _acknowledged?), do: {state, []}

  defp remove_waiters(state, key, requests, reason, acknowledged?) do
    attempt = Map.fetch!(state.attempts, key)
    selected = ordered_waiters(attempt) |> Enum.filter(&(&1.request in requests))

    {next, effects} =
      Enum.reduce(selected, {state, []}, fn waiter, {current, effects} ->
        if waiter.resolving and reason != :delivered and not acknowledged? do
          pending = if waiter.pending_terminal == nil, do: reason, else: waiter.pending_terminal

          {put_in(current.attempts[key].waiters[waiter.request].pending_terminal, pending),
           effects}
        else
          terminal =
            if reason == :delivered,
              do: [],
              else: [{:terminal_waiter, key, waiter.request, reason}]

          current = %{
            current
            | requests: Map.delete(current.requests, waiter.request),
              serials: Map.delete(current.serials, waiter.serial)
          }

          current = update_in(current.attempts[key].waiters, &Map.delete(&1, waiter.request))
          {current, effects ++ terminal ++ [{:release_lease, waiter.request, waiter.lease}]}
        end
      end)

    {next, timers} = reconcile(next, key)
    {next, effects ++ timers}
  end

  defp reconcile(state, key) do
    attempt = Map.fetch!(state.attempts, key)
    empty? = map_size(attempt.waiters) == 0

    retire? =
      empty? and
        (not attempt.issued or attempt.owned or attempt.backend_done or
           attempt.definition.backend == :wait)

    deadline =
      cond do
        retire? ->
          nil

        empty? ->
          if attempt.definition.backend == :systemd, do: attempt.deadline

        true ->
          attempt.waiters
          |> Map.values()
          |> Enum.reject(&(&1.pending_terminal != nil))
          |> Enum.map(& &1.deadline)
          |> Enum.min(fn -> nil end)
      end

    effects =
      cond do
        deadline == attempt.timer_deadline -> []
        deadline == nil -> [{:cancel_deadline, key}]
        true -> [{:arm_deadline, key, deadline}]
      end

    next = put_in(state.attempts[key].timer_deadline, deadline)
    {if(retire?, do: retire_attempt(next, key), else: next), effects}
  end

  defp retire_attempt(state, key) do
    attempt = Map.fetch!(state.attempts, key)

    names =
      if Map.get(state.names, attempt.name) == key,
        do: Map.delete(state.names, attempt.name),
        else: state.names

    next = %{state | attempts: Map.delete(state.attempts, key), names: names}

    case attempt.definition do
      %{backend: :systemd, unit: unit} ->
        identity = {state.epoch, unit}
        record = Map.fetch!(state.units, identity)
        remaining = MapSet.delete(record.attempts, key)

        units =
          if MapSet.size(remaining) == 0,
            do: Map.delete(state.units, identity),
            else: Map.put(state.units, identity, %{record | attempts: remaining})

        %{next | units: units}

      %{backend: backend} when backend in [:helper, :wait] ->
        next
    end
  end

  defp backend_result(state, key, :owned) do
    case Map.get(state.attempts, key) do
      nil ->
        ignored(state)

      _attempt ->
        state = put_in(state.attempts[key].owned, true)
        {next, effects} = reconcile(state, key)
        ok(next, effects)
    end
  end

  defp backend_result(state, key, result) when result in [:not_launched, {:exited, 0}] do
    state = %{state | children: Map.delete(state.children, key)}

    case Map.get(state.attempts, key) do
      nil ->
        ok(state, [])

      _attempt ->
        state = put_in(state.attempts[key].backend_done, true)
        {next, effects} = reconcile(state, key)
        ok(next, effects)
    end
  end

  defp backend_result(state, key, {:exited, status}),
    do: backend_result(state, key, {:error, {:backend_failed, status}})

  defp backend_result(state, key, {:signaled, signal}) when signal in 1..64 do
    if Map.has_key?(state.children, key),
      do: backend_result(state, key, {:error, {:backend_signaled, signal}}),
      else: ignored(state)
  end

  defp backend_result(state, key, {:error, {:observation_lost, _reason} = reason}) do
    case Map.get(state.children, key) do
      nil ->
        ignored(state)

      child ->
        state = %{state | children: Map.put(state.children, key, %{child | phase: :uncertain})}

        case Map.get(state.attempts, key) do
          nil ->
            ok(state, [])

          attempt ->
            {next, effects} = remove_waiters(state, key, Map.keys(attempt.waiters), reason)

            {next, timers} =
              if Map.has_key?(next.attempts, key),
                do: reconcile(next, key),
                else: {next, []}

            ok(next, effects ++ timers)
        end
    end
  end

  defp backend_result(state, key, {:error, reason}) do
    {state, keys} =
      case Map.get(state.attempts, key) do
        %{definition: %{backend: :systemd, unit: unit}} ->
          identity = {state.epoch, unit}
          record = Map.fetch!(state.units, identity)
          keys = record.attempts |> Enum.sort_by(fn member -> state.attempts[member].sequence end)
          {%{state | units: Map.put(state.units, identity, %{record | failed: true})}, keys}

        _ ->
          {state, [key]}
      end

    {next, effects} =
      Enum.reduce(keys, {state, []}, fn member, {current, effects} ->
        current = %{current | children: Map.delete(current.children, member)}

        case Map.get(current.attempts, member) do
          nil ->
            {current, effects}

          attempt ->
            current = put_in(current.attempts[member].backend_done, true)

            {current, retired} =
              remove_waiters(current, member, Map.keys(attempt.waiters), reason)

            {current, timers} =
              if Map.has_key?(current.attempts, member),
                do: reconcile(current, member),
                else: {current, []}

            {current, effects ++ retired ++ timers}
        end
      end)

    ok(next, effects)
  end

  defp current_definition?(%{definitions: nil}, _name, _selected), do: true

  defp current_definition?(state, name, selected) do
    case Map.get(state.definitions, name) do
      nil -> false
      current -> same_definition?(current, selected)
    end
  end

  defp same_definition?(left, right),
    do: left.key == right.key and left.backend == right.backend and left.unit == right.unit

  defp ordered_waiters(attempt),
    do: attempt.waiters |> Map.values() |> Enum.sort_by(& &1.sequence)

  defp active_waiters?(attempt),
    do: Enum.any?(attempt.waiters, fn {_request, waiter} -> waiter.pending_terminal == nil end)

  defp ok(state, effects), do: {:ok, state, :ok, effects}
  defp ignored(state), do: {:ok, state, :ignored, []}
end
