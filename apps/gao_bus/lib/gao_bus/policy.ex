defmodule GaoBus.Policy do
  @moduledoc """
  Ordered authorization with a single immutable, validated policy generation.

  Every operation starts denied. The last matching rule determines its outcome;
  credentials never imply grants. Compatibility configuration compiles into this
  boundary, and native capabilities cannot broaden its decisions. Readers see a
  complete generation or an unavailable policy, never a partially loaded table.
  """
  use GenServer

  alias GaoBus.Config
  alias GaoBus.Config.Capture
  alias GaoBus.Policy.XML

  @table :gao_bus_policy_snapshot
  @reload_supervisor GaoBus.Policy.ReloadSupervisor
  @actions [:connect, :own, :send, :receive, :control, :activate, :monitor]
  @fields [
    :uid,
    :gid,
    :name,
    :destination,
    :sender,
    :interface,
    :member,
    :path,
    :type,
    :requested_reply,
    :control
  ]
  @message_types [:method_call, :method_return, :error, :signal]
  @counter_indices @actions |> Enum.with_index(1) |> Map.new()

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def compile(nil), do: {:error, :missing_policy}

  def compile(%Config{policies: policies, daemon_uid: uid, accounts: accounts} = config) do
    with {:ok, accounts} <- Config.Accounts.load(accounts: accounts),
         {:ok, policy} <-
           XML.compile(policies, daemon_uid: uid, memberships: accounts.memberships) do
      configuration =
        config
        |> Map.take([:settings, :limits, :daemon_uid, :services, :sources, :directives])
        |> Map.put(:accounts, accounts)
        |> Map.put(:captures, Capture.summary(config.captures || Capture.new()))
        |> Map.update!(:services, &discovery_metadata/1)

      {:ok, %{policy | configuration: configuration}}
    end
  end

  def compile(rules) when is_list(rules) and length(rules) <= 10_000 do
    rules
    |> Enum.with_index(1)
    |> Enum.reduce_while({:ok, []}, fn {rule, index}, {:ok, acc} ->
      case validate_rule(rule) do
        :ok -> {:cont, {:ok, [rule | acc]}}
        {:error, reason} -> {:halt, {:error, {:invalid_rule, index, reason}}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      error -> error
    end
  end

  def compile(_rules), do: {:error, :invalid_policy}

  def snapshot do
    case :ets.lookup(@table, :generation) do
      [{:generation, generation, rules}] -> {:ok, generation, rules}
      [] -> {:error, :policy_unavailable}
    end
  catch
    :error, :badarg -> {:error, :policy_unavailable}
  end

  @doc "Read configuration metadata from the same captured authorization generation."
  def configuration(captured \\ snapshot())

  def configuration({:ok, _generation, %XML{configuration: configuration}})
      when is_map(configuration),
      do: {:ok, configuration}

  def configuration({:ok, _generation, _policy}), do: {:error, :configuration_unavailable}
  def configuration({:error, reason}), do: {:error, reason}
  def configuration(_captured), do: {:error, :invalid_snapshot}

  @doc "Names discovered in one generation; discovery does not establish launchability."
  def activatable_names(captured \\ snapshot()) do
    case configuration(captured) do
      {:ok, %{services: %{selected: selected}}} when is_map(selected) ->
        selected |> Map.keys() |> Enum.sort()

      _ ->
        []
    end
  end

  defp discovery_metadata(inventory) do
    inventory
    |> Map.update!(:occurrences, &Enum.map(&1, fn entry -> discovery_entry_metadata(entry) end))
    |> Map.update!(:selected, fn entries ->
      Map.new(entries, fn {name, entry} -> {name, discovery_entry_metadata(entry)} end)
    end)
  end

  defp discovery_entry_metadata(entry),
    do: Map.update!(entry, :capture, &Map.delete(&1, :bytes))

  def authorize(action, context) when action in @actions and is_map(context) do
    authorize(snapshot(), action, context)
  end

  def authorize(_action, _context), do: {:deny, :invalid_authorization_context}

  @doc "Evaluate related checks against the same immutable policy generation."
  def authorize({:ok, generation, %XML{} = policy}, action, context)
      when action in @actions and is_map(context) do
    decision = XML.authorize(policy, action, context)
    record_decision(action, decision)
    if decision == :allow, do: {:allow, generation}, else: {:deny, :policy_denied}
  end

  def authorize({:ok, generation, rules}, action, context)
      when action in @actions and is_map(context) and is_list(rules) do
    decision =
      Enum.reduce(rules, :deny, fn rule, decision ->
        if rule.action == action and matches?(rule.match, context),
          do: rule.effect,
          else: decision
      end)

    record_decision(action, decision)
    if decision == :allow, do: {:allow, generation}, else: {:deny, :policy_denied}
  end

  def authorize({:error, reason}, action, _context) do
    record_decision(action, :deny)
    {:deny, reason}
  end

  def authorize(_snapshot, _action, _context), do: {:deny, :invalid_authorization_context}

  @doc "Fixed-size aggregate diagnostics; never stores identities, names, or payloads."
  def decision_counts do
    case :ets.lookup(@table, :decision_counters) do
      [{:decision_counters, counters}] ->
        {:ok,
         Map.new(@counter_indices, fn {action, index} ->
           {action,
            %{
              allow: :counters.get(counters, index * 2 - 1),
              deny: :counters.get(counters, index * 2)
            }}
         end)}

      [] ->
        {:error, :policy_unavailable}
    end
  catch
    :error, :badarg -> {:error, :policy_unavailable}
  end

  @doc "Explicit development/session fixture. Never selected implicitly by system startup."
  def session_rules do
    for action <- [:connect, :own, :send, :receive],
        do: %{action: action, effect: :allow, match: %{}}
  end

  def reload(rules) do
    case reload_authority() do
      {:ok, %{publication: :router}} ->
        reload_input({:replace, rules})

      _ ->
        with {:ok, compiled} <- compile(rules) do
          reload_input({:replace, rules, compiled})
        end
    end
  catch
    :exit, _ -> {:error, :policy_unavailable}
  end

  @doc "Reload the trusted startup file; runtime configuration changes require a restart."
  def reload_file do
    reload_input(:file)
  catch
    :exit, _ -> {:error, :policy_unavailable}
  end

  @doc false
  def request_reload_file(router) do
    with {:ok, authority} <- reload_authority(),
         :ok <- reloadable(authority, :file),
         :ok <- router_available(authority, router),
         {:ok, token} <- reserve_reload(authority) do
      GenServer.cast(authority.pid, {:begin_reload, authority.epoch, token, :file, router})
      {:ok, {authority.pid, authority.epoch, token}}
    end
  catch
    :exit, _ -> {:error, :policy_unavailable}
  end

  @doc false
  def commit_reload(policy, epoch, token, generation) when is_pid(policy) do
    GenServer.call(policy, {:commit_reload, epoch, token, generation})
  catch
    :exit, _ -> {:error, :policy_unavailable}
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    rules = Keyword.get(opts, :rules, Application.get_env(:gao_bus, :policy_rules))

    with {:ok, candidate} <- initial_candidate(rules, opts),
         :ok <-
           activation_configuration(
             candidate,
             Keyword.get(opts, :activation_mode),
             Keyword.get(opts, :helper_binding)
           ),
         {:ok, compiled} <- compile(candidate),
         :ok <- reload_options(opts),
         {:ok, supervisor} <- start_reload_supervisor(now_ms() + 5000) do
      epoch = make_ref()
      publication = Keyword.get(opts, :publication, :standalone)
      timeout = Keyword.get(opts, :reload_timeout, 5000)

      reloadable =
        is_binary(Keyword.get(opts, :config_file)) and not is_nil(runtime_signature(candidate))

      :ets.new(@table, [:set, :named_table, :protected, read_concurrency: true])
      :ets.insert(@table, {:decision_counters, :counters.new(14, [:write_concurrency])})
      :ets.insert(@table, {:generation, 1, compiled})
      :ets.insert(@table, {:reload_authority, self(), epoch, publication, timeout, reloadable})

      {:ok,
       %{
         generation: 1,
         config_file: Keyword.get(opts, :config_file),
         config_options: Keyword.get(opts, :config_options, []),
         runtime: runtime_signature(candidate),
         runtime_origins: runtime_origins(candidate),
         activation_mode: Keyword.get(opts, :activation_mode),
         helper_binding: Keyword.get(opts, :helper_binding),
         epoch: epoch,
         publication: publication,
         reload_timeout: timeout,
         reload_supervisor: supervisor,
         reload_supervisor_monitor: Process.monitor(supervisor),
         reload_prepare_barrier: Keyword.get(opts, :reload_prepare_barrier),
         reload_result_barrier: Keyword.get(opts, :reload_result_barrier),
         reload: nil
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(
        {:reserve_reload, epoch},
        _from,
        %{epoch: epoch, publication: :standalone, reload: nil} = state
      ) do
    token = make_ref()
    deadline = now_ms() + state.reload_timeout
    timer = Process.send_after(self(), {:reload_timeout, token}, state.reload_timeout)
    job = reload_job(token, deadline, nil, state.generation)
    {:reply, {:ok, token}, %{state | reload: %{job | timer: timer}}}
  end

  def handle_call({:reserve_reload, _epoch}, _from, state),
    do: {:reply, {:error, :reload_busy}, state}

  def handle_call({:begin_reload, epoch, token, input, router}, from, state) do
    case begin_reload(epoch, token, input, router, from, state) do
      {:ok, state} ->
        {:noreply, state}

      {:error, reason, state} ->
        if is_nil(state.reload) and epoch == state.epoch, do: release_reload(token, state)
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:commit_reload, epoch, token, generation}, {caller, _}, state) do
    case state.reload do
      %{
        token: ^token,
        router: ^caller,
        base_generation: ^generation,
        phase: :prepared,
        compiled: compiled
      }
      when epoch == state.epoch and state.publication == :router ->
        cond do
          not current_router?(caller) ->
            {:reply, {:error, :router_unavailable},
             finish_reload({:error, :router_unavailable}, state)}

          now_ms() >= state.reload.deadline ->
            {:reply, {:error, :reload_timeout}, timeout_reload(state)}

          state.generation != generation ->
            {:reply, {:error, :stale_reload}, finish_reload({:error, :stale_reload}, state)}

          true ->
            {result, state} = publish(compiled, state)
            {:reply, result, finish_reload(result, state)}
        end

      _ ->
        {:reply, {:error, :stale_reload}, state}
    end
  end

  @impl true
  def handle_cast({:begin_reload, epoch, token, input, router}, state) do
    case begin_reload(epoch, token, input, router, nil, state) do
      {:ok, state} ->
        {:noreply, state}

      {:error, reason, state} ->
        if is_nil(state.reload) and epoch == state.epoch and current_router?(router) do
          release_reload(token, state)
          send(router, {:policy_reload_finished, self(), epoch, token, {:error, reason}})
        end

        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:reload_candidate, worker, token, result}, state) do
    case state.reload do
      %{token: ^token, worker: ^worker, phase: :preparing} ->
        state =
          cond do
            now_ms() >= state.reload.deadline ->
              timeout_reload(state)

            match?({:error, _}, result) ->
              finish_reload(result, state)

            state.publication == :standalone ->
              {:ok, compiled} = result
              {result, state} = publish(compiled, state)
              finish_reload(result, state)

            true ->
              {:ok, compiled} = result
              job = %{state.reload | phase: :prepared, compiled: compiled}

              send(
                job.router,
                {:policy_reload_prepared, self(), state.epoch, token, job.base_generation}
              )

              %{state | reload: job}
          end

        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:reload_timeout, token}, %{reload: %{token: token, phase: phase}} = state)
      when phase != :finished,
      do: {:noreply, timeout_reload(state)}

  def handle_info({:reload_timeout, token}, state) do
    if is_nil(state.reload) or state.reload.token != token, do: release_reload(token, state)
    {:noreply, state}
  end

  def handle_info(
        {:DOWN, monitor, :process, supervisor, reason},
        %{reload_supervisor_monitor: monitor, reload_supervisor: supervisor} = state
      ),
      do: {:stop, {:reload_supervisor_failed, reason}, state}

  def handle_info({:DOWN, monitor, :process, worker, reason}, state) do
    case state.reload do
      %{monitor: ^monitor, worker: ^worker} = job ->
        state = %{state | reload: %{job | worker_down: true}}

        state =
          if job.phase == :preparing,
            do: finish_reload({:error, {:reload_worker_failed, reason}}, state),
            else: drain_reload(state)

        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    try do
      Supervisor.stop(state.reload_supervisor)
    catch
      :exit, _ -> :ok
    end
  end

  defp start_reload_supervisor(deadline) do
    case Task.Supervisor.start_link(name: @reload_supervisor, max_children: 1) do
      {:error, {:already_started, supervisor}} = error ->
        monitor = Process.monitor(supervisor)

        receive do
          {:DOWN, ^monitor, :process, ^supervisor, _reason} ->
            if now_ms() < deadline, do: start_reload_supervisor(deadline), else: error
        after
          max(deadline - now_ms(), 0) ->
            Process.demonitor(monitor, [:flush])
            error
        end

      result ->
        result
    end
  end

  defp reload_input(input) do
    with {:ok, authority} <- reload_authority(),
         :ok <- reloadable(authority, input),
         {:ok, router} <- publication_router(authority),
         {:ok, token} <- reserve_reload(authority) do
      GenServer.call(
        authority.pid,
        {:begin_reload, authority.epoch, token, input, router},
        :infinity
      )
    end
  end

  defp reload_authority do
    case :ets.lookup(@table, :reload_authority) do
      [{:reload_authority, pid, epoch, publication, timeout, reloadable}] ->
        {:ok,
         %{
           pid: pid,
           epoch: epoch,
           publication: publication,
           timeout: timeout,
           reloadable: reloadable
         }}

      [] ->
        {:error, :policy_unavailable}
    end
  catch
    :error, :badarg -> {:error, :policy_unavailable}
  end

  defp reloadable(%{reloadable: false}, :file), do: {:error, :file_reload_unavailable}
  defp reloadable(_authority, _input), do: :ok

  defp publication_router(%{publication: :standalone}), do: {:ok, nil}

  defp publication_router(authority) do
    router = Process.whereis(GaoBus.Router)
    with :ok <- router_available(authority, router), do: {:ok, router}
  end

  defp router_available(%{publication: :router}, router) do
    if current_router?(router), do: :ok, else: {:error, :router_unavailable}
  end

  defp router_available(_authority, _router), do: {:error, :router_unavailable}

  defp current_router?(router), do: is_pid(router) and Process.whereis(GaoBus.Router) == router

  defp reserve_reload(%{publication: :router} = authority),
    do: GaoBus.Limits.reserve_reload(authority.pid, authority.timeout)

  defp reserve_reload(authority),
    do: GenServer.call(authority.pid, {:reserve_reload, authority.epoch})

  defp begin_reload(epoch, token, input, router, from, state) do
    cond do
      epoch != state.epoch ->
        {:error, :stale_reload, state}

      state.reload != nil ->
        if state.publication == :standalone and state.reload.token == token and
             state.reload.phase == :reserved and is_nil(router),
           do: start_reload(input, from, state),
           else: {:error, :reload_busy, state}

      state.publication == :router and current_router?(router) ->
        case GaoBus.Limits.claim_reload(token, self()) do
          {:ok, deadline} ->
            job = reload_job(token, deadline, router, state.generation)
            start_reload(input, from, %{state | reload: job})

          {:error, reason} ->
            {:error, reason, state}
        end

      true ->
        {:error, :stale_reload, state}
    end
  end

  defp reload_job(token, deadline, router, generation) do
    %{
      token: token,
      deadline: deadline,
      router: router,
      base_generation: generation,
      phase: :reserved,
      compiled: nil,
      from: nil,
      worker: nil,
      monitor: nil,
      worker_down: true,
      timer: nil,
      result: nil,
      notified: false
    }
  end

  defp start_reload(input, from, state) do
    if now_ms() >= state.reload.deadline do
      state = %{state | reload: %{state.reload | from: from}}
      {:ok, timeout_reload(state)}
    else
      owner = self()
      token = state.reload.token

      task =
        Task.Supervisor.async_nolink(state.reload_supervisor, fn ->
          result = prepare_reload(input, state)
          reload_barrier(state.reload_prepare_barrier, :reload_prepared_barrier)
          send(owner, {:reload_candidate, self(), token, result})
          reload_barrier(state.reload_result_barrier, :reload_result_barrier)
          :ok
        end)

      job = %{
        state.reload
        | phase: :preparing,
          from: from,
          worker: task.pid,
          monitor: task.ref,
          worker_down: false
      }

      {:ok, %{state | reload: job}}
    end
  end

  defp prepare_reload(:file, state) do
    with {:ok, config} <- Config.load(state.config_file, state.config_options),
         :ok <- runtime_compatible(state.runtime, state.runtime_origins, config),
         :ok <- activation_configuration(config, state.activation_mode, state.helper_binding),
         {:ok, compiled} <- compile(config),
         do: {:ok, compiled}
  end

  defp prepare_reload({:replace, rules}, state) do
    with :ok <- activation_configuration(rules, state.activation_mode, state.helper_binding) do
      if not is_nil(state.runtime) do
        case rules do
          %Config{} ->
            with :ok <- runtime_compatible(state.runtime, state.runtime_origins, rules),
                 {:ok, compiled} <- compile(rules),
                 do: {:ok, compiled}

          _ ->
            {:error, :configuration_requires_restart}
        end
      else
        compile(rules)
      end
    end
  end

  defp prepare_reload({:replace, rules, compiled}, %{publication: :standalone} = state) do
    with :ok <- activation_configuration(rules, state.activation_mode, state.helper_binding),
         do: {:ok, compiled}
  end

  defp activation_configuration(_rules, nil, _binding), do: :ok

  defp activation_configuration(%Config{} = config, mode, binding),
    do: Config.Runtime.validate_activation(config, mode, binding)

  defp activation_configuration(_rules, _mode, _binding),
    do: {:error, :configuration_requires_restart}

  defp reload_barrier(nil, _message), do: :ok

  defp reload_barrier({owner, tag}, message) do
    send(owner, {message, tag, self()})
    receive do: ({:release_reload, ^tag} -> :ok)
  end

  defp publish(compiled, state) do
    generation = state.generation + 1
    :ets.insert(@table, {:generation, generation, compiled})
    {{:ok, generation}, %{state | generation: generation}}
  end

  defp finish_reload(result, state) do
    if state.reload.timer, do: Process.cancel_timer(state.reload.timer)
    job = %{state.reload | phase: :finished, compiled: nil, result: result, timer: nil}
    drain_reload(%{state | reload: job})
  end

  defp timeout_reload(state) do
    if is_pid(state.reload.worker) and not state.reload.worker_down,
      do: Process.exit(state.reload.worker, :kill)

    state = finish_reload({:error, :reload_timeout}, state)
    if state.reload, do: %{state | reload: notify_reload(state.reload, state.epoch)}, else: state
  end

  defp drain_reload(%{reload: %{phase: :finished, worker_down: true} = job} = state) do
    if job.worker do
      case Task.Supervisor.terminate_child(state.reload_supervisor, job.worker) do
        :ok -> :ok
        {:error, :not_found} -> :ok
      end
    end

    release_reload(job.token, state)
    notify_reload(job, state.epoch)
    %{state | reload: nil}
  end

  defp drain_reload(state), do: state

  defp notify_reload(%{notified: true} = job, _epoch), do: job

  defp notify_reload(job, epoch) do
    if job.from, do: GenServer.reply(job.from, job.result)

    if job.router,
      do: send(job.router, {:policy_reload_finished, self(), epoch, job.token, job.result})

    %{job | notified: true}
  end

  defp release_reload(token, %{publication: :router}) do
    case GaoBus.Limits.release_reload(token) do
      :ok -> :ok
      {:error, reason} -> exit({:reload_accounting_failed, reason})
    end
  end

  defp release_reload(_token, _state), do: :ok

  defp reload_options(opts) do
    publication = Keyword.get(opts, :publication, :standalone)
    timeout = Keyword.get(opts, :reload_timeout, 5000)

    if publication in [:standalone, :router] and is_integer(timeout) and timeout in 1..60_000,
      do: :ok,
      else: {:error, :invalid_reload_options}
  end

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp runtime_signature(%Config{} = config),
    do: {config.daemon_uid, config.settings, config.limits}

  defp runtime_signature(_rules), do: nil

  defp runtime_origins(%Config{} = config) do
    remaining =
      for {kind, names} <- [setting: Map.keys(config.settings), limit: Map.keys(config.limits)],
          name <- names,
          into: %{} do
        {{kind, name}, Enum.reverse(Config.directive_origins(config, kind, name))}
      end

    {_remaining, origins} =
      Enum.reduce(Enum.reverse(config.directives), {remaining, []}, fn directive,
                                                                       {remaining, origins} ->
        key = {directive.kind, directive.name}

        case Map.get(remaining, key) do
          [origin | rest] when origin == directive.provenance ->
            {Map.put(remaining, key, rest),
             [Map.take(directive, [:kind, :name, :provenance]) | origins]}

          _ ->
            {remaining, origins}
        end
      end)

    origins
  end

  defp runtime_origins(_rules), do: []

  defp runtime_compatible(previous, previous_origins, %Config{} = current) do
    signature = runtime_signature(current)

    if signature == previous do
      :ok
    else
      {previous_uid, previous_settings, previous_limits} = previous
      {current_uid, current_settings, current_limits} = signature

      changed? = fn
        %{kind: :setting, name: name} ->
          Map.fetch(previous_settings, name) != Map.fetch(current_settings, name) or
            (name == :user and previous_uid != current_uid)

        %{kind: :limit, name: name} ->
          Map.fetch(previous_limits, name) != Map.fetch(current_limits, name)
      end

      current_origins = runtime_origins(current)

      removed =
        Enum.filter(previous_origins, fn directive ->
          changed?.(directive) and
            not Enum.any?(current_origins, fn origin ->
              origin.kind == directive.kind and origin.name == directive.name
            end)
        end)

      origins =
        (Enum.filter(current_origins, changed?) ++ removed)
        |> Enum.map(& &1.provenance)

      reason =
        if origins == [],
          do: :configuration_requires_restart,
          else: %{reason: :configuration_requires_restart, origins: origins}

      {:error, reason}
    end
  end

  # Supervisor restarts must not resurrect grants captured before a successful
  # file reload. Invalid current files prevent the authority epoch from starting.
  defp initial_candidate(%Config{} = initial, opts) do
    case Keyword.get(opts, :config_file) do
      path when is_binary(path) ->
        with {:ok, current} <- Config.load(path, Keyword.get(opts, :config_options, [])),
             :ok <-
               runtime_compatible(runtime_signature(initial), runtime_origins(initial), current) do
          {:ok, current}
        end

      nil ->
        {:ok, initial}

      _ ->
        {:error, :invalid_config_file}
    end
  end

  defp initial_candidate(rules, _opts), do: {:ok, rules}

  defp record_decision(action, effect) when action in @actions do
    case :ets.lookup(@table, :decision_counters) do
      [{:decision_counters, counters}] ->
        index = Map.fetch!(@counter_indices, action) * 2 - if(effect == :allow, do: 1, else: 0)
        :counters.add(counters, index, 1)

      [] ->
        :ok
    end
  catch
    # Diagnostics may disappear during a core reset; this never changes the
    # authorization result. No event is queued in a subscriber mailbox.
    :error, :badarg -> :ok
  end

  defp record_decision(_action, _effect), do: :ok

  defp validate_rule(%{action: action, effect: effect, match: fields} = rule) do
    cond do
      Map.keys(rule) -- [:action, :effect, :match] != [] -> {:error, :unknown_rule_field}
      action not in @actions -> {:error, :unknown_action}
      effect not in [:allow, :deny] -> {:error, :invalid_effect}
      not is_map(fields) -> {:error, :invalid_match}
      Map.keys(fields) -- @fields != [] -> {:error, :unknown_field}
      not Enum.all?(fields, &valid_match?/1) -> {:error, :invalid_match_value}
      true -> :ok
    end
  end

  defp validate_rule(_rule), do: {:error, :invalid_rule_shape}

  defp valid_match?({_field, :any}), do: true

  defp valid_match?({field, value}) when field in [:uid, :gid],
    do: is_integer(value) and value >= 0 and value < 0xFFFFFFFF

  defp valid_match?({:type, value}), do: value in @message_types
  defp valid_match?({:requested_reply, value}), do: is_boolean(value)

  defp valid_match?({:control, value}),
    do: value in [:reload, :activation_environment, :start_service, :monitor]

  defp valid_match?({_field, {:prefix, value}}), do: valid_text?(value)
  defp valid_match?({_field, value}), do: valid_text?(value)

  defp valid_text?(value),
    do:
      is_binary(value) and byte_size(value) in 1..255 and String.valid?(value) and
        not String.contains?(value, <<0>>)

  defp matches?(fields, context) do
    Enum.all?(fields, fn {field, expected} -> matches_value?(value(field, context), expected) end)
  end

  defp value(field, context) when field in [:uid, :gid],
    do: context |> Map.get(:credentials, %{}) |> Map.get(field)

  defp value(:destination, context), do: Map.get(context, :destination_names, [])
  defp value(:sender, context), do: Map.get(context, :sender_names, [])

  defp value(field, context) when field in [:type, :interface, :member, :path],
    do: context |> Map.get(:message, %{}) |> Map.get(field)

  defp value(field, context), do: Map.get(context, field)

  # Missing identity/metadata cannot satisfy a wildcard grant.
  defp matches_value?(nil, _expected), do: false

  defp matches_value?(value, expected) when is_list(value),
    do: Enum.any?(value, &matches_value?(&1, expected))

  defp matches_value?(_value, :any), do: true

  defp matches_value?(value, {:prefix, prefix}) when is_binary(value),
    do: value == prefix or String.starts_with?(value, prefix <> ".")

  defp matches_value?(value, expected), do: value == expected
end
