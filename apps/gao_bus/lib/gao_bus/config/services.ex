defmodule GaoBus.Config.Services do
  @moduledoc """
  Bounded system-service metadata discovery using one captured input generation.

  Desktop strings and argv follow the pinned D-Bus 1.14 parser, including its
  first-section/key, locale, comment and final-empty-argument behavior. Canonical
  filenames and eager complete account binding are supported-profile restrictions.
  Parsing and discovery never execute a command or probe a systemd target.
  """

  alias GaoBus.Config.{Accounts, Capture}

  @max_bytes 131_072
  @max_string 4096
  @max_lines 4096
  @max_sections 64
  @max_declarations 64
  @max_directories 64
  @max_entries 8192
  @max_files 1024
  @max_words 256
  @origin_keys [:file, :line, :element, :occurrence, :include_chain]
  @fields %{
    "Name" => :name,
    "Exec" => :exec,
    "User" => :user,
    "SystemdService" => :systemd_service
  }

  def parse(bytes, path, origin, accounts) do
    try do
      context = Map.put(origin, :file, path)
      base = at(context, 1, "D-BUS Service")

      cond do
        not is_binary(bytes) -> reject(base, context, :invalid_service_bytes)
        byte_size(bytes) > @max_bytes -> reject(base, context, :service_file_too_large)
        not String.valid?(bytes) -> reject(base, context, :invalid_service_encoding)
        :binary.match(bytes, <<0>>) != :nomatch -> reject(base, context, :invalid_service_nul)
        true -> :ok
      end

      state =
        scan(
          bytes,
          1,
          %{sections: [], declarations: [], current: nil, group: nil, fields: %{}},
          context
        )

      group = state.group || reject(base, context, :missing_service_group)
      name = required(state.fields, :name, group, context)
      exec = required(state.fields, :exec, group, context)
      user = required(state.fields, :user, group, context)

      unless GaoBus.NameRegistry.requestable_name?(name.value),
        do: reject(name.provenance, context, :invalid_service_name)

      unless byte_size(name.value) <= 247 and Path.basename(path) == name.value <> ".service",
        do: reject(name.provenance, context, :noncanonical_service_filename)

      if user.value == "", do: reject(user.provenance, context, :missing_service_user)

      account =
        case Accounts.bind_user(accounts, user.value) do
          {:ok, account} -> account
          {:error, reason} -> reject(user.provenance, context, reason)
        end

      systemd = Map.get(state.fields, :systemd_service)

      if systemd && systemd.value == "",
        do: reject(systemd.provenance, context, :empty_systemd_service)

      argv = argv(exec.value, exec.provenance, context)
      unless valid_origin?(group), do: reject(base, context, :invalid_provenance)

      unless Enum.all?(state.declarations, &valid_origin?(&1.provenance)),
        do: reject(base, context, :invalid_provenance)

      {:ok,
       %{
         name: name.value,
         exec: exec.value,
         argv: argv,
         user: user.value,
         account: account,
         systemd_service: if(systemd, do: systemd.value, else: nil),
         provenance: clean_origin(group),
         field_origins:
           Map.new(state.fields, fn {key, field} -> {key, clean_origin(field.provenance)} end),
         sections:
           Enum.map(
             Enum.reverse(state.sections),
             &Map.update!(&1, :provenance, fn origin -> clean_origin(origin) end)
           ),
         declarations:
           Enum.map(
             Enum.reverse(state.declarations),
             &Map.update!(&1, :provenance, fn origin -> clean_origin(origin) end)
           )
       }}
    catch
      {:service_error, error} -> {:error, error}
    end
  end

  def discover(config, capture) do
    try do
      paths = Map.get(config.settings, :servicedir, [])

      declarations =
        Enum.filter(config.directives, &(&1.kind == :setting and &1.name == :servicedir))

      state = %{
        directories: [],
        occurrences: [],
        selected: %{},
        entries: 0,
        files: 0,
        capture: capture
      }

      state =
        paths
        |> Stream.with_index(1)
        |> Enum.reduce(state, fn {path, index}, state ->
          origin = directory_origin(declarations, path, index)
          context = %{directory_index: index, directory_origin: origin}
          if index > @max_directories, do: reject(origin, context, :service_directories_exceeded)
          discover_directory(path, index, origin, state, config.accounts)
        end)

      {:ok,
       %{
         directories: Enum.reverse(state.directories),
         occurrences: Enum.reverse(state.occurrences),
         selected: state.selected
       }, state.capture}
    catch
      {:service_error, error} -> {:error, error}
    end
  end

  defp discover_directory(path, index, origin, state, accounts) do
    context = %{directory_index: index, directory_origin: origin}

    case Capture.list(state.capture, path) do
      {:ok, listing, capture} ->
        entries = state.entries + length(listing.names)
        if entries > @max_entries, do: reject(origin, context, :service_entries_exceeded)

        directory = %{
          path: listing.path,
          index: index,
          origin: origin,
          status: :present,
          capture: listing
        }

        state = %{
          state
          | directories: [directory | state.directories],
            entries: entries,
            capture: capture
        }

        listing.names
        |> Enum.filter(&String.ends_with?(&1, ".service"))
        |> Enum.reduce({state, %{}}, fn name, {state, local} ->
          path = Path.join(listing.path, name)
          files = state.files + 1

          source = %{
            file: path,
            line: 1,
            element: "D-BUS Service",
            occurrence: files,
            include_chain: Map.get(origin, :include_chain, []),
            directory_index: index,
            directory_origin: origin
          }

          if files > @max_files,
            do: reject(at(source, 1, "D-BUS Service"), source, :service_files_exceeded)

          {record, capture} =
            case Capture.read(state.capture, path, @max_bytes) do
              {:ok, record, capture} -> {record, capture}
              {:error, error, _capture} -> read_error(error, source)
            end

          entry =
            case parse(record.bytes, path, source, accounts) do
              {:ok, entry} -> entry
              {:error, error} -> throw({:service_error, error})
            end

          if Map.has_key?(local, entry.name) do
            error = Map.put(source, :previous_origin, local[entry.name])
            reject(entry.field_origins.name, error, :conflicting_service_definition)
          end

          disposition =
            if Map.has_key?(state.selected, entry.name), do: :shadowed, else: :effective

          occurrence =
            Map.merge(entry, %{
              path: path,
              directory_index: index,
              directory_origin: origin,
              disposition: disposition,
              capture: record
            })

          selected = Map.put_new(state.selected, entry.name, occurrence)

          {%{
             state
             | files: files,
               capture: capture,
               selected: selected,
               occurrences: [occurrence | state.occurrences]
           }, Map.put(local, entry.name, entry.provenance)}
        end)
        |> elem(0)

      {:error, %{reason: :enoent} = error, capture} ->
        directory = %{
          path: Map.get(error, :path, path),
          index: index,
          origin: origin,
          status: :missing,
          capture: error
        }

        %{state | directories: [directory | state.directories], capture: capture}

      {:error, error, _capture} ->
        read_error(error, Map.merge(origin, context))
    end
  end

  defp directory_origin(declarations, path, index) do
    case Enum.at(declarations, index - 1) do
      %{value: ^path, provenance: origin} -> origin
      _ -> %{file: path, line: 1, element: "servicedir", occurrence: 1, include_chain: []}
    end
  end

  defp read_error(error, context) do
    source =
      Map.merge(
        at(context, 1, "D-BUS Service"),
        Map.take(error, [:path, :operation, :native_reason])
      )

    source =
      if is_binary(Map.get(error, :path)), do: Map.put(source, :file, error.path), else: source

    reject(Map.put(source, :line, nil), context, error.reason)
  end

  defp scan("", _line, state, _context), do: state

  defp scan(bytes, line, state, context) do
    origin = at(context, line, "D-BUS Service")
    if line > @max_lines, do: reject(origin, context, :service_lines_exceeded)
    {text, rest} = physical_line(bytes)
    if byte_size(text) > @max_string, do: reject(origin, context, :service_line_too_long)

    state =
      cond do
        Regex.match?(~r/\A[ \t\r\f]*\z/, text) -> state
        String.starts_with?(text, "#") -> state
        String.starts_with?(text, "[") -> section(text, line, state, context)
        true -> declaration(text, line, state, context)
      end

    scan(rest, line + 1, state, context)
  end

  defp physical_line(bytes) do
    case :binary.match(bytes, "\n") do
      {offset, 1} ->
        <<line::binary-size(offset), _newline, rest::binary>> = bytes

        line =
          if String.ends_with?(line, "\r"),
            do: binary_part(line, 0, byte_size(line) - 1),
            else: line

        {line, rest}

      :nomatch ->
        {bytes, ""}
    end
  end

  defp section(text, line, state, context) do
    origin = at(context, line, "section")

    name =
      case Regex.run(~r/\A\[([\x20-\x5A\x5C\x5E-\x7E]+)\]\z/, text) do
        [_, name] -> name
        _ -> reject(origin, context, :invalid_service_section)
      end

    if length(state.sections) >= @max_sections,
      do: reject(origin, context, :service_sections_exceeded)

    origin = at(context, line, name)
    effective = name == "D-BUS Service" and state.group == nil

    %{
      state
      | sections: [%{name: name, provenance: origin} | state.sections],
        current: %{name: name, effective: effective},
        group: if(effective, do: origin, else: state.group)
    }
  end

  defp declaration(text, line, state, context) do
    origin = at(context, line, "key")

    {key, rest} =
      case Regex.run(~r/\A([A-Za-z0-9-]+)(.*)\z/s, text) do
        [_, key, rest] -> {key, rest}
        _ -> reject(origin, context, :invalid_service_key)
      end

    origin = at(context, line, key)
    if byte_size(key) > @max_string, do: reject(origin, context, :service_key_too_long)

    if length(state.declarations) >= @max_declarations,
      do: reject(origin, context, :service_declarations_exceeded)

    {kind, value} =
      if String.starts_with?(rest, "[") do
        {:locale, nil}
      else
        if state.current == nil, do: reject(origin, context, :service_key_without_section)

        case Regex.run(~r/\A *= *(.*)\z/s, rest) do
          [_, raw] -> {:key, unescape(raw, origin, context, [])}
          _ -> reject(origin, context, :invalid_service_key)
        end
      end

    declaration = %{
      key: key,
      value: value,
      kind: kind,
      section: state.current && state.current.name,
      provenance: origin
    }

    if kind == :key and state.current.effective and key == "AssumedAppArmorLabel",
      do: reject(origin, context, :unsupported_security_field)

    field = Map.get(@fields, key)

    fields =
      if kind == :key and state.current.effective and field do
        Map.put_new(state.fields, field, %{value: value, provenance: origin})
      else
        state.fields
      end

    %{state | declarations: [declaration | state.declarations], fields: fields}
  end

  defp unescape("", _origin, _context, value),
    do: value |> Enum.reverse() |> IO.iodata_to_binary()

  defp unescape(<<92, byte, rest::binary>>, origin, context, value) do
    decoded =
      case byte do
        ?s -> ?\s
        ?t -> ?\t
        ?n -> ?\n
        ?r -> ?\r
        92 -> 92
        _ -> reject(origin, context, :invalid_service_escape)
      end

    unescape(rest, origin, context, [decoded | value])
  end

  defp unescape(<<92>>, origin, context, _value),
    do: reject(origin, context, :invalid_service_escape)

  defp unescape(<<byte, rest::binary>>, origin, context, value),
    do: unescape(rest, origin, context, [byte | value])

  defp required(fields, key, group, context) do
    case Map.fetch(fields, key) do
      {:ok, field} -> field
      :error -> reject(group, context, {:missing_service_field, key})
    end
  end

  # Keep the two reference stages separate: tokenize retains quote/escape bytes;
  # unquote removes them. Newline always delimits, space only a nonempty token.
  defp argv(exec, origin, context) do
    tokens = tokenize(exec, nil, false, [], [], origin, context)
    argv = Enum.map(tokens, &unquote_token(&1, nil, [], origin, context))

    if Enum.reduce(argv, 0, &(byte_size(&1) + &2)) > @max_string,
      do: reject(origin, context, :service_argv_bytes_exceeded)

    argv
  end

  defp tokenize("", nil, _quoted, token, tokens, origin, context),
    do: Enum.reverse(delimit(token, tokens, origin, context))

  defp tokenize("", _quote, _quoted, _token, _tokens, origin, context),
    do: reject(origin, context, :invalid_service_exec_quotes)

  defp tokenize(<<byte, rest::binary>>, 92, _quoted, token, tokens, origin, context) do
    token = if byte == ?\n, do: token, else: [byte, 92 | token]
    tokenize(rest, nil, false, token, tokens, origin, context)
  end

  defp tokenize(bytes, ?#, _quoted, token, tokens, origin, context) do
    rest =
      case :binary.match(bytes, "\n") do
        {offset, 1} -> binary_part(bytes, offset + 1, byte_size(bytes) - offset - 1)
        :nomatch -> ""
      end

    tokenize(rest, nil, false, token, tokens, origin, context)
  end

  defp tokenize(<<byte, rest::binary>>, quote, quoted, token, tokens, origin, context)
       when quote in [?', ?"] do
    next = if byte == quote and not (quote == ?" and quoted), do: nil, else: quote
    tokenize(rest, next, byte == 92 and not quoted, [byte | token], tokens, origin, context)
  end

  defp tokenize(<<byte, rest::binary>>, nil, _quoted, token, tokens, origin, context) do
    cond do
      byte == ?\n or (byte in [?\s, ?\t] and token != []) ->
        tokenize(rest, nil, false, [], delimit(token, tokens, origin, context), origin, context)

      byte in [?\s, ?\t] ->
        tokenize(rest, nil, false, token, tokens, origin, context)

      byte in [?', ?"] ->
        tokenize(rest, byte, false, [byte | token], tokens, origin, context)

      byte in [?#, 92] ->
        tokenize(rest, byte, byte == 92, token, tokens, origin, context)

      true ->
        tokenize(rest, nil, false, [byte | token], tokens, origin, context)
    end
  end

  defp delimit(token, tokens, origin, context) do
    if length(tokens) >= @max_words, do: reject(origin, context, :service_argv_words_exceeded)
    [token |> Enum.reverse() |> IO.iodata_to_binary() | tokens]
  end

  defp unquote_token("", nil, value, _origin, _context),
    do: value |> Enum.reverse() |> IO.iodata_to_binary()

  defp unquote_token("", _quote, _value, origin, context),
    do: reject(origin, context, :invalid_service_exec_quotes)

  defp unquote_token(<<byte, rest::binary>>, quote, value, origin, context) when byte == quote,
    do: unquote_token(rest, nil, value, origin, context)

  defp unquote_token(<<byte, rest::binary>>, nil, value, origin, context) when byte in [?', ?"],
    do: unquote_token(rest, byte, value, origin, context)

  defp unquote_token(<<92, byte, rest::binary>>, nil, value, origin, context),
    do: unquote_token(rest, nil, [byte | value], origin, context)

  defp unquote_token(<<92, byte, rest::binary>>, ?", value, origin, context)
       when byte in [?", 92, ?`, ?$, ?\n],
       do: unquote_token(rest, ?", [byte | value], origin, context)

  defp unquote_token(<<byte, rest::binary>>, quote, value, origin, context),
    do: unquote_token(rest, quote, [byte | value], origin, context)

  defp at(context, line, element) do
    %{
      file: Map.get(context, :file),
      line: line,
      element: if(byte_size(element) <= 255, do: element, else: "key"),
      occurrence: Map.get(context, :occurrence, 1),
      include_chain: Map.get(context, :include_chain, [])
    }
  end

  defp valid_origin?(%{
         file: file,
         line: line,
         element: element,
         occurrence: occurrence,
         include_chain: chain
       }) do
    bounded_string?(file, 4096) and is_integer(line) and line in 1..1_048_577 and
      bounded_string?(element, 255) and is_integer(occurrence) and occurrence in 1..1024 and
      is_list(chain) and length(chain) <= 32 and Enum.all?(chain, &valid_include_origin?/1)
  end

  defp valid_origin?(_), do: false

  defp valid_include_origin?(
         %{file: file, line: line, element: element, occurrence: occurrence} = origin
       ) do
    bounded_string?(file, 4096) and is_integer(line) and line in 1..1_048_577 and
      bounded_string?(element, 255) and is_integer(occurrence) and occurrence in 1..1024 and
      not Map.has_key?(origin, :include_chain)
  end

  defp valid_include_origin?(_), do: false

  defp bounded_string?(value, maximum),
    do:
      is_binary(value) and byte_size(value) in 1..maximum and String.valid?(value) and
        :binary.match(value, <<0>>) == :nomatch

  defp clean_origin(origin),
    do:
      origin
      |> Map.take(@origin_keys)
      |> Map.update!(:include_chain, fn chain ->
        Enum.map(chain, &Map.take(&1, [:file, :line, :element, :occurrence]))
      end)

  defp reject(origin, context, reason) do
    error =
      origin
      |> Map.take(@origin_keys ++ [:path, :operation, :native_reason])
      |> Map.merge(Map.take(context, [:directory_index, :directory_origin, :previous_origin]))
      |> Map.put(:reason, reason)

    throw({:service_error, error})
  end
end
