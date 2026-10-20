defmodule GaoBus.Config.XML do
  @moduledoc false

  @max_bytes 1_048_576
  @max_depth 32
  @max_nodes 100_000
  @doctype ~r/\A<!DOCTYPE\s+busconfig\s+(?:SYSTEM\s+(?<system>["'])busconfig\.dtd\k<system>|PUBLIC\s+(?<public>["'])-\/\/freedesktop\/\/DTD (?:D-Bus|D-BUS) Bus Configuration 1\.0\/\/EN\k<public>\s+(?<uri>["'])https?:\/\/www\.freedesktop\.org\/standards\/dbus\/1\.0\/busconfig\.dtd\k<uri>)\s*>\z/s

  # SAX uses strings for names. The tree is bounded and never interns XML names.
  def parse(bytes, file) when is_binary(bytes) and is_binary(file) do
    cond do
      byte_size(bytes) > @max_bytes -> error(file, 1, "busconfig", :xml_too_large)
      not String.valid?(bytes) -> error(file, 1, "busconfig", :invalid_encoding)
      true -> normalize_doctype(bytes, file)
    end
  end

  defp normalize_doctype(bytes, file) do
    # Mask XML literals for discovery only; SAX still validates their syntax.
    masked = Regex.replace(~r/<!--.*?-->|<\?.*?\?>|<!\[CDATA\[.*?\]\]>/s, bytes, &blank/1)

    case Regex.scan(~r/<!DOCTYPE\b/, masked, return: :index) do
      [] ->
        sax(bytes, file)

      [[{offset, _}]] ->
        rest = binary_part(bytes, offset, byte_size(bytes) - offset)

        case :binary.match(rest, ">") do
          {length, 1} ->
            declaration = binary_part(rest, 0, length + 1)

            prefix = binary_part(masked, 0, offset)

            if Regex.match?(~r/\A(?:\xEF\xBB\xBF)?[ \t\r\n]*\z/, prefix) and
                 Regex.match?(@doctype, declaration) do
              normalized =
                binary_part(bytes, 0, offset) <>
                  blank(declaration) <>
                  binary_part(rest, length + 1, byte_size(rest) - length - 1)

              sax(normalized, file)
            else
              error(file, line_at(bytes, offset), "DOCTYPE", :unsupported_doctype)
            end

          :nomatch ->
            error(file, line_at(bytes, offset), "DOCTYPE", :unsupported_doctype)
        end

      _ ->
        error(file, 1, "DOCTYPE", :unsupported_doctype)
    end
  end

  defp sax(bytes, file) do
    state = %{file: file, stack: [], root: nil, nodes: 0}

    options = [
      event_fun: &event/3,
      event_state: state,
      external_entities: :none,
      fail_undeclared_ref: true,
      entity_recurse_limit: 0
    ]

    case :xmerl_sax_parser.stream(bytes, [:disallow_entities | options]) do
      {:ok, %{root: root, stack: []}, rest} when is_map(root) ->
        if String.trim(to_string(rest)) == "",
          do: {:ok, root},
          else: error(file, 1, "busconfig", {:invalid_xml, :trailing_input})

      {:config_error, _location, reason, _tags, _state} when is_map(reason) ->
        {:error, reason}

      {_kind, {_directory, _entity, line}, reason, _tags, _state} ->
        error(file, line, "busconfig", {:invalid_xml, to_string(reason)})

      other ->
        error(file, 1, "busconfig", {:invalid_xml, inspect(other)})
    end
  end

  defp event({:startElement, uri, name, {_prefix, _local}, attributes}, {_, _, line}, state) do
    name = to_string(name)
    if uri != [], do: reject(state, line, name, :unsupported_namespace)
    if length(state.stack) >= @max_depth, do: reject(state, line, name, :xml_depth_exceeded)
    if state.nodes >= @max_nodes, do: reject(state, line, name, :xml_nodes_exceeded)

    attributes =
      Enum.reduce(attributes, %{}, fn {uri, prefix, key, value}, acc ->
        key = to_string(key)
        if uri != [] or prefix != [], do: reject(state, line, name, :unsupported_namespace)
        if Map.has_key?(acc, key), do: reject(state, line, name, :duplicate_attribute)
        Map.put(acc, key, to_string(value))
      end)

    node = %{name: name, attributes: attributes, line: line, text: [], children: []}
    %{state | stack: [node | state.stack], nodes: state.nodes + 1}
  end

  defp event({:endElement, _, _, _}, _, %{stack: [node | rest]} = state) do
    node = %{
      node
      | text: node.text |> Enum.reverse() |> IO.iodata_to_binary(),
        children: Enum.reverse(node.children)
    }

    case rest do
      [] -> %{state | stack: [], root: node}
      [parent | tail] -> %{state | stack: [%{parent | children: [node | parent.children]} | tail]}
    end
  end

  defp event({kind, characters}, _, %{stack: [node | rest]} = state)
       when kind in [:characters, :ignorableWhitespace] do
    %{state | stack: [%{node | text: [to_string(characters) | node.text]} | rest]}
  end

  defp event({:startPrefixMapping, _, _}, {_, _, line}, state),
    do: reject(state, line, "busconfig", :unsupported_namespace)

  defp event({:startDTD, _, _, _}, {_, _, line}, state),
    do: reject(state, line, "DOCTYPE", :unsupported_doctype)

  defp event(_event, _location, state), do: state

  defp blank(text), do: Regex.replace(~r/[^\r\n]/, text, " ")

  defp line_at(bytes, offset),
    do: length(:binary.split(binary_part(bytes, 0, offset), "\n", [:global]))

  defp reject(state, line, element, reason),
    do: throw({:config_error, %{file: state.file, line: line, element: element, reason: reason}})

  defp error(file, line, element, reason),
    do: {:error, %{file: file, line: line, element: element, reason: reason}}
end
