defmodule ExDBus.Introspection do
  @moduledoc """
  D-Bus introspection XML generation and parsing.

  Generates standard D-Bus introspection XML from interface definitions,
  and parses introspection XML into structured data.
  """

  @doc """
  An interface definition with methods, signals, and properties.
  """
  @type t :: %__MODULE__{
          name: String.t() | nil,
          methods: [__MODULE__.Method.t()],
          signals: [__MODULE__.Signal.t()],
          properties: [__MODULE__.Property.t()]
        }

  defstruct name: nil, methods: [], signals: [], properties: []

  defmodule Method do
    @moduledoc "D-Bus method definition with name, arguments, and annotations."
    @type t :: %__MODULE__{name: String.t() | nil, args: [ExDBus.Introspection.Arg.t()]}
    defstruct name: nil, args: []
  end

  defmodule Signal do
    @moduledoc "D-Bus signal definition with name and arguments."
    @type t :: %__MODULE__{name: String.t() | nil, args: [ExDBus.Introspection.Arg.t()]}
    defstruct name: nil, args: []
  end

  defmodule Property do
    @moduledoc "D-Bus property definition with name, type, access mode, and annotations."
    @type t :: %__MODULE__{
            name: String.t() | nil,
            type: String.t() | nil,
            access: :read | :write | :readwrite,
            annotations: [{String.t(), String.t()}]
          }
    defstruct name: nil, type: nil, access: :read, annotations: []
  end

  defmodule Arg do
    @moduledoc "D-Bus method/signal argument with name, type, and direction."
    @type t :: %__MODULE__{
            name: String.t() | nil,
            type: String.t() | nil,
            direction: :in | :out | nil
          }
    defstruct name: nil, type: nil, direction: nil
  end

  @doc """
  Generate introspection XML for a node.

  ## Parameters
    - `path` - The object path
    - `interfaces` - List of `%ExDBus.Introspection{}` structs
    - `child_nodes` - List of child node name strings (optional)

  ## Example

      iex> iface = %ExDBus.Introspection{
      ...>   name: "com.example.Foo",
      ...>   methods: [
      ...>     %ExDBus.Introspection.Method{
      ...>       name: "Bar",
      ...>       args: [
      ...>         %ExDBus.Introspection.Arg{name: "input", type: "s", direction: :in},
      ...>         %ExDBus.Introspection.Arg{name: "output", type: "s", direction: :out}
      ...>       ]
      ...>     }
      ...>   ]
      ...> }
      iex> xml = ExDBus.Introspection.to_xml("/com/example", [iface])
      iex> String.contains?(xml, "<interface name=\\"com.example.Foo\\">")
      true
  """
  @spec to_xml(String.t(), [t()], [String.t()]) :: String.t()
  def to_xml(path, interfaces, child_nodes \\ []) do
    [
      ~s(<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"\n),
      ~s( "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">\n),
      ~s(<node name="#{escape_xml(path)}">\n),
      Enum.map(interfaces, &interface_to_xml/1),
      Enum.map(child_nodes, &child_node_to_xml/1),
      "</node>\n"
    ]
    |> IO.iodata_to_binary()
  end

  @doc """
  Parse introspection XML into structured data.

  Returns `{:ok, path, interfaces, child_nodes}` or `{:error, reason}`.
  """
  @spec from_xml(String.t()) :: {:ok, String.t(), [t()], [String.t()]} | {:error, term()}
  def from_xml(xml) when is_binary(xml) do
    parse_node(xml)
  rescue
    e -> {:error, e}
  end

  @doc """
  Standard org.freedesktop.DBus.Introspectable interface definition.
  """
  @spec introspectable_interface() :: t()
  def introspectable_interface do
    %__MODULE__{
      name: "org.freedesktop.DBus.Introspectable",
      methods: [
        %Method{
          name: "Introspect",
          args: [%Arg{name: "xml_data", type: "s", direction: :out}]
        }
      ]
    }
  end

  @doc """
  Standard org.freedesktop.DBus.Properties interface definition.
  """
  @spec properties_interface() :: t()
  def properties_interface do
    %__MODULE__{
      name: "org.freedesktop.DBus.Properties",
      methods: [
        %Method{
          name: "Get",
          args: [
            %Arg{name: "interface_name", type: "s", direction: :in},
            %Arg{name: "property_name", type: "s", direction: :in},
            %Arg{name: "value", type: "v", direction: :out}
          ]
        },
        %Method{
          name: "Set",
          args: [
            %Arg{name: "interface_name", type: "s", direction: :in},
            %Arg{name: "property_name", type: "s", direction: :in},
            %Arg{name: "value", type: "v", direction: :in}
          ]
        },
        %Method{
          name: "GetAll",
          args: [
            %Arg{name: "interface_name", type: "s", direction: :in},
            %Arg{name: "props", type: "a{sv}", direction: :out}
          ]
        }
      ],
      signals: [
        %Signal{
          name: "PropertiesChanged",
          args: [
            %Arg{name: "interface_name", type: "s"},
            %Arg{name: "changed_properties", type: "a{sv}"},
            %Arg{name: "invalidated_properties", type: "as"}
          ]
        }
      ]
    }
  end

  @doc """
  Standard org.freedesktop.DBus.Peer interface definition.
  """
  @spec peer_interface() :: t()
  def peer_interface do
    %__MODULE__{
      name: "org.freedesktop.DBus.Peer",
      methods: [
        %Method{name: "Ping", args: []},
        %Method{
          name: "GetMachineId",
          args: [%Arg{name: "machine_uuid", type: "s", direction: :out}]
        }
      ]
    }
  end

  @doc """
  The org.freedesktop.DBus interface definition for the bus itself.
  """
  @spec bus_interface() :: t()
  def bus_interface do
    %__MODULE__{
      name: "org.freedesktop.DBus",
      methods: [
        %Method{
          name: "Hello",
          args: [%Arg{name: "unique_name", type: "s", direction: :out}]
        },
        %Method{
          name: "RequestName",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "flags", type: "u", direction: :in},
            %Arg{name: "result", type: "u", direction: :out}
          ]
        },
        %Method{
          name: "ReleaseName",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "result", type: "u", direction: :out}
          ]
        },
        %Method{
          name: "GetNameOwner",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "unique_name", type: "s", direction: :out}
          ]
        },
        %Method{
          name: "ListNames",
          args: [%Arg{name: "names", type: "as", direction: :out}]
        },
        %Method{
          name: "ListQueuedOwners",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "owners", type: "as", direction: :out}
          ]
        },
        %Method{
          name: "ListActivatableNames",
          args: [%Arg{name: "names", type: "as", direction: :out}]
        },
        %Method{
          name: "StartServiceByName",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "flags", type: "u", direction: :in},
            %Arg{name: "result", type: "u", direction: :out}
          ]
        },
        %Method{
          name: "UpdateActivationEnvironment",
          args: [%Arg{name: "environment", type: "a{ss}", direction: :in}]
        },
        %Method{
          name: "NameHasOwner",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "result", type: "b", direction: :out}
          ]
        },
        %Method{
          name: "AddMatch",
          args: [%Arg{name: "rule", type: "s", direction: :in}]
        },
        %Method{
          name: "RemoveMatch",
          args: [%Arg{name: "rule", type: "s", direction: :in}]
        },
        %Method{name: "ReloadConfig", args: []},
        %Method{
          name: "GetId",
          args: [%Arg{name: "id", type: "s", direction: :out}]
        },
        %Method{
          name: "GetConnectionUnixUser",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "uid", type: "u", direction: :out}
          ]
        },
        %Method{
          name: "GetConnectionUnixProcessID",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "pid", type: "u", direction: :out}
          ]
        },
        %Method{
          name: "GetConnectionCredentials",
          args: [
            %Arg{name: "name", type: "s", direction: :in},
            %Arg{name: "credentials", type: "a{sv}", direction: :out}
          ]
        }
      ],
      properties: [
        %Property{
          name: "Features",
          type: "as",
          access: :read,
          annotations: [{"org.freedesktop.DBus.Property.EmitsChangedSignal", "const"}]
        },
        %Property{
          name: "Interfaces",
          type: "as",
          access: :read,
          annotations: [{"org.freedesktop.DBus.Property.EmitsChangedSignal", "const"}]
        }
      ],
      signals: [
        %Signal{
          name: "NameOwnerChanged",
          args: [
            %Arg{name: "name", type: "s"},
            %Arg{name: "old_owner", type: "s"},
            %Arg{name: "new_owner", type: "s"}
          ]
        },
        %Signal{
          name: "NameAcquired",
          args: [%Arg{name: "name", type: "s"}]
        },
        %Signal{
          name: "NameLost",
          args: [%Arg{name: "name", type: "s"}]
        }
      ]
    }
  end

  # --- XML generation ---

  defp interface_to_xml(%__MODULE__{} = iface) do
    [
      ~s(  <interface name="#{escape_xml(iface.name)}">\n),
      Enum.map(iface.methods, &method_to_xml/1),
      Enum.map(iface.signals, &signal_to_xml/1),
      Enum.map(iface.properties, &property_to_xml/1),
      "  </interface>\n"
    ]
  end

  defp method_to_xml(%Method{args: []} = m) do
    ~s(    <method name="#{escape_xml(m.name)}"/>\n)
  end

  defp method_to_xml(%Method{} = m) do
    [
      ~s(    <method name="#{escape_xml(m.name)}">\n),
      Enum.map(m.args, &arg_to_xml/1),
      "    </method>\n"
    ]
  end

  defp signal_to_xml(%Signal{args: []} = s) do
    ~s(    <signal name="#{escape_xml(s.name)}"/>\n)
  end

  defp signal_to_xml(%Signal{} = s) do
    [
      ~s(    <signal name="#{escape_xml(s.name)}">\n),
      Enum.map(s.args, &arg_to_xml/1),
      "    </signal>\n"
    ]
  end

  defp property_to_xml(%Property{annotations: []} = p) do
    ~s(    <property name="#{escape_xml(p.name)}" type="#{escape_xml(p.type)}" access="#{p.access}"/>\n)
  end

  defp property_to_xml(%Property{} = p) do
    [
      ~s(    <property name="#{escape_xml(p.name)}" type="#{escape_xml(p.type)}" access="#{p.access}">\n),
      Enum.map(p.annotations, fn {name, value} ->
        ~s(      <annotation name="#{escape_xml(name)}" value="#{escape_xml(value)}"/>\n)
      end),
      "    </property>\n"
    ]
  end

  defp arg_to_xml(%Arg{} = a) do
    name_attr = if a.name, do: ~s( name="#{escape_xml(a.name)}"), else: ""
    dir_attr = if a.direction, do: ~s( direction="#{a.direction}"), else: ""
    ~s(      <arg#{name_attr} type="#{escape_xml(a.type)}"#{dir_attr}/>\n)
  end

  defp child_node_to_xml(name) do
    ~s(  <node name="#{escape_xml(name)}"/>\n)
  end

  defp escape_xml(nil), do: ""

  defp escape_xml(str) when is_binary(str) do
    str
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp escape_xml(atom) when is_atom(atom), do: escape_xml(Atom.to_string(atom))

  # --- XML parsing (simple regex-based, no XML library dependency) ---

  defp parse_node(xml) do
    path = extract_attr(xml, "node", "name") || "/"

    interfaces =
      Regex.scan(~r/<interface name="([^"]+)">(.*?)<\/interface>/s, xml)
      |> Enum.map(fn [_full, name, body] -> parse_interface(name, body) end)

    children =
      Regex.scan(~r/<node name="([^"]+)"\s*\/>/, xml)
      |> Enum.map(fn [_full, name] -> name end)

    {:ok, path, interfaces, children}
  end

  defp parse_interface(name, body) do
    methods = parse_methods(body)
    signals = parse_signals(body)
    properties = parse_properties(body)

    %__MODULE__{
      name: name,
      methods: methods,
      signals: signals,
      properties: properties
    }
  end

  defp parse_methods(body) do
    # Match methods with args
    with_args =
      Regex.scan(~r/<method name="([^"]+)">\s*(.*?)\s*<\/method>/s, body)
      |> Enum.map(fn [_full, name, args_body] ->
        %Method{name: name, args: parse_args(args_body)}
      end)

    # Match self-closing methods
    without_args =
      Regex.scan(~r/<method name="([^"]+)"\/>/s, body)
      |> Enum.map(fn [_full, name] ->
        %Method{name: name, args: []}
      end)

    with_args ++ without_args
  end

  defp parse_signals(body) do
    with_args =
      Regex.scan(~r/<signal name="([^"]+)">\s*(.*?)\s*<\/signal>/s, body)
      |> Enum.map(fn [_full, name, args_body] ->
        %Signal{name: name, args: parse_args(args_body)}
      end)

    without_args =
      Regex.scan(~r/<signal name="([^"]+)"\/>/s, body)
      |> Enum.map(fn [_full, name] ->
        %Signal{name: name, args: []}
      end)

    with_args ++ without_args
  end

  defp parse_properties(body) do
    Regex.scan(
      ~r/<property name="([^"]+)" type="([^"]+)" access="([^"]+)"(?:\/>|>(.*?)<\/property>)/s,
      body
    )
    |> Enum.map(fn [_full, name, type, access | contents] ->
      %Property{
        name: name,
        type: type,
        access:
          case access do
            "read" -> :read
            "write" -> :write
            "readwrite" -> :readwrite
            _ -> :readwrite
          end,
        annotations: Enum.flat_map(contents, &parse_property_annotations/1)
      }
    end)
  end

  defp parse_property_annotations(body) do
    Regex.scan(~r/<annotation name="([^"]+)" value="([^"]*)"\/>/s, body)
    |> Enum.map(fn [_full, name, value] -> {name, value} end)
  end

  defp parse_args(body) do
    # Match <arg .../> (self-closing) and <arg ...>...</arg> (GDBus style)
    Regex.scan(~r/<arg\s[^>]*(?:\/>|>[\s\S]*?<\/arg>)/s, body)
    |> Enum.map(fn [tag] ->
      name = extract_tag_attr(tag, "name")
      type = extract_tag_attr(tag, "type")
      direction = extract_tag_attr(tag, "direction")

      %Arg{
        name: if(name == "" or is_nil(name), do: nil, else: name),
        type: type,
        direction:
          case direction do
            "in" -> :in
            "out" -> :out
            nil -> nil
            _ -> :in
          end
      }
    end)
  end

  defp extract_attr(xml, element, attr) do
    case Regex.run(~r/<#{element}[^>]*\s#{attr}="([^"]+)"/, xml) do
      [_, value] -> value
      nil -> nil
    end
  end

  defp extract_tag_attr(tag, attr) do
    case Regex.run(~r/\s#{attr}="([^"]*)"/, tag) do
      [_, value] -> value
      nil -> nil
    end
  end
end
