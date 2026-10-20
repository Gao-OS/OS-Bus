defmodule GaoBus.Config.XMLTest do
  # The atom-count regression observes a process-wide VM counter.
  use ExUnit.Case, async: false
  alias GaoBus.Config.XML

  test "known SYSTEM and PUBLIC doctypes need no external DTD" do
    for doctype <- [
          "<!DOCTYPE busconfig SYSTEM \"busconfig.dtd\">",
          "<!DOCTYPE busconfig SYSTEM 'busconfig.dtd'>",
          "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">"
        ] do
      assert {:ok, %{name: "busconfig", children: [%{name: "policy", line: 3}]}} =
               XML.parse(
                 doctype <>
                   "\n<busconfig>\n<policy context=\"default\"><allow user=\"*\"/></policy></busconfig>",
                 "policy.conf"
               )
    end
  end

  test "installed D-Bus PUBLIC identifier is accepted without external DTD" do
    for uri <- ["http", "https"] do
      assert {:ok, %{name: "busconfig", children: [%{name: "policy", line: 3}]}} =
               XML.parse(
                 "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \"#{uri}://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">" <>
                   "\n<busconfig>\n<policy context=\"default\"><allow user=\"*\"/></policy></busconfig>",
                 "installed.conf"
               )
    end
  end

  test "other PUBLIC identifier spellings remain unsupported" do
    for spelling <- ["D-bus", "D-BUs", "DBus"] do
      assert {:error, %{reason: :unsupported_doctype}} =
               XML.parse(
                 "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD #{spelling} Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\"><busconfig/>",
                 "unknown-public.conf"
               )
    end
  end

  for xml <- [
        "<!DOCTYPE busconfig SYSTEM \"http://127.0.0.1:1/evil.dtd\"><busconfig/>",
        "<!DOCTYPE busconfig [<!ENTITY secret SYSTEM \"file:///etc/passwd\">]><busconfig>&secret;</busconfig>",
        "<!DOCTYPE busconfig [<!ENTITY expand \"large\">]><busconfig>&expand;</busconfig>",
        "<busconfig>&undeclared;</busconfig>",
        "<busconfig xmlns=\"http://evil.invalid\"/>",
        "<busconfig><policy context=\"default\" context=\"mandatory\"/></busconfig>",
        "<busconfig/><busconfig/>",
        "<busconfig><policy></busconfig>"
      ] do
    @xml xml
    test "unsafe or malformed XML is rejected: #{xml}" do
      assert {:error, %{file: "policy.conf", line: _, element: _, reason: _}} =
               XML.parse(@xml, "policy.conf")
    end
  end

  test "XML bytes and nesting are bounded" do
    assert {:error, %{reason: :xml_too_large}} =
             XML.parse(
               "<busconfig>" <> :binary.copy(" ", 1_048_576) <> "</busconfig>",
               "large.conf"
             )

    assert {:error, %{reason: :xml_depth_exceeded}} =
             XML.parse(
               :binary.copy("<busconfig>", 33) <> :binary.copy("</busconfig>", 33),
               "deep.conf"
             )
  end

  test "XML node count is bounded independently of input bytes" do
    assert {:error, %{reason: :xml_nodes_exceeded}} =
             XML.parse(
               "<busconfig>" <> :binary.copy("<x/>", 100_000) <> "</busconfig>",
               "nodes.conf"
             )
  end

  test "DOCTYPE text inside comments, processing instructions and CDATA is literal" do
    declaration = "<!DOCTYPE busconfig SYSTEM 'arbitrary://DTD'>"

    assert {:ok, %{name: "busconfig", text: ^declaration}} =
             XML.parse(
               "<!--#{declaration}--><?literal #{declaration}?><busconfig><![CDATA[#{declaration}]]></busconfig>",
               "literal.conf"
             )
  end

  test "unknown names cannot intern arbitrary atoms" do
    inputs =
      for index <- 1..500,
          do: "<busconfig><unknown_#{index} attr_#{index}=\"value\"/></busconfig>"

    assert {:ok, _} = XML.parse("<busconfig><warm warm=\"value\"/></busconfig>", "warm.conf")
    before_count = :erlang.system_info(:atom_count)

    for xml <- inputs do
      assert {:ok, %{name: "busconfig"}} =
               XML.parse(xml, "unknown.conf")
    end

    assert :erlang.system_info(:atom_count) == before_count
  end

  test "installed HTTPS doctype is accepted without network fetching" do
    assert {:ok, %{name: "busconfig"}} =
             XML.parse(
               "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\" \"https://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\"><busconfig/>",
               "installed.conf"
             )
  end

  test "Unicode comments before DOCTYPE retain byte offsets and line provenance" do
    assert {:ok, %{name: "busconfig", line: 3}} =
             XML.parse(
               "<!-- 安全 -->\n<!DOCTYPE busconfig SYSTEM \"busconfig.dtd\">\n<busconfig/>",
               "unicode.conf"
             )
  end

  for xml <- [
        "<!DOCTYPE busconfig SYSTEM \"busconfig.dtd'><busconfig/>",
        "<busconfig><!DOCTYPE busconfig SYSTEM \"busconfig.dtd\"></busconfig>",
        "<busconfig/><!DOCTYPE busconfig SYSTEM \"busconfig.dtd\">"
      ] do
    @doctype_xml xml
    test "DOCTYPE normalization cannot hide malformed placement or quotes: #{xml}" do
      assert {:error, %{reason: :unsupported_doctype}} = XML.parse(@doctype_xml, "doctype.conf")
    end
  end

  test "arbitrary DTD URI schemes are rejected before they can become atoms" do
    inputs =
      for index <- 1..500,
          do: "<!DOCTYPE busconfig SYSTEM \"unknown_scheme_#{index}://DTD\"><busconfig/>"

    assert {:error, _} =
             XML.parse("<!DOCTYPE busconfig SYSTEM \"unknown://DTD\"><busconfig/>", "warm.conf")

    before_count = :erlang.system_info(:atom_count)

    for xml <- inputs do
      assert {:error, %{reason: :unsupported_doctype}} = XML.parse(xml, "scheme.conf")
    end

    assert :erlang.system_info(:atom_count) == before_count
  end
end
