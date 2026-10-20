defmodule GaoBus.Config.LoaderTest do
  use ExUnit.Case, async: true

  alias GaoBus.Config

  @moduletag :tmp_dir
  @accounts %{
    users: %{"root" => 0, "messagebus" => 4, "service" => 28},
    groups: %{"root" => 0, "messagebus" => 4, "users" => 100},
    memberships: %{0 => [0], 4 => [4], 28 => [100]}
  }

  defp load(context, xml) do
    path = Path.join(context.tmp_dir, "system.conf")
    File.write!(path, xml)
    Config.load(path, accounts: @accounts, daemon_uid: 4)
  end

  test "policy classes and typed rules retain source order and omitted modifiers", context do
    assert {:ok, config} =
             load(context, """
             <busconfig>
               <policy user="service"><allow own="org.example.Service"/></policy>
               <policy context="default"><deny send_type="method_call"/><allow user="*"/></policy>
               <policy group="users"><allow send_destination_prefix="org.example"/></policy>
               <policy at_console="true"><allow receive_sender="*"/></policy>
               <policy at_console="false"><deny receive_type="error" receive_requested_reply="true"/></policy>
               <policy context="mandatory"><deny own_prefix="org.example.Restricted"/></policy>
             </busconfig>
             """)

    assert Enum.map(config.policies, & &1.selector) ==
             [
               {:uid, 28},
               :default,
               {:gid, 100},
               {:at_console, true},
               {:at_console, false},
               :mandatory
             ]

    assert [
             %{
               rules: [
                 %{
                   effect: :allow,
                   attributes: %{"own" => "org.example.Service"},
                   provenance: %{line: 2}
                 }
               ]
             }
             | _
           ] = config.policies

    assert %{
             rules: [
               %{attributes: %{"send_type" => :method_call}},
               %{attributes: %{"user" => "*"}}
             ]
           } = Enum.at(config.policies, 1)

    assert [%{file: file, sha256: hash, occurrence: 1}] = config.sources
    assert file == Path.join(context.tmp_dir, "system.conf")
    assert hash == Base.encode16(:crypto.hash(:sha256, File.read!(file)), case: :lower)
  end

  test "all supported message attributes preserve XML semantics without grants", context do
    assert {:ok, config} =
             load(context, """
             <busconfig><policy context="default">
               <allow send_destination="*" send_interface="*" send_member="*" send_type="*" send_path="*" send_requested_reply="false" eavesdrop="true" min_fds="0" max_fds="253"/>
               <deny receive_sender="org.example.Service" receive_interface="org.example.Interface" receive_member="Changed" receive_type="signal" receive_path="/example" receive_requested_reply="true" eavesdrop="false"/>
               <allow send_error="*" send_type="error" send_requested_reply="false"/>
               <deny receive_error="org.example.Error" receive_type="error" receive_requested_reply="true"/>
               <allow send_broadcast="true"/>
               <deny group="users"/>
             </policy></busconfig>
             """)

    assert [%{rules: [allow, deny, send_error, receive_error, broadcast, admission]}] =
             config.policies

    assert %{
             "send_type" => "*",
             "send_requested_reply" => false,
             "eavesdrop" => true,
             "min_fds" => 0,
             "max_fds" => 253
           } = allow.attributes

    assert %{"receive_type" => :signal, "receive_requested_reply" => true, "eavesdrop" => false} =
             deny.attributes

    assert broadcast.attributes == %{"send_broadcast" => true}
    assert admission.attributes == %{"group" => 100}

    assert send_error.attributes == %{
             "send_error" => "*",
             "send_type" => :error,
             "send_requested_reply" => false
           }

    assert receive_error.attributes == %{
             "receive_error" => "org.example.Error",
             "receive_type" => :error,
             "receive_requested_reply" => true
           }
  end

  test "both effects reject admission rules in user and group policy classes", context do
    for selector <- ["user=\"service\"", "group=\"users\""],
        effect <- ["allow", "deny"],
        attribute <- ["user=\"service\"", "group=\"users\""] do
      assert {:error, %{reason: :invalid_admission_policy_class}} =
               load(
                 context,
                 "<busconfig><policy #{selector}><#{effect} #{attribute}/></policy></busconfig>"
               )
    end
  end

  test "reference-invalid message combinations reject the whole XML candidate", context do
    for effect <- ["allow", "deny"],
        attributes <- [
          "send_member=\"Secret\"",
          "receive_member=\"Secret\"",
          "send_interface=\"*\" send_error=\"*\"",
          "send_interface=\"*\" send_member=\"Secret\" send_error=\"*\"",
          "receive_interface=\"*\" receive_error=\"*\"",
          "receive_path=\"/example\" receive_member=\"Secret\" receive_error=\"*\"",
          "send_broadcast=\"true\" send_destination=\"org.example.Service\""
        ] do
      assert {:error, %{element: ^effect, reason: :invalid_rule_combination}} =
               load(
                 context,
                 "<busconfig><policy context=\"default\"><#{effect} #{attributes}/></policy></busconfig>"
               )
    end
  end

  test "wildcard destination and member path alternatives remain valid", context do
    assert {:ok, _} =
             load(context, """
             <busconfig><policy context="default">
               <allow send_broadcast="true" send_destination="*"/>
               <allow send_path="/example" send_member="Secret"/>
               <deny receive_path="/example" receive_member="Secret"/>
             </policy></busconfig>
             """)
  end

  test "includes preserve repeated occurrences and directory order", context do
    directory = Path.join(context.tmp_dir, "system.d")
    File.mkdir!(directory)

    leaf =
      "<busconfig><policy context=\"default\"><allow own=\"org.example.Leaf\"/></policy></busconfig>"

    File.write!(Path.join(context.tmp_dir, "leaf.conf"), leaf)

    File.write!(
      Path.join(directory, "b.conf"),
      "<busconfig><include>../leaf.conf</include></busconfig>"
    )

    File.write!(
      Path.join(directory, "a.conf"),
      "<busconfig><policy context=\"mandatory\"><deny own=\"*\"/></policy></busconfig>"
    )

    File.write!(Path.join(directory, "ignored.txt"), "invalid XML")

    assert {:ok, config} =
             load(
               context,
               "<busconfig><include>leaf.conf</include><includedir>system.d</includedir><include>leaf.conf</include></busconfig>"
             )

    assert Enum.map(config.sources, &Path.basename(&1.file)) == [
             "system.conf",
             "leaf.conf",
             "a.conf",
             "b.conf",
             "leaf.conf",
             "leaf.conf"
           ]

    assert Enum.map(config.sources, & &1.occurrence) == Enum.to_list(1..6)
    assert Enum.map(config.policies, & &1.selector) == [:default, :mandatory, :default, :default]
  end

  test "missing directory and explicitly optional file are accepted", context do
    assert {:ok, %{sources: [_], policies: []}} =
             load(
               context,
               "<busconfig><includedir>absent</includedir><include ignore_missing=\"yes\">absent.conf</include></busconfig>"
             )

    assert {:error, %{file: file, element: "include", reason: {:file_error, :enoent}}} =
             load(context, "<busconfig><include>absent.conf</include></busconfig>")

    assert file == Path.join(context.tmp_dir, "system.conf")
  end

  test "optional include never hides malformed configuration", context do
    File.write!(Path.join(context.tmp_dir, "bad.conf"), "<busconfig>")

    assert {:error, %{file: file, reason: {:invalid_xml, _}}} =
             load(
               context,
               "<busconfig><include ignore_missing=\"yes\">bad.conf</include></busconfig>"
             )

    assert file == Path.join(context.tmp_dir, "bad.conf")
  end

  test "symlink alias cycle is rejected with including provenance", context do
    File.ln_s!("system.conf", Path.join(context.tmp_dir, "alias.conf"))

    assert {:error, %{element: "include", reason: :include_cycle}} =
             load(context, "<busconfig><include>alias.conf</include></busconfig>")
  end

  test "include recursion is bounded", context do
    for index <- 0..32 do
      xml =
        if index == 32,
          do: "<busconfig/>",
          else: "<busconfig><include>#{index + 1}.conf</include></busconfig>"

      File.write!(Path.join(context.tmp_dir, "#{index}.conf"), xml)
    end

    assert {:error, %{reason: :include_depth_exceeded}} =
             Config.load(Path.join(context.tmp_dir, "0.conf"), accounts: @accounts, daemon_uid: 4)
  end

  test "installed daemon directives and all finite limits are retained", context do
    names =
      ~w(max_incoming_bytes max_incoming_unix_fds max_outgoing_bytes max_outgoing_unix_fds max_message_size max_message_unix_fds service_start_timeout auth_timeout pending_fd_timeout max_completed_connections max_incomplete_connections max_connections_per_user max_pending_service_starts max_names_per_connection max_match_rules_per_connection max_replies_per_connection reply_timeout)

    limits = Enum.map_join(names, fn name -> "<limit name=\"#{name}\">100</limit>" end)

    assert {:ok, config} =
             load(context, """
             <busconfig><type>system</type><user>messagebus</user><fork/><pidfile>/run/dbus/pid</pidfile><syslog/>
             <auth>EXTERNAL</auth><listen>unix:path=/run/dbus/system_bus_socket</listen><apparmor mode="disabled"/>
             <servicehelper>/run/wrappers/bin/dbus-daemon-launch-helper</servicehelper><servicedir>/usr/share/dbus-1/system-services</servicedir>#{limits}</busconfig>
             """)

    assert %{
             type: :system,
             user: 4,
             fork: true,
             pidfile: "/run/dbus/pid",
             syslog: true,
             auth: ["EXTERNAL"],
             listen: ["unix:path=/run/dbus/system_bus_socket"],
             apparmor: :disabled,
             servicehelper: "/run/wrappers/bin/dbus-daemon-launch-helper",
             servicedir: ["/usr/share/dbus-1/system-services"]
           } = config.settings

    assert config.limits == Map.new(names, &{&1, 100})
  end

  for clause <- [
        "<policy context=\"default\"><allow send_destination=\"*\" receive_sender=\"*\"/></policy>",
        "<policy context=\"default\"><allow own=\"*\" send_type=\"signal\"/></policy>",
        "<policy context=\"default\"><allow user=\"root\" own=\"*\"/></policy>",
        "<policy user=\"root\" group=\"root\"><allow own=\"*\"/></policy>",
        "<policy context=\"default\"><allow send_destination=\"*\" send_destination_prefix=\"org.example\"/></policy>",
        "<policy context=\"default\"><allow send_type=\"bogus\"/></policy>",
        "<policy context=\"default\"><allow send_type=\"signal\" min_fds=\"3\" max_fds=\"2\"/></policy>",
        "<policy context=\"default\"><allow own=\"*\" eavesdrop=\"true\"/></policy>",
        "<policy context=\"default\"><allow send_destination=\"org.example.*\"/></policy>",
        "<policy user=\"root\"><deny user=\"service\"/></policy>",
        "<policy context=\"default\"><allow send_type=\"signal\" silently_allow=\"true\"/></policy>",
        "<policy user=\"unknown-account\"><allow own=\"*\"/></policy>",
        "<apparmor mode=\"required\"/>",
        "<selinux/>",
        "<unknown_activation/>",
        "<limit name=\"unknown_limit\">10</limit>",
        "<limit name=\"auth_timeout\">-1</limit>",
        "<auth>ANONYMOUS</auth>",
        "<listen>tcp:host=localhost,port=1234</listen>"
      ] do
    @clause clause
    test "unsupported or contradictory clause rejects whole candidate: #{clause}", context do
      assert {:error, %{file: file, line: line, element: element, reason: _}} =
               load(
                 context,
                 "<busconfig><policy context=\"default\"><allow user=\"*\"/></policy>" <>
                   @clause <> "</busconfig>"
               )

      assert file == Path.join(context.tmp_dir, "system.conf")
      assert line >= 1
      assert is_binary(element)
    end
  end

  test "complete pinned profile retains every installed rule and repeated source" do
    root = Path.expand("../../../../test/reports/foundation/p09-profile", __DIR__)
    inventory = Jason.decode!(File.read!(Path.join(root, "inventory.json")))

    accounts = %{
      users: %{
        "root" => 0,
        "messagebus" => 4,
        "polkituser" => 28,
        "systemd-network" => 152,
        "systemd-resolve" => 153,
        "systemd-timesync" => 154,
        "systemd-oom" => 995
      },
      groups: %{"root" => 0, "messagebus" => 4},
      memberships: %{0 => [0]},
      user_records: %{
        "root" => %{name: "root", uid: 0, gid: 0, groups: [0], provenance: nil}
      }
    }

    # systemd-oom is deliberately a synthetic trusted test identity. Its real
    # numeric UID must come from the target VM's runtime account snapshot.
    assert {:ok, config} = Config.load(inventory["root"], accounts: accounts)
    assert length(config.sources) == 17
    assert length(config.policies) == 39
    assert Enum.sum(Enum.map(config.policies, &length(&1.rules))) == 500
    assert length(config.settings.servicedir) == 3
    assert config.daemon_uid == 4

    expected_hashes =
      inventory["files"]
      |> Enum.filter(&(&1["kind"] == "xml"))
      |> Enum.map(& &1["sha256"])
      |> Enum.sort()

    assert Enum.sort(Enum.map(config.sources, & &1.sha256)) == expected_hashes

    assert Enum.all?(config.sources, fn source ->
             source.sha256 ==
               Base.encode16(:crypto.hash(:sha256, File.read!(source.file)), case: :lower)
           end)

    services = config.services
    assert length(services.occurrences) == 16
    assert map_size(services.selected) == 15
    assert Enum.map(services.directories, & &1.path) == config.settings.servicedir
    assert Enum.map(services.directories, & &1.status) == [:missing, :present, :present]

    assert Enum.map(services.occurrences, & &1.path) ==
             Enum.map(inventory["services"], & &1["path"])

    assert Enum.map(services.occurrences, & &1.capture.sha256) ==
             Enum.map(inventory["services"], & &1["sha256"])

    for {entry, installed} <- Enum.zip(services.occurrences, inventory["services"]) do
      fields = installed["sections"]["D-BUS Service"]
      assert entry.name == fields["Name"]
      assert entry.exec == fields["Exec"]
      assert entry.user == "root"
      assert entry.account == accounts.user_records["root"]
      assert entry.systemd_service == fields["SystemdService"]
    end

    [effective, shadowed] =
      Enum.filter(services.occurrences, &(&1.name == "org.freedesktop.PolicyKit1"))

    assert effective.disposition == :effective
    assert effective.directory_index == 2
    assert shadowed.disposition == :shadowed
    assert shadowed.directory_index == 3
    assert services.selected[effective.name] == effective
    assert effective.capture.sha256 == shadowed.capture.sha256

    assert effective.argv == [
             String.replace_suffix(effective.exec, " --no-debug", ""),
             "--no-debug"
           ]

    assert shadowed.argv == effective.argv
    assert effective.systemd_service == "polkit.service"

    false_commands = Enum.reject(services.occurrences, &(&1.name == effective.name))
    assert length(false_commands) == 14

    for entry <- false_commands do
      assert Path.type(entry.exec) == :absolute
      assert Path.basename(entry.exec) == "false"
      assert entry.argv == [entry.exec]
      assert entry.disposition == :effective
      assert entry.directory_index == 2
    end

    assert services.selected["org.freedesktop.systemd1"].systemd_service == nil
  end

  test "daemon UID is explicit when configuration does not select a user", context do
    path = Path.join(context.tmp_dir, "system.conf")
    File.write!(path, "<busconfig/>")
    assert {:error, %{reason: :missing_daemon_uid}} = Config.load(path, accounts: @accounts)
    assert {:ok, %{daemon_uid: 28}} = Config.load(path, accounts: @accounts, daemon_uid: 28)
  end

  test "scalar settings and finite limits use their last occurrence", context do
    assert {:ok, config} =
             load(
               context,
               "<busconfig><type>session</type><user>root</user><limit name=\"auth_timeout\">100</limit><type>system</type><user>messagebus</user><limit name=\"auth_timeout\">200</limit></busconfig>"
             )

    assert config.settings.type == :system
    assert config.daemon_uid == 4
    assert config.limits == %{"auth_timeout" => 200}
  end

  test "repeated includes cannot exceed the file count ceiling", context do
    File.write!(Path.join(context.tmp_dir, "leaf.conf"), "<busconfig/>")

    assert {:error, %{reason: :include_count_exceeded}} =
             load(
               context,
               "<busconfig>" <>
                 :binary.copy("<include>leaf.conf</include>", 1024) <> "</busconfig>"
             )
  end

  test "aggregate XML bytes cannot exceed the candidate ceiling", context do
    for index <- 1..9,
        do:
          File.write!(
            Path.join(context.tmp_dir, "#{index}.conf"),
            "<busconfig>" <> :binary.copy(" ", 1_000_000) <> "</busconfig>"
          )

    includes = Enum.map_join(1..9, fn index -> "<include>#{index}.conf</include>" end)

    assert {:error, %{reason: :config_bytes_exceeded}} =
             load(context, "<busconfig>" <> includes <> "</busconfig>")
  end

  test "rule count has a finite candidate ceiling", context do
    assert {:error, %{reason: :rule_count_exceeded}} =
             load(
               context,
               "<busconfig><policy context=\"default\">" <>
                 :binary.copy("<allow own=\"*\"/>", 10001) <> "</policy></busconfig>"
             )
  end
end
