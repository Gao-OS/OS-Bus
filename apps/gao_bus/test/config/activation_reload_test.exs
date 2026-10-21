defmodule GaoBus.Config.ActivationReloadTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Config, Policy}

  @moduletag :tmp_dir
  @name "org.example.Activated"

  setup %{tmp_dir: directory} do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    services = Path.join(directory, "services")
    File.mkdir!(services)
    path = Path.join(directory, "bus.conf")
    passwd = Path.join(directory, "passwd")
    group = Path.join(directory, "group")
    File.write!(passwd, "messagebus:x:42:42::/:/bin/false\n")
    File.write!(group, "messagebus:x:42:\n")

    File.write!(path, """
    <busconfig><type>system</type><user>messagebus</user>
      <servicedir>#{services}</servicedir>
      <servicehelper>/run/wrappers/bin/dbus-daemon-launch-helper</servicehelper>
      <policy context="default"><allow user="*"/></policy>
    </busconfig>
    """)

    service = Path.join(services, @name <> ".service")
    write_service(service, "SystemdService=example.service\n")
    options = [passwd: passwd, group: group]
    assert {:ok, config} = Config.load(path, options)
    %{config: config, path: path, service: service, options: options}
  end

  test "reload cannot introduce a helper behind an unchanged service directory", fixture do
    start_supervised!(
      {Policy,
       rules: fixture.config,
       config_file: fixture.path,
       config_options: fixture.options,
       activation_mode: :systemd}
    )

    original = Policy.snapshot()
    write_service(fixture.service, "")

    assert {:error,
            %{reason: {:unsupported_activation_backend, @name, :helper}, origins: origins}} =
             Policy.reload_file()

    assert Enum.all?(origins, &(&1.file == fixture.service))
    assert Policy.snapshot() == original
    assert {:ok, helper_config} = Config.load(fixture.path, fixture.options)

    assert {:error, %{reason: {:unsupported_activation_backend, @name, :helper}}} =
             Policy.reload(helper_config)

    assert Policy.snapshot() == original
  end

  test "reload publishes a changed supported systemd service", fixture do
    start_supervised!(
      {Policy,
       rules: fixture.config,
       config_file: fixture.path,
       config_options: fixture.options,
       activation_mode: :systemd}
    )

    write_service(fixture.service, "SystemdService=changed.service\n")
    assert {:ok, 2} = Policy.reload_file()
    assert {:ok, configuration} = Policy.configuration()
    assert configuration.services.selected[@name].systemd_service == "changed.service"

    assert configuration.settings.servicehelper ==
             "/run/wrappers/bin/dbus-daemon-launch-helper"
  end

  test "initial reread enforces the selected backend before publication", fixture do
    write_service(fixture.service, "")

    assert {:error, _reason} =
             start_supervised(
               {Policy,
                rules: fixture.config,
                config_file: fixture.path,
                config_options: fixture.options,
                activation_mode: :systemd}
             )

    assert {:error, :policy_unavailable} = Policy.snapshot()
  end

  defp write_service(path, unit) do
    File.write!(
      path,
      "[D-BUS Service]\nName=#{@name}\nExec=/bin/false\nUser=messagebus\n" <> unit
    )
  end
end
