import Config

configuration = System.fetch_env!("OS_BUS_CONFIG")

unless Path.type(configuration) == :absolute do
  raise "OS_BUS_CONFIG must be an absolute configuration path"
end

inherited =
  case System.get_env("OS_BUS_INHERITED_LISTENER") do
    nil -> false
    "false" -> false
    "true" -> true
    _ -> raise "OS_BUS_INHERITED_LISTENER must be true or false"
  end

activation =
  case System.get_env("OS_BUS_ACTIVATION", "disabled") do
    "disabled" -> :disabled
    "systemd" -> :systemd
    "systemd-helper" -> :systemd_helper
    _ -> raise "OS_BUS_ACTIVATION must be disabled, systemd or systemd-helper"
  end

config :gao_bus,
  profile: :system,
  cluster: false,
  lifecycle: :release,
  inherited_listener: inherited,
  config_file: configuration,
  runtime_invocation: %{
    nofork: true,
    nopidfile: true,
    log_target: :stderr,
    activation: activation
  }

if path = System.get_env("DBUS_SOCKET_PATH") do
  config :gao_bus, socket_path: path
end
