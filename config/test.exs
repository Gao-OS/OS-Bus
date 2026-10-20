import Config

# Explicit session fixture for existing interoperability tests. Production has
# no default policy; system-profile tests install their own restrictive rules.
config :gao_bus,
  profile: :session,
  policy_rules:
    Enum.map([:connect, :own, :send, :receive], &%{action: &1, effect: :allow, match: %{}})

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :gao_bus_web, GaoBusWebWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "iKIHyGYt9OBbhF6TJdUNWvxtbpY1kr7pyFeJUuGnp+afbC3UrZlOXHW8aiLwKVFU",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Keep test-env GaoBus boot away from the default development socket.
config :gao_bus, :socket_path, Path.join(System.tmp_dir!(), "gb_test_boot")

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
