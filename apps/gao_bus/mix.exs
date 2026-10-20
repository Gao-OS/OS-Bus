defmodule GaoBus.MixProject do
  use Mix.Project

  def project do
    [
      app: :gao_bus,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :xmerl],
      mod: {GaoBus.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_d_bus, in_umbrella: true},
      {:elixir_make, "~> 0.9", runtime: false},
      {:phoenix_pubsub, "~> 2.1"}
    ]
  end
end
