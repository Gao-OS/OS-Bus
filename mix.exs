defmodule GaoBus.Umbrella.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.3.0-alpha.1",
      start_permanent: Mix.env() == :prod,
      releases: [
        os_bus: [
          applications: [gao_bus: :permanent],
          include_executables_for: [:unix],
          runtime_config_path: "rel/os_bus/runtime.exs",
          rel_templates_path: "rel/os_bus",
          reboot_system_after_config: false
        ]
      ],
      deps: deps(),
      name: "GaoBus",
      source_url: "https://github.com/Gao-OS/OS-Bus",
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  # Dependencies listed here are available only for this
  # project and cannot be accessed from applications inside
  # the apps folder.
  #
  # Run "mix help deps" for examples and options.
  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end
end
