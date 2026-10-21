# Package-build input only. Never run against a host's active bus/configuration.
# Run using the built umbrella in the image builder's isolated absolute-path
# filesystem, after the fixed helper and standard wrapper have been built.
defmodule GaoBus.HelperBindingManifestProducer do
  alias GaoBus.Activation.HelperBinding
  alias GaoBus.Config
  alias GaoBus.Config.{Accounts, Capture}

  @maximum 33_554_432

  def run(arguments) do
    producer_identity = isolated_image()

    {options, [], []} =
      OptionParser.parse(arguments,
        strict: [
          helper: :string,
          helper_config_header: :string,
          wrapper_source: :string,
          passwd: :string,
          group: :string,
          daemon: :string,
          derivation: :string
        ]
      )

    helper = Keyword.fetch!(options, :helper)
    wrapper = Keyword.fetch!(options, :wrapper_source)
    header_path = Keyword.fetch!(options, :helper_config_header)
    derivation = Keyword.fetch!(options, :derivation)
    # The producer is part of the reproducible derivation. This identifies its
    # closure; supplying a header from an unrelated build is not supported.
    true =
      String.starts_with?(derivation, "/nix/store/") and String.ends_with?(derivation, ".drv")

    true = Enum.all?([helper, wrapper, header_path], &String.starts_with?(&1, "/nix/store/"))

    header = read(header_path, 1_048_576)

    [_, root] =
      Regex.run(~r/^#define[ \t]+DBUS_SYSTEM_CONFIG_FILE[ \t]+"([^"\n]+)"[ \t]*$/m, header)

    bridge = HelperBinding.bridge_path()
    bridge_bytes = read(bridge, @maximum)
    {:ok, entrypoint} = HelperBinding.bridge_binding(bridge_bytes)
    true = entrypoint != ""
    wrapper_bytes = read(wrapper, @maximum)
    # Supported standard-wrapper derivation embeds its fixed exec target. The
    # exact binary hash is retained, rather than trusting wrapper flags alone.
    true = :binary.match(wrapper_bytes, helper <> <<0>>) != :nomatch

    {:ok, config} =
      Config.load(root,
        passwd: Keyword.fetch!(options, :passwd),
        group: Keyword.fetch!(options, :group)
      )

    {:ok, daemon} = Accounts.bind_user(config.accounts, Keyword.fetch!(options, :daemon))
    installed = File.stat!(entrypoint)
    true = installed.type == :regular and installed.uid == 0 and installed.gid == daemon.gid
    mode = Bitwise.band(installed.mode, 0o7777)
    true = mode in [0o4550, 0o4750]
    identity = %{uid: daemon.uid, gid: daemon.gid, real_uid: daemon.uid, real_gid: daemon.gid}
    summary = Capture.summary(config.captures)

    manifest = %{
      "version" => 1,
      "bridge" => artifact(bridge, "gao_helper_bridge"),
      "helper" => artifact(helper, helper),
      "wrapper_source" => artifact(wrapper, wrapper),
      "entrypoint" => %{
        "path" => entrypoint,
        "sha256" => digest(wrapper_bytes),
        "uid" => installed.uid,
        "gid" => installed.gid,
        "mode" => mode
      },
      "compiled_helper_path" => entrypoint,
      "configuration_root" => root,
      "endpoint" => "unix:path=/run/dbus/system_bus_socket",
      "daemon" => %{"name" => daemon.name, "uid" => daemon.uid, "gid" => daemon.gid},
      "servicedirs" => Map.get(config.settings, :servicedir, []),
      "files" => captured(summary.files, & &1.sha256),
      "directories" => captured(summary.directories, & &1.names),
      "accounts" =>
        Map.new(
          [daemon | Enum.map(config.services.selected, fn {_name, entry} -> entry.account end)],
          fn record ->
            {record.name,
             %{"uid" => record.uid, "gid" => record.gid, "groups" => Enum.sort(record.groups)}}
          end
        )
    }

    :ok = HelperBinding.pair(config, manifest, identity, manifest["endpoint"])
    # Target uid/gid/modes describe final root-owned package installation, not
    # the unprivileged builder's uid/gid. Runtime verifies those installed facts.
    manifest_path = Path.join(List.to_string(:code.priv_dir(:gao_bus)), "helper_binding.json")
    encoded = JSON.encode!(manifest)
    true = byte_size(encoded) <= 1_048_576
    File.write!(manifest_path, encoded <> "\n", [:exclusive])
    File.chmod!(manifest_path, 0o444)

    # Sidecar is build provenance, never an approval input to the daemon.
    provenance = %{
      "derivation" => derivation,
      "producer_sha256" => digest(read(__ENV__.file, 1_048_576)),
      "helper_config_header" => header_path,
      "helper_config_header_sha256" => digest(header),
      "manifest_sha256" => digest(encoded <> "\n"),
      "producer_identity" => Map.take(producer_identity, [:uid, :gid, :real_uid, :real_gid])
    }

    File.write!(manifest_path <> ".provenance.json", JSON.encode!(provenance) <> "\n", [
      :exclusive
    ])

    File.chmod!(manifest_path <> ".provenance.json", 0o444)
  end

  defp isolated_image do
    # This producer never runs a root BEAM and never accepts a host approval flag.
    true = File.read!("/etc/osbus-p10-package-builder") == "offline-disposable-image-v1\n"
    true = "osbus.p10-package-builder=1" in String.split(File.read!("/proc/cmdline"))
    %{uid: uid, real_uid: uid, gid: gid, real_gid: gid} = identity = GaoBus.Unix.Native.identity()
    true = uid != 0 and gid != 0
    false = File.exists?("/run/dbus/system_bus_socket")
    identity
  end

  defp artifact(source, path) do
    stat = File.stat!(source)

    %{
      "path" => path,
      "sha256" => digest(read(source, @maximum)),
      "uid" => 0,
      "gid" => 0,
      "mode" => Bitwise.band(stat.mode, 0o7777)
    }
  end

  defp captured(records, value) do
    Map.new(records, fn
      {path, {:ok, record}} -> {path, value.(record)}
      {path, {:error, %{reason: :enoent}}} -> {path, nil}
    end)
  end

  defp read(path, maximum) do
    before = File.stat!(path, time: :posix)
    true = before.type == :regular and before.size <= maximum
    {:ok, file} = :file.open(String.to_charlist(path), [:raw, :binary, :read])

    try do
      {:ok, bytes} = :file.read(file, maximum + 1)
      true = byte_size(bytes) == before.size
      {:ok, after_read} = :file.read_file_info(file, time: :posix)
      keys = [:type, :size, :mode, :inode, :major_device, :minor_device, :mtime, :ctime]
      true = Map.take(before, keys) == Map.take(File.Stat.from_record(after_read), keys)
      true = Map.take(before, keys) == Map.take(File.stat!(path, time: :posix), keys)
      bytes
    after
      :file.close(file)
    end
  end

  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end

GaoBus.HelperBindingManifestProducer.run(System.argv())
