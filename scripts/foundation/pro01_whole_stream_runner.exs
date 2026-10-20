# C-only disposable-VM runner; frozen product, one positive whole-stream test.
import Bitwise

[bindings_path, evidence] = System.argv()
true = evidence == "/run/osbus-pro01-whole-stream"
status_path = Path.join(evidence, "runner-status.json")
write = fn path, value -> File.write!(path, :json.encode(value)) end

try do
  true = System.version() == "1.17.3"
  ~c"27" = :erlang.system_info(:otp_release)
  version_file = Path.join([to_string(:code.root_dir()), "releases", "27", "OTP_VERSION"])
  "27.3.4.6" = String.trim(File.read!(version_file))
  %{type: :regular, uid: 0} = File.lstat!("/etc/osbus-pro01-whole-stream-guest")
  "isolated-vm\n" = File.read!("/etc/osbus-pro01-whole-stream-guest")
  private = Path.join(evidence, "private")
  ^private = System.get_env("TMPDIR")
  %{type: :directory, uid: 1101, mode: mode} = File.lstat!(private)
  true = band(mode, 0o777) == 0o700
  [] = File.ls!(private)
  {:ok, _} = Application.ensure_all_started(:crypto)
  bindings = :json.decode(File.read!(bindings_path))
  "pro01-whole-stream" = bindings["selection"]
  1 = bindings["expected_tests"]
  true = bindings["not_a_release"]

  pin = fn path ->
    %{type: :regular, mode: mode} = File.lstat!(path)
    true = band(mode, 0o222) == 0
    bytes = File.read!(path)

    %{
      bytes: byte_size(bytes),
      mode: band(mode, 0o777),
      sha256: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
    }
  end

  for field <- ["artifact_store", "runtime_store", "fixtures_store", "dependency_store"] do
    true = String.starts_with?(bindings[field], "/nix/store/")
  end

  artifact = bindings["artifact_store"]
  artifact_pin = pin.(Path.join(artifact, "artifact.json"))
  true = artifact_pin.sha256 == bindings["artifact_sha256"]
  manifest = :json.decode(File.read!(Path.join(artifact, "artifact.json")))
  true = manifest["not_a_release"]
  80 = map_size(manifest["files"])
  71 = map_size(manifest["sources"])
  true = manifest["origin_pin"]["sha256"] == bindings["runtime_sha256"]
  true = pin.(bindings["runtime_store"]).sha256 == bindings["runtime_sha256"]
  true = pin.(__ENV__.file).sha256 == bindings["runner_sha256"]
  ["ex_d_bus", "gao_bus", "phoenix_pubsub"] = Enum.sort(File.ls!(Path.join(artifact, "lib")))

  actual_files =
    artifact
    |> Path.join("lib/**/*")
    |> Path.wildcard(match_dot: true)
    |> Enum.reject(&(File.lstat!(&1).type == :directory))
    |> Enum.map(&Path.relative_to(&1, artifact))
    |> Enum.sort()

  true = actual_files == Enum.sort(Map.keys(manifest["files"]))

  for {name, expected} <- manifest["files"] do
    true = String.starts_with?(name, "lib/") and ".." not in Path.split(name)
    observed = pin.(Path.join(artifact, name))
    true = observed.bytes == expected["bytes"]
    true = observed.sha256 == expected["sha256"]
    true = observed.mode == band(expected["mode"], bnot(0o222))
  end

  captures =
    for {store_field, hashes_field} <- [
          {"fixtures_store", "fixture_hashes"},
          {"dependency_store", "dependency_hashes"}
        ],
        into: %{} do
      root = bindings[store_field]
      hashes = bindings[hashes_field]

      if store_field == "dependency_store",
        do: true = Enum.sort(File.ls!(root)) == Enum.sort(Map.keys(hashes))

      files =
        for {name, expected} <- hashes, into: %{} do
          true = Path.type(name) == :relative and ".." not in Path.split(name)
          observed = pin.(Path.join(root, name))
          true = observed.sha256 == expected
          {name, observed}
        end

      {store_field, %{store: root, files: files}}
    end

  write.(Path.join(evidence, "verified-inputs.json"), %{
    artifact_store: artifact,
    artifact_pin: artifact_pin,
    artifact_files: 80,
    production_source_pins: 71,
    captures: captures,
    runtime_manifest_sha256: bindings["runtime_sha256"],
    not_a_release: true
  })

  %{uid: 1101, real_uid: 1101, gid: 1101, real_gid: 1101} = GaoBus.Unix.Native.identity()
  Code.ensure_loaded!(Jason)

  true =
    to_string(:code.which(Jason)) == Path.join(bindings["dependency_store"], "Elixir.Jason.beam")

  Application.put_env(:gao_bus, :profile, :system)
  ExUnit.start(autorun: false, seed: 1703, max_cases: 1)

  for name <- bindings["tests"],
      do: Code.require_file(Path.join(bindings["fixtures_store"], name))

  result = ExUnit.run()
  IO.puts(["WHOLE_STREAM_EXUNIT ", :json.encode(result)])
  empty = File.ls!(private) == []

  passed =
    result.total == 1 and result.failures == 0 and result.skipped == 0 and
      result.excluded == 0 and empty

  write.(status_path, %{
    selection: "pro01-whole-stream",
    result: result,
    private_directory_empty: empty,
    passed: passed,
    runtime_qualification: false,
    product_qualified: false
  })

  System.halt(if passed, do: 0, else: 1)
rescue
  error ->
    write.(status_path, %{
      selection: "pro01-whole-stream",
      passed: false,
      error: Exception.format(:error, error, __STACKTRACE__),
      runtime_qualification: false,
      product_qualified: false
    })

    reraise error, __STACKTRACE__
end
