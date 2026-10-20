defmodule GaoBus.Activation.HelperBinding do
  @moduledoc """
  Installed-package binding for the fixed traditional activation bridge.

  Only `priv/helper_binding.json` is consumed. A package publisher must generate
  it from the exact helper build, wrapper and captured deployment configuration;
  this module does not turn caller metadata into installation approval. All
  reads are bounded and all existing path components must be protected from
  non-root replacement. Revalidation runs in the helper worker, never Router.
  """

  import Bitwise
  alias GaoBus.Config
  alias GaoBus.Config.{Accounts, Capture}
  alias GaoBus.Unix.{Directory, Native}

  @endpoint "unix:path=/run/dbus/system_bus_socket"
  @manifest_bytes 1_048_576
  @artifact_bytes 33_554_432
  @file_bytes 1_048_576
  @capture_bytes 16_777_216
  @artifacts ~w(bridge helper wrapper_source entrypoint)
  @keys ~w(version bridge helper wrapper_source entrypoint compiled_helper_path configuration_root endpoint daemon servicedirs files directories accounts)

  defstruct [:manifest_sha256, :configuration, :identity, :endpoint]

  def bridge_path, do: Path.join(List.to_string(:code.priv_dir(:gao_bus)), "gao_helper_bridge")

  def load(%Config{} = config, identity, endpoint) do
    manifest_path = Path.join(List.to_string(:code.priv_dir(:gao_bus)), "helper_binding.json")

    with {:ok, bytes, _stat} <- read_trusted(manifest_path, @manifest_bytes),
         {:ok, manifest} <- decode(bytes),
         :ok <- pair(config, manifest, identity, endpoint),
         :ok <- installation(manifest) do
      {:ok,
       %__MODULE__{
         manifest_sha256: digest(bytes),
         configuration: config,
         identity: identity,
         endpoint: endpoint
       }}
    else
      {:error, reason} -> refusal(config, reason)
    end
  end

  def revalidate(%__MODULE__{} = binding), do: revalidate(binding.configuration, binding)
  def revalidate(_binding), do: {:error, :missing_helper_binding}

  def revalidate(%Config{} = config, %__MODULE__{} = binding) do
    with true <- Native.identity() == binding.identity,
         {:ok, current} <- load(config, binding.identity, binding.endpoint),
         true <- current.manifest_sha256 == binding.manifest_sha256 do
      :ok
    else
      false -> refusal(config, :helper_binding_changed)
      {:error, _reason} = failure -> failure
    end
  end

  def revalidate(%Config{} = config, _binding), do: refusal(config, :missing_helper_binding)

  @doc false
  # Pure pairing is also usable by the package producer; it never authorizes a
  # worker. `load/3` additionally verifies the fixed manifest and installation.
  def pair(%Config{} = config, manifest, identity, endpoint) do
    with :ok <- schema(manifest),
         true <- endpoint == @endpoint and manifest["endpoint"] == endpoint,
         true <- config.settings[:type] == :system,
         true <- is_map(config.services) and is_map(Map.get(config.services, :selected)),
         true <- is_map(Map.get(config.accounts, :users)) and
                   is_map(Map.get(config.accounts, :user_records)),
         true <- config.settings[:servicehelper] == manifest["compiled_helper_path"],
         true <- manifest["entrypoint"]["path"] == manifest["compiled_helper_path"],
         [%{file: root} | _] <- config.sources,
         true <- root == manifest["configuration_root"],
         true <- Map.get(config.settings, :listen, []) == [endpoint],
         true <- Map.get(config.settings, :servicedir, []) == manifest["servicedirs"],
         :ok <- daemon(config, manifest["daemon"], identity),
         {:ok, files, directories} <- captured(config),
         :ok <- account_sources(config.accounts, files),
         true <- files == manifest["files"] and directories == manifest["directories"],
         {:ok, accounts} <- bound_accounts(config, manifest["daemon"]["name"]),
         true <- accounts == manifest["accounts"] do
      :ok
    else
      {:error, _reason} = failure -> failure
      _ -> {:error, :helper_configuration_pairing_mismatch}
    end
  end

  defp decode(bytes) do
    case JSON.decode(bytes) do
      {:ok, value} -> {:ok, value}
      {:error, _reason} -> {:error, :invalid_helper_manifest}
    end
  end

  defp schema(manifest) when is_map(manifest) do
    valid =
      Enum.sort(Map.keys(manifest)) == Enum.sort(@keys) and manifest["version"] == 1 and
        artifact?(manifest["bridge"], :bridge) and
        Enum.all?(@artifacts -- ["bridge"], &artifact?(manifest[&1], :absolute)) and
        Enum.all?(~w(compiled_helper_path configuration_root), &path?(manifest[&1])) and
        manifest["endpoint"] == @endpoint and daemon_record?(manifest["daemon"]) and
        paths?(manifest["servicedirs"], 64) and files?(manifest["files"]) and
        directories?(manifest["directories"]) and accounts?(manifest["accounts"])

    if valid, do: :ok, else: {:error, :invalid_helper_manifest}
  end

  defp schema(_manifest), do: {:error, :invalid_helper_manifest}

  defp artifact?(record, kind) when is_map(record) do
    valid_path = if kind == :bridge, do: record["path"] == "gao_helper_bridge", else: path?(record["path"])

    Enum.sort(Map.keys(record)) == ~w(gid mode path sha256 uid) and valid_path and
      hash?(record["sha256"]) and record["uid"] == 0 and Accounts.valid_id?(record["gid"]) and
      is_integer(record["mode"]) and record["mode"] in 0..0o7777 and
      band(record["mode"], 0o022) == 0 and band(record["mode"], 0o111) != 0
  end

  defp artifact?(_record, _kind), do: false

  defp daemon_record?(record) when is_map(record),
    do:
      Enum.sort(Map.keys(record)) == ~w(gid name uid) and is_binary(record["name"]) and
        byte_size(record["name"]) in 1..255 and Accounts.valid_id?(record["uid"]) and
        record["uid"] != 0 and Accounts.valid_id?(record["gid"])

  defp daemon_record?(_record), do: false

  defp files?(files) when is_map(files) and map_size(files) in 1..1024,
    do: Enum.all?(files, fn {path, hash} -> path?(path) and (is_nil(hash) or hash?(hash)) end)

  defp files?(_files), do: false

  defp directories?(directories) when is_map(directories) and map_size(directories) <= 64 do
    Enum.all?(directories, fn {path, names} ->
      path?(path) and
        (is_nil(names) or
           (is_list(names) and length(names) <= 1024 and names == Enum.sort(Enum.uniq(names)) and
              Enum.all?(names, fn name ->
                is_binary(name) and byte_size(name) in 1..255 and String.valid?(name) and
                  name not in [".", ".."] and not String.contains?(name, ["/", <<0>>])
              end)))
    end) and
      Enum.reduce(directories, 0, fn {_path, names}, count -> count + length(names || []) end) <=
        8192
  end

  defp directories?(_directories), do: false

  defp accounts?(accounts) when is_map(accounts) and map_size(accounts) in 1..1024 do
    Enum.all?(accounts, fn {name, record} ->
      is_binary(name) and byte_size(name) in 1..255 and is_map(record) and
        Enum.sort(Map.keys(record)) == ~w(gid groups uid) and
        Accounts.valid_id?(record["uid"]) and Accounts.valid_id?(record["gid"]) and
        is_list(record["groups"]) and length(record["groups"]) <= 65_536 and
        Enum.all?(record["groups"], &Accounts.valid_id?/1) and
        record["groups"] == Enum.sort(Enum.uniq(record["groups"]))
    end)
  end

  defp accounts?(_accounts), do: false

  defp paths?(paths, maximum),
    do: is_list(paths) and length(paths) <= maximum and Enum.all?(paths, &path?/1)

  defp path?(path) when is_binary(path),
    do:
      byte_size(path) in 1..4096 and String.valid?(path) and
        not String.contains?(path, <<0>>) and Path.type(path) == :absolute and
        Path.expand(path) == path and length(Path.split(path)) <= 128

  defp path?(_path), do: false
  defp hash?(hash) when is_binary(hash), do: Regex.match?(~r/\A[0-9a-f]{64}\z/, hash)
  defp hash?(_hash), do: false

  defp daemon(config, daemon, identity) do
    with %{uid: uid, gid: gid, real_uid: uid, real_gid: gid} <- identity,
         true <- uid == daemon["uid"] and gid == daemon["gid"] and config.daemon_uid == uid and
                   config.settings[:user] == uid,
         {:ok, %{uid: ^uid, gid: ^gid}} <- Accounts.bind_user(config.accounts, daemon["name"]) do
      :ok
    else
      _ -> {:error, :helper_daemon_identity_mismatch}
    end
  end

  defp captured(%Config{captures: %Capture{} = capture}) do
    with {:ok, files} <- captured_map(capture.files, & &1.sha256),
         {:ok, directories} <- captured_map(capture.directories, & &1.names) do
      {:ok, files, directories}
    end
  end

  defp captured(_config), do: {:error, :helper_capture_unavailable}

  defp captured_map(records, value) do
    Enum.reduce_while(records, {:ok, %{}}, fn
      {path, {:ok, record}}, {:ok, result} ->
        {:cont, {:ok, Map.put(result, path, value.(record))}}

      {path, {:error, %{reason: :enoent}}}, {:ok, result} ->
        {:cont, {:ok, Map.put(result, path, nil)}}

      _, _ ->
        {:halt, {:error, :helper_capture_unavailable}}
    end)
  end

  defp bound_accounts(config, daemon_name) do
    with {:ok, daemon} <- Accounts.bind_user(config.accounts, daemon_name),
         true <- Enum.all?(config.services.selected, fn {_name, entry} ->
           case Accounts.bind_user(config.accounts, entry.user) do
             {:ok, account} -> account == entry.account
             _ -> false
           end
         end) do
      records = [daemon | Enum.map(config.services.selected, fn {_name, entry} -> entry.account end)]

      {:ok,
       Map.new(records, fn record ->
         {record.name,
          %{"uid" => record.uid, "gid" => record.gid, "groups" => Enum.sort(record.groups)}}
       end)}
    else
      _ -> {:error, :helper_account_pairing_mismatch}
    end
  end

  defp account_sources(%{sources: %{passwd: passwd, group: group}}, files) do
    if Enum.all?([passwd, group], fn source ->
         is_binary(source[:file]) and hash?(source[:sha256]) and
           Map.get(files, source.file) == source.sha256
       end),
      do: :ok,
      else: {:error, :helper_account_sources_unavailable}
  end

  defp account_sources(_accounts, _files), do: {:error, :helper_account_sources_unavailable}

  defp installation(manifest) do
    with true <- manifest["entrypoint"]["mode"] in [0o4550, 0o4750],
         true <- manifest["entrypoint"]["gid"] == manifest["daemon"]["gid"],
         true <- manifest["entrypoint"]["sha256"] == manifest["wrapper_source"]["sha256"],
         {:ok, bridge} <- artifacts(manifest),
         {:ok, helper_path} <- bridge_binding(bridge),
         true <- helper_path == manifest["compiled_helper_path"],
         :ok <- files(manifest["files"]),
         :ok <- directories(manifest["directories"]) do
      :ok
    else
      false -> {:error, :helper_artifact_binding_mismatch}
      {:error, _reason} = failure -> failure
    end
  end

  @doc false
  # Deliberately bounded ELF32/ELF64 section-table reader. Extended indexes and
  # stripped section tables are unsupported package profiles, never guessed.
  def bridge_binding(<<127, "ELF", class, data, 1, _::binary>> = bytes)
      when class in [1, 2] and data in [1, 2] and byte_size(bytes) <= @artifact_bytes do
    endian = if data == 1, do: :little, else: :big
    {offset_position, word, entry_position, count_position, names_position, entry_size} =
      if class == 2, do: {40, 8, 58, 60, 62, 64}, else: {32, 4, 46, 48, 50, 40}

    with {:ok, offset} <- number(bytes, offset_position, word, endian),
         {:ok, ^entry_size} <- number(bytes, entry_position, 2, endian),
         {:ok, count} when count in 1..1024 <- number(bytes, count_position, 2, endian),
         {:ok, names_index} when names_index < count <- number(bytes, names_position, 2, endian),
         {:ok, table} <- part(bytes, offset, count * entry_size),
         {:ok, names_header} <- part(table, names_index * entry_size, entry_size),
         {:ok, names} <- section_bytes(bytes, names_header, class, endian),
         true <- byte_size(names) <= 65_536 do
      sections =
        for <<header::binary-size(entry_size) <- table>>,
            {:ok, name_offset} = number(header, 0, 4, endian),
            cstring(names, name_offset) == {:ok, ".gao_helper_binding"},
            do: header

      with [header] <- sections,
           {:ok, 1} <- number(header, 4, 4, endian),
           {:ok, flags} <- number(header, 8, word, endian),
           true <- band(flags, 3) == 2,
           {:ok, binding} <- section_bytes(bytes, header, class, endian),
           true <- byte_size(binding) in 1..4097,
           {:ok, path} <- cstring(binding, 0),
           true <- byte_size(path) + 1 == byte_size(binding),
           true <- path == "" or path?(path) do
        {:ok, path}
      else
        _ -> {:error, :invalid_bridge_binding_section}
      end
    else
      _ -> {:error, :invalid_bridge_elf}
    end
  end

  def bridge_binding(_bytes), do: {:error, :invalid_bridge_elf}

  defp section_bytes(bytes, header, class, endian) do
    {offset_position, size_position, word} = if class == 2, do: {24, 32, 8}, else: {16, 20, 4}

    with {:ok, offset} <- number(header, offset_position, word, endian),
         {:ok, size} <- number(header, size_position, word, endian),
         do: part(bytes, offset, size)
  end

  defp number(bytes, offset, size, endian) do
    with {:ok, value} <- part(bytes, offset, size),
      do: {:ok, :binary.decode_unsigned(value, endian)}
  end

  defp part(bytes, offset, size) when offset >= 0 and size >= 0 and offset + size <= byte_size(bytes),
    do: {:ok, binary_part(bytes, offset, size)}

  defp part(_bytes, _offset, _size), do: {:error, :invalid_bridge_elf}

  defp cstring(bytes, offset) when offset < byte_size(bytes) do
    tail = binary_part(bytes, offset, byte_size(bytes) - offset)
    case :binary.match(tail, <<0>>) do
      {length, 1} -> {:ok, binary_part(tail, 0, length)}
      :nomatch -> {:error, :invalid_bridge_elf}
    end
  end

  defp cstring(_bytes, _offset), do: {:error, :invalid_bridge_elf}

  defp artifacts(manifest) do
    Enum.reduce_while(@artifacts, {:ok, nil}, fn name, {:ok, bridge} ->
      record = manifest[name]
      path = if name == "bridge", do: bridge_path(), else: record["path"]

      case read_trusted(path, @artifact_bytes) do
        {:ok, bytes, stat} ->
          if digest(bytes) == record["sha256"] and stat.uid == record["uid"] and
               stat.gid == record["gid"] and band(stat.mode, 0o7777) == record["mode"] do
            {:cont, {:ok, if(name == "bridge", do: bytes, else: bridge)}}
          else
            {:halt, {:error, {:helper_artifact_mismatch, path}}}
          end

        {:error, _reason} = failure ->
          {:halt, failure}
      end
    end)
  end

  defp files(expected) do
    Enum.reduce_while(Enum.sort(expected), {:ok, 0}, fn {path, hash}, {:ok, total} ->
      case verify_file(path, hash, min(@file_bytes, @capture_bytes - total)) do
        {:ok, bytes} -> {:cont, {:ok, total + bytes}}
        {:error, _reason} = failure -> {:halt, failure}
      end
    end)
    |> case do
      {:ok, _total} -> :ok
      failure -> failure
    end
  end

  defp verify_file(path, nil, _limit), do: absent(path)

  defp verify_file(path, hash, limit) do
    with {:ok, bytes, _stat} <- read_trusted(path, limit),
         true <- digest(bytes) == hash do
      {:ok, byte_size(bytes)}
    else
      false -> {:error, {:helper_source_changed, path}}
      {:error, _reason} = failure -> failure
    end
  end

  defp directories(expected) do
    Enum.reduce_while(Enum.sort(expected), :ok, fn {path, names}, :ok ->
      result =
        if is_nil(names) do
          case absent(path) do
            {:ok, 0} -> :ok
            failure -> failure
          end
        else
          with {:ok, resolved, chain} <- resolve(path),
               {:ok, listing} <- Directory.list(resolved),
               {:ok, ^resolved, ^chain} <- resolve(path),
               true <- listing.names == names do
            :ok
          else
            _ -> {:error, {:helper_directory_changed, path}}
          end
        end

      if result == :ok, do: {:cont, :ok}, else: {:halt, result}
    end)
  end

  defp absent(path) do
    case resolve(path) do
      {:error, {:helper_path, ^path, :enoent}} -> {:ok, 0}
      _ -> {:error, {:helper_source_changed, path}}
    end
  end

  defp read_trusted(path, limit) do
    with {:ok, resolved, chain} <- resolve(path),
         {:ok, stat} <- File.stat(resolved, time: :posix),
         true <- stat.type == :regular and stat.size <= limit and protected?(stat),
         {:ok, file} <- :file.open(String.to_charlist(resolved), [:raw, :binary, :read]) do
      try do
        with {:ok, before} <- :file.read_file_info(file, time: :posix),
             true <- fingerprint(File.Stat.from_record(before)) == fingerprint(stat),
             {:ok, bytes} <- read_bytes(file, limit),
             true <- byte_size(bytes) == stat.size,
             {:ok, after_read} <- :file.read_file_info(file, time: :posix),
             true <- fingerprint(File.Stat.from_record(after_read)) == fingerprint(stat),
             {:ok, ^resolved, ^chain} <- resolve(path),
             {:ok, after_path} <- File.stat(resolved, time: :posix),
             true <- fingerprint(after_path) == fingerprint(stat) do
          {:ok, bytes, stat}
        else
          _ -> {:error, {:helper_file_changed, path}}
        end
      after
        :file.close(file)
      end
    else
      {:error, reason} -> {:error, {:helper_file_unavailable, path, reason}}
      false -> {:error, {:untrusted_helper_file, path}}
    end
  end

  defp read_bytes(file, limit) do
    case :file.read(file, limit + 1) do
      :eof -> {:ok, <<>>}
      {:ok, bytes} when byte_size(bytes) <= limit -> {:ok, bytes}
      _ -> {:error, :helper_file_byte_limit}
    end
  end

  defp resolve(path), do: resolve(path, path, 32, [])

  defp resolve(path, original, remaining, links) when remaining >= 0 do
    if path?(path) do
      result =
        Enum.reduce_while(Path.split(path), {:ok, "", []}, fn component, {:ok, prefix, chain} ->
          current = if prefix == "", do: component, else: Path.join(prefix, component)

          case File.lstat(current, time: :posix) do
            {:ok, %{type: :symlink, uid: 0} = stat} ->
              case File.read_link(current) do
                {:ok, target} ->
                  suffix = String.trim_leading(String.replace_prefix(path, current, ""), "/")
                  case link_target(target, current, suffix) do
                    {:ok, target} ->
                      {:halt, {:link, target, chain ++ [{current, fingerprint(stat)}]}}

                    :error ->
                      {:halt, {:error, {:untrusted_helper_symlink, current}}}
                  end

                {:error, reason} ->
                  {:halt, {:error, {:helper_path, original, reason}}}
              end

            {:ok, stat} ->
              if protected?(stat) and (current == path or stat.type == :directory) do
                {:cont, {:ok, current, chain ++ [{current, fingerprint(stat)}]}}
              else
                {:halt, {:error, {:untrusted_helper_path, current}}}
              end

            {:error, reason} ->
              {:halt, {:error, {:helper_path, original, reason}}}
          end
        end)

      case result do
        {:link, target, chain} -> resolve(target, original, remaining - 1, links ++ chain)
        {:ok, resolved, chain} -> {:ok, resolved, links ++ chain}
        failure -> failure
      end
    else
      {:error, :invalid_helper_path}
    end
  end

  defp resolve(_path, _original, _remaining, _links), do: {:error, :helper_symlink_limit}

  defp link_target(target, current, suffix) do
    # Lexically collapsing a/../b can disagree with kernel traversal if a is a
    # symlink. Refuse that unsupported spelling rather than verify another file.
    if byte_size(target) in 1..4096 and String.valid?(target) and
         not String.contains?(target, <<0>>) and
         Enum.all?(String.split(target, "/"), &(&1 not in [".", ".."])) do
      target = Path.expand(target, Path.dirname(current))
      {:ok, if(suffix == "", do: target, else: Path.join(target, suffix))}
    else
      :error
    end
  end

  defp protected?(%{uid: 0, mode: mode, type: type}) do
    band(mode, 0o022) == 0 or
      (type == :directory and band(mode, 0o1002) == 0o1000)
  end

  defp protected?(_stat), do: false

  defp fingerprint(stat),
    do: Map.take(stat, [:type, :size, :mode, :uid, :gid, :inode, :major_device, :minor_device, :mtime, :ctime])

  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp refusal(config, reason) do
    origins =
      Config.directive_origins(config, :setting, [:servicehelper, :servicedir, :user, :listen]) ++
        Enum.map(config.sources, &Map.take(&1, [:file, :line, :element, :include_chain]))

    {:error, %{reason: {:helper_binding, reason}, origins: Enum.uniq(origins)}}
  end
end
