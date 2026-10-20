defmodule GaoBus.Config.Accounts do
  @moduledoc """
  Finite local account-database snapshot for compatibility policy and bootstrap.
  No NSS/network lookup or subprocess is used. Membership includes passwd primary
  groups and group-file memberships; it is distinct from a process's kernel groups.
  A caller may instead supply an independently trusted, validated snapshot.
  Named binding records preserve primary GIDs separately from memberships. Local
  sources identify captured bytes and observed read metadata, not an atomic read
  across passwd/group or protection against changes invisible to that metadata.
  """
  alias GaoBus.Config.Capture

  @max_bytes 1_048_576
  @max_accounts 65_536

  def load(options \\ []) do
    case load_captured(options, Capture.new()) do
      {:ok, snapshot, _capture} -> {:ok, snapshot}
      failure -> failure
    end
  end

  def load_captured(options, capture) do
    case Keyword.fetch(options, :accounts) do
      {:ok, snapshot} ->
        case validate(snapshot) do
          {:ok, snapshot} -> {:ok, snapshot, capture}
          failure -> failure
        end

      :error ->
        local(
          Keyword.get(options, :passwd, "/etc/passwd"),
          Keyword.get(options, :group, "/etc/group"),
          capture
        )
    end
  end

  def group_ids(%{users: users, memberships: memberships}, uid) do
    if uid in Map.values(users) do
      case Map.fetch(memberships, uid) do
        {:ok, gids} -> {:ok, gids}
        :error -> {:error, :account_groups_unavailable}
      end
    else
      {:error, :unknown_account_uid}
    end
  end

  def resolve(snapshot, kind, value) when kind in [:users, :groups] do
    case Integer.parse(value) do
      {id, ""} when id >= 0 and id < 0xFFFFFFFF ->
        {:ok, id}

      _ ->
        case Map.fetch(Map.fetch!(snapshot, kind), value) do
          {:ok, id} -> {:ok, id}
          :error -> {:error, {:unknown_account, kind, value}}
        end
    end
  end

  def valid_id?(id), do: is_integer(id) and id >= 0 and id < 0xFFFFFFFF

  def bind_user(snapshot, value) when is_binary(value) do
    case Integer.parse(value) do
      {uid, ""} when uid >= 0 and uid < 0xFFFFFFFF ->
        names = for {name, ^uid} <- snapshot.users, do: name

        case names do
          [] -> {:error, :unknown_account_uid}
          [name] -> binding(snapshot, name)
          _aliases -> {:error, :ambiguous_account_uid}
        end

      _ ->
        if Map.has_key?(snapshot.users, value),
          do: binding(snapshot, value),
          else: {:error, {:unknown_account, :users, value}}
    end
  end

  defp binding(snapshot, name) do
    case Map.fetch(Map.get(snapshot, :user_records, %{}), name) do
      {:ok, record} -> {:ok, record}
      :error -> {:error, :account_identity_unavailable}
    end
  end

  defp validate(%{users: users, groups: groups, memberships: memberships} = snapshot)
       when is_map(users) and is_map(groups) and is_map(memberships) do
    valid =
      map_size(users) <= @max_accounts and map_size(groups) <= @max_accounts and
        map_size(memberships) <= @max_accounts and
        Enum.all?([users, groups], fn accounts ->
          Enum.all?(accounts, fn {name, id} -> valid_name?(name) and valid_id?(id) end)
        end) and
        Enum.all?(memberships, fn {uid, gids} ->
          valid_id?(uid) and is_list(gids) and length(gids) <= @max_accounts and
            Enum.all?(gids, &valid_id?/1)
        end) and valid_records?(snapshot)

    if valid do
      normalized = %{
        snapshot
        | memberships:
            Map.new(memberships, fn {uid, gids} -> {uid, Enum.sort(Enum.uniq(gids))} end)
      }

      normalized =
        if Map.has_key?(snapshot, :user_records) do
          Map.put(
            normalized,
            :user_records,
            Map.new(snapshot.user_records, fn {name, record} ->
              {name, %{record | groups: Enum.sort(Enum.uniq(record.groups))}}
            end)
          )
        else
          normalized
        end

      {:ok, normalized}
    else
      error("<accounts>", 1, :invalid_account_snapshot)
    end
  end

  defp validate(_snapshot), do: error("<accounts>", 1, :invalid_account_snapshot)

  defp valid_records?(snapshot) do
    case Map.fetch(snapshot, :user_records) do
      :error ->
        true

      {:ok, records} when is_map(records) and map_size(records) <= @max_accounts ->
        Enum.all?(records, fn {name, record} -> valid_record?(name, record, snapshot) end)

      _ ->
        false
    end
  end

  defp valid_record?(
         name,
         %{name: name, uid: uid, gid: gid, groups: gids, provenance: origin},
         snapshot
       ) do
    valid_name?(name) and valid_id?(uid) and valid_id?(gid) and
      Map.get(snapshot.users, name) == uid and is_list(gids) and
      length(gids) <= @max_accounts and Enum.all?(gids, &valid_id?/1) and gid in gids and
      Map.has_key?(snapshot.memberships, uid) and
      MapSet.subset?(MapSet.new(gids), MapSet.new(snapshot.memberships[uid])) and
      valid_origin?(origin)
  end

  defp valid_record?(_name, _record, _snapshot), do: false

  defp valid_origin?(nil), do: true

  defp valid_origin?(%{file: file, line: line}),
    do:
      is_binary(file) and byte_size(file) in 1..4096 and String.valid?(file) and
        is_integer(line) and line in 1..(@max_bytes + 1)

  defp valid_origin?(_origin), do: false

  defp local(passwd, group, capture) do
    with {:ok, users, passwd_source, capture} <- lines(passwd, &passwd_entry/1, capture),
         {:ok, groups, group_source, capture} <- lines(group, &group_entry/1, capture) do
      records =
        Map.new(users, fn {{name, uid, gid}, line} ->
          {name,
           %{
             name: name,
             uid: uid,
             gid: gid,
             groups: [gid],
             provenance: %{file: passwd_source.file, line: line}
           }}
        end)

      records =
        Enum.reduce(groups, records, fn {{_name, gid, members}, _line}, acc ->
          Enum.reduce(members, acc, fn name, acc ->
            case Map.fetch(acc, name) do
              {:ok, record} -> Map.put(acc, name, %{record | groups: [gid | record.groups]})
              :error -> acc
            end
          end)
        end)

      memberships =
        Enum.reduce(records, %{}, fn {_name, record}, acc ->
          Map.update(acc, record.uid, record.groups, &(record.groups ++ &1))
        end)

      case validate(%{
             users: Map.new(records, fn {name, record} -> {name, record.uid} end),
             groups: Map.new(groups, fn {{name, gid, _}, _line} -> {name, gid} end),
             memberships: memberships,
             user_records: records,
             sources: %{passwd: passwd_source, group: group_source}
           }) do
        {:ok, snapshot} -> {:ok, snapshot, capture}
        failure -> failure
      end
    end
  end

  defp lines(path, parser, capture) do
    case Capture.read(capture, path, @max_bytes) do
      {:ok, record, capture} ->
        with {:ok, entries} <- parse_lines(record.bytes, record.path, parser) do
          source = %{
            kind: :local_file,
            file: record.path,
            bytes: record.bytes_read,
            sha256: record.sha256,
            identity: record.identity.before,
            read_identity: record.identity,
            directory: record.directory,
            syscall_attempts: record.syscall_attempts,
            read_attempts: record.read_attempts
          }

          {:ok, entries, source, capture}
        end

      {:error, failure, _capture} ->
        reason =
          case failure.reason do
            :file_byte_limit -> :account_file_too_large
            reason when reason in [:file_changed, :directory_changed] -> :account_file_changed
            reason -> reason
          end

        error(failure.path, 1, reason)
    end
  end

  defp parse_lines(bytes, path, parser) do
    if String.valid?(bytes),
      do: parse_valid_lines(bytes, path, parser),
      else: error(path, 1, :invalid_encoding)
  end

  defp parse_valid_lines(bytes, path, parser) do
    bytes
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce_while({:ok, [], MapSet.new()}, fn {text, line}, {:ok, entries, names} ->
      if text == "" or String.starts_with?(text, "#") do
        {:cont, {:ok, entries, names}}
      else
        case parser.(text) do
          {:ok, entry} ->
            name = elem(entry, 0)

            if MapSet.member?(names, name) or MapSet.size(names) >= @max_accounts,
              do: {:halt, error(path, line, :duplicate_or_excess_accounts)},
              else: {:cont, {:ok, [{entry, line} | entries], MapSet.put(names, name)}}

          :error ->
            {:halt, error(path, line, :invalid_account_entry)}
        end
      end
    end)
    |> case do
      {:ok, entries, _names} -> {:ok, Enum.reverse(entries)}
      error -> error
    end
  end

  defp passwd_entry(text) do
    case String.split(text, ":") do
      [name, _password, uid, gid, _gecos, _home, _shell] ->
        with true <- valid_name?(name),
             {:ok, uid} <- number(uid),
             {:ok, gid} <- number(gid),
             do: {:ok, {name, uid, gid}},
             else: (_ -> :error)

      _ ->
        :error
    end
  end

  defp group_entry(text) do
    case String.split(text, ":") do
      [name, _password, gid, members] ->
        members = String.split(members, ",", trim: true)

        with true <- valid_name?(name),
             {:ok, gid} <- number(gid),
             true <- Enum.all?(members, &valid_name?/1),
             do: {:ok, {name, gid, members}},
             else: (_ -> :error)

      _ ->
        :error
    end
  end

  defp number(text) do
    case Integer.parse(text) do
      {id, ""} when id >= 0 and id < 0xFFFFFFFF -> {:ok, id}
      _ -> :error
    end
  end

  defp valid_name?(name),
    do:
      is_binary(name) and byte_size(name) in 1..255 and String.valid?(name) and
        Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_.-]*\$?\z/, name)

  defp error(file, line, reason),
    do: {:error, %{file: file, line: line, element: "accounts", reason: reason}}
end
