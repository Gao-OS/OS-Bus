defmodule ExDBus.Wire.TypesTest do
  use ExUnit.Case
  alias ExDBus.Wire.Types

  doctest Types

  describe "parse_signature/1" do
    test "parses simple types" do
      assert {:ok, :byte} = Types.parse_signature("y")
      assert {:ok, :boolean} = Types.parse_signature("b")
      assert {:ok, :int32} = Types.parse_signature("i")
      assert {:ok, :string} = Types.parse_signature("s")
      assert {:ok, :double} = Types.parse_signature("d")
      assert {:ok, :object_path} = Types.parse_signature("o")
      assert {:ok, :signature} = Types.parse_signature("g")
    end

    test "parses array types" do
      assert {:ok, {:array, :int32}} = Types.parse_signature("ai")
      assert {:ok, {:array, :string}} = Types.parse_signature("as")
      assert {:ok, {:array, {:array, :int32}}} = Types.parse_signature("aai")
    end

    test "parses struct types" do
      assert {:ok, {:struct, [:int32]}} = Types.parse_signature("(i)")
      assert {:ok, {:struct, [:int32, :string, :int32]}} = Types.parse_signature("(isi)")
      assert {:ok, {:struct, [:string, {:array, :int32}]}} = Types.parse_signature("(sai)")
    end

    test "rejects dict entry types outside arrays" do
      assert {:error, :dict_entry_outside_array} = Types.parse_signature("{sv}")
      assert {:error, :dict_entry_outside_array} = Types.parse_signature("{si}")
    end

    test "parses array of dict entries (common pattern)" do
      assert {:ok, {:array, {:dict_entry, :string, :variant}}} =
               Types.parse_signature("a{sv}")
    end

    test "parses variant" do
      assert {:ok, :variant} = Types.parse_signature("v")
    end

    test "rejects invalid signatures" do
      assert {:error, _} = Types.parse_signature("z")
      assert {:error, _} = Types.parse_signature("")
      assert {:error, _} = Types.parse_signature("(i")
      assert {:error, _} = Types.parse_signature("ai extra")
    end
  end

  describe "serialize_signature/1" do
    test "serializes simple types back" do
      assert "y" = Types.serialize_signature(:byte)
      assert "b" = Types.serialize_signature(:boolean)
      assert "i" = Types.serialize_signature(:int32)
      assert "s" = Types.serialize_signature(:string)
    end

    test "serializes container types" do
      assert "ai" = Types.serialize_signature({:array, :int32})
      assert "as" = Types.serialize_signature({:array, :string})
      assert "a{sv}" = Types.serialize_signature({:array, {:dict_entry, :string, :variant}})
    end

    test "serializes struct types" do
      assert "(i)" = Types.serialize_signature({:struct, [:int32]})
      assert "(isi)" = Types.serialize_signature({:struct, [:int32, :string, :int32]})
    end

    test "roundtrips parse → serialize → parse" do
      signatures = [
        "y",
        "i",
        "s",
        "as",
        "a{sv}",
        "(isi)",
        "(sai)"
      ]

      for sig <- signatures do
        {:ok, type} = Types.parse_signature(sig)
        serialized = Types.serialize_signature(type)
        {:ok, reparsed} = Types.parse_signature(serialized)
        assert type == reparsed, "Roundtrip failed for #{sig}"
      end
    end
  end

  describe "alignment/1" do
    test "basic type alignments" do
      assert 1 = Types.alignment(:byte)
      assert 4 = Types.alignment(:boolean)
      assert 2 = Types.alignment(:int16)
      assert 4 = Types.alignment(:int32)
      assert 8 = Types.alignment(:int64)
      assert 8 = Types.alignment(:double)
      assert 4 = Types.alignment(:string)
    end

    test "container type alignments" do
      assert 4 = Types.alignment({:array, :int32})
      assert 8 = Types.alignment({:struct, [:int32, :string]})
      assert 8 = Types.alignment({:dict_entry, :string, :int32})
      assert 1 = Types.alignment(:variant)
      assert 1 = Types.alignment(:signature)
    end
  end

  describe "valid?/2" do
    test "validates basic types" do
      assert Types.valid?(:byte, 0)
      assert Types.valid?(:byte, 255)
      refute Types.valid?(:byte, 256)
      refute Types.valid?(:byte, -1)

      assert Types.valid?(:boolean, true)
      assert Types.valid?(:boolean, false)
      refute Types.valid?(:boolean, "true")

      assert Types.valid?(:int32, 0)
      assert Types.valid?(:int32, -2_147_483_648)
      assert Types.valid?(:int32, 2_147_483_647)
      refute Types.valid?(:int32, 2_147_483_648)

      assert Types.valid?(:uint32, 0)
      assert Types.valid?(:uint32, 4_294_967_295)
      refute Types.valid?(:uint32, -1)
    end

    test "validates strings" do
      assert Types.valid?(:string, "")
      assert Types.valid?(:string, "hello")
      refute Types.valid?(:string, :atom)

      assert Types.valid?(:object_path, "/")
      assert Types.valid?(:object_path, "/org/freedesktop/DBus")
      refute Types.valid?(:object_path, "/path-with-dash")
      refute Types.valid?(:object_path, "relative/path")
    end

    test "validates containers" do
      assert Types.valid?({:array, :int32}, [])
      assert Types.valid?({:array, :int32}, [1, 2, 3])
      refute Types.valid?({:array, :int32}, "not a list")

      assert Types.valid?({:struct, [:int32, :string]}, {1, "hello"})
      refute Types.valid?({:struct, [:int32]}, "not a tuple")

      assert Types.valid?(:variant, {"i", 42})
      refute Types.valid?(:variant, {"i"})
    end
  end
end
