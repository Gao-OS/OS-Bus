/* Independent D-Bus wire oracle; never opens a bus or socket.
 * Generate with GLib 2.86.3:
 * cc -D_GNU_SOURCE glib_wire_corpus.c $(pkg-config --cflags --libs gio-2.0) -o /tmp/glib_wire_corpus
 * /tmp/glib_wire_corpus > glib_wire_corpus.txt
 */
#include <gio/gio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static GVariant *nested_body(void) {
  GVariant *entries[] = {
    g_variant_new_dict_entry(g_variant_new_string("Enabled"), g_variant_new_variant(g_variant_new_boolean(TRUE))),
    g_variant_new_dict_entry(g_variant_new_string("Count"), g_variant_new_variant(g_variant_new_uint32(42))),
    g_variant_new_dict_entry(g_variant_new_string("Object"), g_variant_new_variant(g_variant_new_object_path("/test")))
  };
  GVariant *structs[] = { g_variant_new("(xt)", (gint64)-7, (guint64)UINT64_MAX),
                         g_variant_new("(xt)", (gint64)0, (guint64)1) };
  const guint8 bytes[] = { 0, 127, 255 };
  GVariant *values[] = {
    g_variant_new_array(G_VARIANT_TYPE("{sv}"), entries, 3),
    g_variant_new_array(G_VARIANT_TYPE("(xt)"), structs, 2),
    g_variant_new_variant(g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes, 3, sizeof(guint8))),
    g_variant_new_array(G_VARIANT_TYPE_UINT64, NULL, 0),
    g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0),
    g_variant_new_string("UTF-8: \xc3\xa9 \xef\xb7\x90 \xef\xbf\xbe"),
    g_variant_new_signature("a{sv}"),
    g_variant_new_handle(3),
    g_variant_new_double(-0.0)
  };
  return g_variant_new_tuple(values, G_N_ELEMENTS(values));
}

static GVariant *nonfinite_body(void) {
  const uint64_t patterns[] = { UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
                               UINT64_C(0x7ff8000000000001), UINT64_C(0xfff0000000000042) };
  GVariant *values[G_N_ELEMENTS(patterns)];
  for (gsize i = 0; i < G_N_ELEMENTS(patterns); i++) {
    double value;
    memcpy(&value, &patterns[i], sizeof(value));
    values[i] = g_variant_new_double(value);
  }
  return g_variant_new_tuple(values, G_N_ELEMENTS(values));
}

static void emit(const char *name, GVariant *body, GDBusMessageByteOrder order) {
  GDBusMessage *message = g_dbus_message_new_method_call("org.foundation.Corpus", "/test",
                                                       "org.foundation.Corpus", "Probe");
  GError *error = NULL;
  gsize size = 0;
  g_dbus_message_set_serial(message, 42);
  g_dbus_message_set_sender(message, ":1.42");
  g_dbus_message_set_byte_order(message, order);
  g_dbus_message_set_body(message, body);
  if (strcmp(name, "nested") == 0) {
    GUnixFDList *fds = g_unix_fd_list_new();
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) g_error("open /dev/null failed");
    for (int i = 0; i < 4; i++) {
      if (g_unix_fd_list_append(fds, fd, &error) < 0) g_error("append FD failed: %s", error->message);
    }
    close(fd);
    g_dbus_message_set_unix_fd_list(message, fds);
    g_dbus_message_set_num_unix_fds(message, 4);
    g_object_unref(fds);
  }
  guchar *blob = g_dbus_message_to_blob(message, &size, G_DBUS_CAPABILITY_FLAGS_UNIX_FD_PASSING, &error);
  if (blob == NULL) g_error("marshal failed: %s", error->message);
  printf("%s %s ", name, order == G_DBUS_MESSAGE_BYTE_ORDER_LITTLE_ENDIAN ? "little" : "big");
  for (gsize i = 0; i < size; i++) printf("%02x", blob[i]);
  putchar('\n');
  g_free(blob);
  g_object_unref(message);
}

int main(void) {
  printf("# GLib %u.%u.%u independent g_dbus_message_to_blob corpus\n", glib_major_version,
         glib_minor_version, glib_micro_version);
  emit("nested", nested_body(), G_DBUS_MESSAGE_BYTE_ORDER_LITTLE_ENDIAN);
  emit("nested", nested_body(), G_DBUS_MESSAGE_BYTE_ORDER_BIG_ENDIAN);
  emit("nonfinite", nonfinite_body(), G_DBUS_MESSAGE_BYTE_ORDER_LITTLE_ENDIAN);
  emit("nonfinite", nonfinite_body(), G_DBUS_MESSAGE_BYTE_ORDER_BIG_ENDIAN);
  return 0;
}
