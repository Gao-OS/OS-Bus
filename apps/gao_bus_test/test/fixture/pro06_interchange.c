/* Finite PRO-06 normal-value actor. No handle values or ancillary transfers. */
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CALLS 12
#define DEADLINE_MS 5000
static const char *control;
static guint methods;
static GMainLoop *loop;
static gint64 deadline;
static gboolean completed;

static void fail(const char *message) {
  g_printerr("PRO06: %s\n", message);
  exit(1);
}
static void checked_error(GError *error) {
  if (error) fail(error->message);
}
static char *quote(const char *text) {
  GString *out = g_string_new("\"");
  for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
    if (*p == '"' || *p == '\\') g_string_append_c(out, '\\');
    if (*p < 32) g_string_append_printf(out, "\\u%04x", *p);
    else g_string_append_c(out, *p);
  }
  g_string_append_c(out, '"');
  return g_string_free(out, FALSE);
}
static gboolean signalled(const char *phase) {
  char *path = g_build_filename(control, phase, NULL);
  struct stat info;
  gboolean found = lstat(path, &info) == 0;
  if (found && (!S_ISREG(info.st_mode) || info.st_uid != 0)) fail("invalid root control file");
  g_free(path);
  return found;
}
static void wait_phase(const char *phase) {
  gint64 end = g_get_monotonic_time() + (!strcmp(phase, "finish") ? 90000000 : 20000000);
  while (!signalled(phase)) {
    if (g_get_monotonic_time() >= end) fail("control deadline");
    g_poll(NULL, 0, 20);
  }
}
static void ready(const char *role, GDBusConnection *connection) {
  char *name = quote(g_dbus_connection_get_unique_name(connection));
  g_print("{\"event\":\"ready\",\"role\":\"%s\",\"unique_name\":%s,\"pid\":%ld,\"uid\":%ld,\"gid\":%ld}\n",
          role, name, (long)getpid(), (long)getuid(), (long)getgid());
  g_free(name);
  fflush(stdout);
}

typedef struct { GMainLoop *loop; GDBusConnection *connection; GError *error; GCancellable *cancel; } Connect;
static void connected(GObject *object, GAsyncResult *result, gpointer data) {
  (void)object;
  Connect *state = data;
  state->connection = g_dbus_connection_new_for_address_finish(result, &state->error);
  g_main_loop_quit(state->loop);
}
static gboolean cancel_connect(gpointer data) {
  g_cancellable_cancel(((Connect *)data)->cancel);
  return G_SOURCE_REMOVE;
}
static GDBusConnection *connect_bus(const char *address) {
  Connect state = {0};
  state.loop = g_main_loop_new(NULL, FALSE);
  state.cancel = g_cancellable_new();
  guint timeout = g_timeout_add(DEADLINE_MS, cancel_connect, &state);
  g_dbus_connection_new_for_address(address,
    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
    NULL, state.cancel, connected, &state);
  g_main_loop_run(state.loop);
  if (!g_cancellable_is_cancelled(state.cancel)) g_source_remove(timeout);
  checked_error(state.error);
  if (!state.connection) fail("no connection");
  g_dbus_connection_set_exit_on_close(state.connection, FALSE);
  g_object_unref(state.cancel);
  g_main_loop_unref(state.loop);
  return state.connection;
}

/* Constructors and expected text are deliberately separate corpus definitions. */
static GVariant *value(guint index) {
  GVariantBuilder b, c;
  switch (index) {
  case 0:
    g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b, "{sv}", "title", g_variant_new_string("Gao 高 UTF-8"));
    g_variant_builder_add(&b, "{sv}", "enabled", g_variant_new_boolean(TRUE));
    g_variant_builder_init(&c, G_VARIANT_TYPE("a(it)"));
    g_variant_builder_add(&c, "(it)", G_MININT32, (guint64)0);
    g_variant_builder_add(&c, "(it)", G_MAXINT32, G_MAXUINT64);
    g_variant_builder_add(&b, "{sv}", "items", g_variant_builder_end(&c));
    return g_variant_builder_end(&b);
  case 1:
    g_variant_builder_init(&b, G_VARIANT_TYPE("a(it)"));
    g_variant_builder_add(&b, "(it)", -1, (guint64)1);
    g_variant_builder_add(&b, "(it)", 0, G_MAXUINT64);
    return g_variant_builder_end(&b);
  case 2: {
    const guint8 bytes[] = {0, 127, 128, 255};
    g_variant_builder_init(&b, G_VARIANT_TYPE("aay"));
    g_variant_builder_add_value(&b, g_variant_new_array(G_VARIANT_TYPE_BYTE, NULL, 0));
    g_variant_builder_add_value(&b, g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes, 4, 1));
    return g_variant_new("(@ay@aay)", g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, bytes, 4, 1),
                         g_variant_builder_end(&b));
  }
  case 3:
    return g_variant_new("(ynqiuxtbdsog)", 255, -32768, 65535, G_MININT32, G_MAXUINT32,
      G_MININT64, G_MAXUINT64, TRUE, -1.25, "ordinary λ", "/org/foundation/Types", "a{sv}");
  case 4:
    g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b, "{sv}", "flag", g_variant_new_boolean(TRUE));
    g_variant_builder_init(&c, G_VARIANT_TYPE("au"));
    g_variant_builder_add(&c, "u", (guint32)0);
    g_variant_builder_add(&c, "u", G_MAXUINT32);
    g_variant_builder_add(&b, "{sv}", "numbers", g_variant_builder_end(&c));
    return g_variant_new_variant(g_variant_new("(s@a{sv})", "inside", g_variant_builder_end(&b)));
  case 5:
    return g_variant_new("(@aai@a{sv}@av)",
      g_variant_new_array(G_VARIANT_TYPE("ai"), NULL, 0),
      g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0),
      g_variant_new_array(G_VARIANT_TYPE_VARIANT, NULL, 0));
  default: fail("corpus index"); return NULL;
  }
}
static GVariant *expected(guint index) {
  static const char *types[] = {"a{sv}", "a(it)", "(ayaay)", "(ynqiuxtbdsog)", "v", "(aaia{sv}av)"};
  static const char *texts[] = {
    "{'title': <'Gao 高 UTF-8'>, 'enabled': <true>, 'items': <[(int32 -2147483648, uint64 0), (2147483647, 18446744073709551615)]>}",
    "[(-1, uint64 1), (0, 18446744073709551615)]",
    "([byte 0, 127, 128, 255], [@ay [], [byte 0, 127, 128, 255]])",
    "(byte 255, int16 -32768, uint16 65535, int32 -2147483648, uint32 4294967295, int64 -9223372036854775808, uint64 18446744073709551615, true, -1.25, 'ordinary λ', objectpath '/org/foundation/Types', signature 'a{sv}')",
    "<('inside', {'flag': <true>, 'numbers': <[uint32 0, 4294967295]>})>",
    "(@aai [], @a{sv} {}, @av [])"
  };
  GError *error = NULL;
  GVariant *result = g_variant_parse(G_VARIANT_TYPE(types[index]), texts[index], NULL, NULL, &error);
  checked_error(error);
  return g_variant_ref_sink(result);
}
static void method_call(GDBusConnection *connection, const char *sender, const char *path,
  const char *interface, const char *member, GVariant *parameters,
  GDBusMethodInvocation *invocation, gpointer data) {
  (void)connection; (void)sender; (void)path; (void)interface; (void)data;
  if (strcmp(member, "TypeRoundTrip") || !g_variant_is_of_type(parameters, G_VARIANT_TYPE("(v)")))
    fail("unexpected service call");
  methods++;
  if (methods > CALLS) fail("excess service calls");
  g_dbus_method_invocation_return_value(invocation, g_variant_ref(parameters));
}
static gboolean service_tick(gpointer data) {
  (void)data;
  if (signalled("finish")) {
    completed = TRUE;
    g_main_loop_quit(loop);
    return G_SOURCE_REMOVE;
  }
  if (g_get_monotonic_time() >= deadline) {
    g_main_loop_quit(loop);
    return G_SOURCE_REMOVE;
  }
  return G_SOURCE_CONTINUE;
}
static void service(GDBusConnection *connection) {
  const char *xml = "<node><interface name='org.foundation.Types'><method name='TypeRoundTrip'>"
    "<arg type='v' direction='in'/><arg type='v' direction='out'/></method></interface></node>";
  GError *error = NULL;
  GDBusNodeInfo *info = g_dbus_node_info_new_for_xml(xml, &error);
  checked_error(error);
  const GDBusInterfaceVTable vtable = {.method_call = method_call};
  guint registration = g_dbus_connection_register_object(connection, "/org/foundation/Types",
    info->interfaces[0], &vtable, NULL, NULL, &error);
  checked_error(error);
  if (!registration) fail("service registration");
  ready("service", connection);
  wait_phase("service.go");
  loop = g_main_loop_new(NULL, FALSE);
  deadline = g_get_monotonic_time() + 90000000;
  g_timeout_add(20, service_tick, NULL);
  g_main_loop_run(loop);
  if (!completed || methods != CALLS) fail("service completion count/deadline");
  g_print("{\"event\":\"service_complete\",\"method_count\":%u,\"expected_count\":%d}\n", methods, CALLS);
  g_dbus_connection_unregister_object(connection, registration);
  g_dbus_node_info_unref(info);
  g_main_loop_unref(loop);
}
static char *bus_string(GDBusConnection *connection, const char *member, GVariant *args) {
  GError *error = NULL;
  GVariant *reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus",
    "/org/freedesktop/DBus", "org.freedesktop.DBus", member, args, G_VARIANT_TYPE("(s)"),
    G_DBUS_CALL_FLAGS_NONE, DEADLINE_MS, NULL, &error);
  checked_error(error);
  char *text;
  g_variant_get(reply, "(s)", &text);
  g_variant_unref(reply);
  return text;
}
static void observer(GDBusConnection *connection) {
  const char *unique = g_dbus_connection_get_unique_name(connection);
  char *before_id = bus_string(connection, "GetId", NULL);
  char *before_owner = bus_string(connection, "GetNameOwner", g_variant_new("(s)", unique));
  if (strcmp(before_owner, unique)) fail("observer owner before");
  ready("observer", connection);
  wait_phase("observer.go");
  wait_phase("finish");
  char *after_id = bus_string(connection, "GetId", NULL);
  char *after_owner = bus_string(connection, "GetNameOwner", g_variant_new("(s)", unique));
  gboolean equal = !strcmp(before_id, after_id) && !strcmp(before_owner, after_owner);
  char *a = quote(before_id), *b = quote(after_id), *c = quote(before_owner), *d = quote(after_owner);
  g_print("{\"event\":\"observer_complete\",\"before_id\":%s,\"after_id\":%s,\"before_owner\":%s,\"after_owner\":%s,\"same_connection\":true,\"equal\":%s,\"pid\":%ld,\"uid\":%ld,\"gid\":%ld}\n",
    a, b, c, d, equal ? "true" : "false", (long)getpid(), (long)getuid(), (long)getgid());
  g_free(a); g_free(b); g_free(c); g_free(d);
  g_free(before_id); g_free(after_id); g_free(before_owner); g_free(after_owner);
  if (!equal) fail("observer continuity");
}
static void client(GDBusConnection *connection, const char *destination) {
  if (!g_dbus_is_unique_name(destination)) fail("destination must be registered unique name");
  ready("client", connection);
  wait_phase("client.go");
  guint count = 0;
  const GDBusMessageByteOrder orders[] = {G_DBUS_MESSAGE_BYTE_ORDER_LITTLE_ENDIAN, G_DBUS_MESSAGE_BYTE_ORDER_BIG_ENDIAN};
  for (guint order = 0; order < 2; order++) for (guint index = 0; index < 6; index++) {
    GError *error = NULL;
    GVariant *sent = g_variant_ref_sink(value(index));
    GVariant *want = expected(index);
    if (!g_variant_equal(sent, want)) fail("constructor differs from independent expectation");
    GDBusMessage *message = g_dbus_message_new_method_call(destination, "/org/foundation/Types",
      "org.foundation.Types", "TypeRoundTrip");
    g_dbus_message_set_body(message, g_variant_new("(v)", sent));
    g_dbus_message_set_byte_order(message, orders[order]);
    g_dbus_message_set_serial(message, count + 100);
    gsize length = 0;
    guchar *blob = g_dbus_message_to_blob(message, &length, G_DBUS_CAPABILITY_FLAGS_NONE, &error);
    checked_error(error);
    if (!blob || length < 16 || blob[0] != (guchar)orders[order] || g_dbus_message_get_num_unix_fds(message))
      fail("outgoing serialization marker or descriptor count");
    char outgoing = blob[0];
    g_free(blob);
    GDBusMessage *reply = g_dbus_connection_send_message_with_reply_sync(connection, message,
      G_DBUS_SEND_MESSAGE_FLAGS_NONE, DEADLINE_MS, NULL, NULL, &error);
    checked_error(error);
    if (!reply || g_dbus_message_get_message_type(reply) != G_DBUS_MESSAGE_TYPE_METHOD_RETURN ||
        g_dbus_message_get_num_unix_fds(reply)) fail("unexpected reply");
    GVariant *body = g_dbus_message_get_body(reply);
    if (!body || !g_variant_is_of_type(body, G_VARIANT_TYPE("(v)"))) fail("reply signature");
    GVariant *wrapped = g_variant_get_child_value(body, 0);
    GVariant *actual = g_variant_get_variant(wrapped);
    gboolean equal = g_variant_equal(want, actual);
    char *expected_text = g_variant_print(want, TRUE), *actual_text = g_variant_print(actual, TRUE);
    char *expected_json = quote(expected_text), *actual_json = quote(actual_text);
    g_print("{\"event\":\"case\",\"index\":%u,\"endian\":\"%s\",\"signature\":\"%s\",\"expected\":%s,\"actual\":%s,\"semantic_equal\":%s,\"outgoing_first_byte\":%u,\"reply_first_byte\":%u,\"unix_fds\":0}\n",
      index, order == 0 ? "little" : "big", g_variant_get_type_string(want), expected_json, actual_json,
      equal ? "true" : "false", (unsigned char)outgoing, (unsigned char)g_dbus_message_get_byte_order(reply));
    fflush(stdout);
    g_free(expected_text); g_free(actual_text); g_free(expected_json); g_free(actual_json);
    g_variant_unref(actual); g_variant_unref(wrapped); g_variant_unref(sent); g_variant_unref(want);
    g_object_unref(message); g_object_unref(reply);
    if (!equal) fail("semantic inequality");
    count++;
  }
  if (count != CALLS) fail("client count");
  g_print("{\"event\":\"client_complete\",\"method_count\":%u,\"expected_count\":%d}\n", count, CALLS);
}
int main(int argc, char **argv) {
  if (argc < 4) fail("usage: service|observer ADDRESS CONTROL_DIR; client ADDRESS DESTINATION CONTROL_DIR");
  gboolean is_client = !strcmp(argv[1], "client");
  if (argc != (is_client ? 5 : 4)) fail("role arguments");
  if (strcmp(argv[2], "unix:path=/run/osbus-security/sec01-complete/reference/bus") &&
      strcmp(argv[2], "unix:path=/run/osbus-security/sec01-complete/gao_bus/bus")) fail("private address required");
  char *marker = NULL;
  gsize size;
  struct stat info;
  if (lstat("/etc/osbus-security-guest", &info) || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
      (info.st_mode & 0777) != 0444 || !g_file_get_contents("/etc/osbus-security-guest", &marker, &size, NULL) ||
      strcmp(marker, "isolated-vm\n")) fail("isolated VM marker required");
  g_free(marker);
  uid_t uid = !strcmp(argv[1], "observer") ? 1100 : 1101;
  if (getuid() != uid || geteuid() != uid || getgid() != uid || getegid() != uid) fail("real UID/GID required");
  control = argv[is_client ? 4 : 3];
  char *socket_path = g_strdup(argv[2] + strlen("unix:path="));
  char *directory = g_path_get_dirname(socket_path);
  char *required = g_build_filename(directory, "pro06-control", NULL);
  if (strcmp(control, required) || lstat(control, &info) || !S_ISDIR(info.st_mode) || info.st_uid != 0 ||
      (info.st_mode & 0777) != 0755) fail("private root control directory required");
  g_free(socket_path); g_free(directory); g_free(required);
  GDBusConnection *connection = connect_bus(argv[2]);
  if (!strcmp(argv[1], "service")) service(connection);
  else if (!strcmp(argv[1], "observer")) observer(connection);
  else if (is_client) client(connection, argv[3]);
  else fail("unknown role");
  GError *error = NULL;
  if (!g_dbus_connection_close_sync(connection, NULL, &error)) checked_error(error);
  g_object_unref(connection);
  return 0;
}
