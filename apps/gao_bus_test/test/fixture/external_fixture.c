/*
 * external_fixture.c — GLib/GDBus fixture service for E2E testing.
 *
 * Registers com.test.ExternalFixture on a given D-Bus session bus and
 * exports Echo, TypeRoundTrip, AlwaysFail, SlowEcho, EmitTestSignal
 * methods plus a TestSignal signal and CurrentValue property.
 *
 * Usage: external_fixture [--bus-address ADDRESS]
 *
 * Prints "READY\n" to stdout after name acquisition so the test harness
 * can synchronize. Exits cleanly on SIGTERM.
 */

#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static GDBusNodeInfo *introspection_data = NULL;
static GMainLoop *loop = NULL;
static gchar *current_value = NULL;
static GDBusConnection *the_connection = NULL;
static const gchar *object_path = "/com/test/ExternalFixture";

static const gchar introspection_xml[] =
  "<node>"
  "  <interface name='com.test.ExternalFixture'>"
  "    <method name='Echo'>"
  "      <arg direction='in' name='input' type='s'/>"
  "      <arg direction='out' name='output' type='s'/>"
  "    </method>"
  "    <method name='ReadAndReturnFD'>"
  "      <arg direction='in' name='resource' type='h'/>"
  "      <arg direction='out' name='resource' type='h'/>"
  "      <arg direction='out' name='contents' type='s'/>"
  "    </method>"
  "    <method name='TypeRoundTrip'>"
  "      <arg direction='in' name='input' type='v'/>"
  "      <arg direction='out' name='output' type='v'/>"
  "    </method>"
  "    <method name='AlwaysFail'>"
  "      <arg direction='in' name='input' type='s'/>"
  "    </method>"
  "    <method name='SlowEcho'>"
  "      <arg direction='in' name='delay_ms' type='u'/>"
  "      <arg direction='in' name='input' type='s'/>"
  "      <arg direction='out' name='output' type='s'/>"
  "    </method>"
  "    <method name='EmitTestSignal'>"
  "      <arg direction='in' name='payload' type='s'/>"
  "    </method>"
  "    <signal name='TestSignal'>"
  "      <arg name='payload' type='s'/>"
  "    </signal>"
  "    <property name='CurrentValue' type='s' access='readwrite'/>"
  "  </interface>"
  "</node>";

/* SlowEcho callback data */
typedef struct {
  GDBusMethodInvocation *invocation;
  gchar *input;
} SlowEchoData;

static gboolean slow_echo_reply(gpointer user_data)
{
  SlowEchoData *data = (SlowEchoData *)user_data;
  g_dbus_method_invocation_return_value(data->invocation,
    g_variant_new("(s)", data->input));
  g_free(data->input);
  g_free(data);
  return G_SOURCE_REMOVE;
}

static void handle_method_call(GDBusConnection *connection,
                               const gchar *sender,
                               const gchar *obj_path,
                               const gchar *interface_name,
                               const gchar *method_name,
                               GVariant *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer user_data)
{
  (void)connection; (void)sender; (void)obj_path;
  (void)interface_name; (void)user_data;

  if (g_strcmp0(method_name, "Echo") == 0) {
    const gchar *input;
    g_variant_get(parameters, "(&s)", &input);
    g_dbus_method_invocation_return_value(invocation,
      g_variant_new("(s)", input));
  }
  else if (g_strcmp0(method_name, "TypeRoundTrip") == 0) {
    GVariant *variant;
    g_variant_get(parameters, "(v)", &variant);
    g_dbus_method_invocation_return_value(invocation,
      g_variant_new("(v)", variant));
    g_variant_unref(variant);
  }
  else if (g_strcmp0(method_name, "ReadAndReturnFD") == 0) {
    gint32 index;
    GError *error = NULL;
    g_variant_get(parameters, "(h)", &index);
    GUnixFDList *incoming = g_dbus_message_get_unix_fd_list(
      g_dbus_method_invocation_get_message(invocation));
    gint fd = incoming ? g_unix_fd_list_get(incoming, index, &error) : -1;
    gchar contents[128];
    ssize_t length = fd < 0 ? -1 : pread(fd, contents, sizeof(contents) - 1, 0);
    if (length < 0 || !g_utf8_validate(contents, length, NULL)) {
      if (fd >= 0) close(fd);
      g_clear_error(&error);
      g_dbus_method_invocation_return_dbus_error(invocation,
        "org.freedesktop.DBus.Error.InvalidArgs", "Expected a readable UTF-8 fixture file");
      return;
    }
    contents[length] = '\0';
    GUnixFDList *outgoing = g_unix_fd_list_new_from_array(&fd, 1);
    g_dbus_method_invocation_return_value_with_unix_fd_list(invocation,
      g_variant_new("(hs)", 0, contents), outgoing);
    g_object_unref(outgoing);
  }
  else if (g_strcmp0(method_name, "AlwaysFail") == 0) {
    g_dbus_method_invocation_return_dbus_error(invocation,
      "org.freedesktop.DBus.Error.Failed",
      "This method always fails");
  }
  else if (g_strcmp0(method_name, "SlowEcho") == 0) {
    guint32 delay_ms;
    const gchar *input;
    g_variant_get(parameters, "(u&s)", &delay_ms, &input);

    SlowEchoData *data = g_new(SlowEchoData, 1);
    data->invocation = invocation;
    data->input = g_strdup(input);

    g_timeout_add(delay_ms, slow_echo_reply, data);
  }
  else if (g_strcmp0(method_name, "EmitTestSignal") == 0) {
    const gchar *payload;
    g_variant_get(parameters, "(&s)", &payload);

    GError *error = NULL;
    g_dbus_connection_emit_signal(the_connection,
      NULL, /* broadcast */
      object_path,
      "com.test.ExternalFixture",
      "TestSignal",
      g_variant_new("(s)", payload),
      &error);

    if (error) {
      g_dbus_method_invocation_return_gerror(invocation, error);
      g_error_free(error);
    } else {
      g_dbus_method_invocation_return_value(invocation, NULL);
    }
  }
  else {
    g_dbus_method_invocation_return_dbus_error(invocation,
      "org.freedesktop.DBus.Error.UnknownMethod",
      "Unknown method");
  }
}

static GVariant *handle_get_property(GDBusConnection *connection,
                                     const gchar *sender,
                                     const gchar *obj_path,
                                     const gchar *interface_name,
                                     const gchar *property_name,
                                     GError **error,
                                     gpointer user_data)
{
  (void)connection; (void)sender; (void)obj_path;
  (void)interface_name; (void)user_data;

  if (g_strcmp0(property_name, "CurrentValue") == 0) {
    return g_variant_new_string(current_value ? current_value : "");
  }

  g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
    "Unknown property: %s", property_name);
  return NULL;
}

static gboolean handle_set_property(GDBusConnection *connection,
                                    const gchar *sender,
                                    const gchar *obj_path,
                                    const gchar *interface_name,
                                    const gchar *property_name,
                                    GVariant *value,
                                    GError **error,
                                    gpointer user_data)
{
  (void)connection; (void)sender; (void)obj_path;
  (void)interface_name; (void)user_data;

  if (g_strcmp0(property_name, "CurrentValue") == 0) {
    g_free(current_value);
    current_value = g_variant_dup_string(value, NULL);
    return TRUE;
  }

  g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
    "Unknown property: %s", property_name);
  return FALSE;
}

static const GDBusInterfaceVTable interface_vtable = {
  .method_call = handle_method_call,
  .get_property = handle_get_property,
  .set_property = handle_set_property
};

static void on_bus_acquired(GDBusConnection *connection,
                            const gchar *name,
                            gpointer user_data)
{
  (void)name; (void)user_data;
  the_connection = connection;

  GError *error = NULL;
  g_dbus_connection_register_object(connection,
    object_path,
    introspection_data->interfaces[0],
    &interface_vtable,
    NULL, NULL, &error);

  if (error) {
    g_printerr("Error registering object: %s\n", error->message);
    g_error_free(error);
    g_main_loop_quit(loop);
  }
}

static void on_name_acquired(GDBusConnection *connection,
                              const gchar *name,
                              gpointer user_data)
{
  (void)connection; (void)name; (void)user_data;
  /* Sync signal for test harness */
  fprintf(stdout, "READY\n");
  fflush(stdout);
}

static void on_name_lost(GDBusConnection *connection,
                          const gchar *name,
                          gpointer user_data)
{
  (void)connection; (void)name; (void)user_data;
  g_printerr("Lost bus name, exiting\n");
  g_main_loop_quit(loop);
}

int main(int argc, char *argv[])
{
  const gchar *bus_address = NULL;

  for (int i = 1; i < argc; i++) {
    if (g_str_has_prefix(argv[i], "--bus-address=")) {
      bus_address = argv[i] + strlen("--bus-address=");
    } else if (g_strcmp0(argv[i], "--bus-address") == 0 && i + 1 < argc) {
      bus_address = argv[++i];
    }
  }

  introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, NULL);
  if (!introspection_data) {
    g_printerr("Failed to parse introspection XML\n");
    return 1;
  }

  current_value = g_strdup("initial");
  loop = g_main_loop_new(NULL, FALSE);

  if (bus_address) {
    g_setenv("DBUS_SESSION_BUS_ADDRESS", bus_address, TRUE);
  }

  guint owner_id = g_bus_own_name(G_BUS_TYPE_SESSION,
    "com.test.ExternalFixture",
    G_BUS_NAME_OWNER_FLAGS_NONE,
    on_bus_acquired,
    on_name_acquired,
    on_name_lost,
    NULL, NULL);

  g_main_loop_run(loop);

  g_bus_unown_name(owner_id);
  g_dbus_node_info_unref(introspection_data);
  g_free(current_value);
  g_main_loop_unref(loop);

  return 0;
}
