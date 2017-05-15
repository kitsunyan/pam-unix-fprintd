/*
 * pam_fprint: PAM module for fingerprint authentication through fprintd
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2008 Bastien Nocera <hadess@hadess.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>

#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "pam_fprintd.h"
#include "marshal.h"

#define D(...)
#define TR(str) str
#define finger_str_to_msg(str, ...) g_strdup(str)
#define verify_result_str_to_msg(str, ...) str
#define send_err_msg(...)
#define send_info_msg(...)

static DBusGProxy *create_manager (pam_handle_t *pamh, DBusGConnection **ret_conn, GMainLoop **ret_loop)
{
	DBusGConnection *connection;
	DBusConnection *conn;
	DBusGProxy *manager;
	DBusError error;
	GMainLoop *loop;
	GMainContext *ctx;

	/* Otherwise dbus-glib doesn't setup it value types */
	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

	if (connection != NULL)
		dbus_g_connection_unref (connection);

	/* And set us up a private D-Bus connection */
	dbus_error_init (&error);
	conn = dbus_bus_get_private (DBUS_BUS_SYSTEM, &error);
	if (conn == NULL) {
		D(pamh, "Error with getting the bus: %s", error.message);
		dbus_error_free (&error);
		return NULL;
	}

	/* Set up our own main loop context */
	ctx = g_main_context_new ();
	loop = g_main_loop_new (ctx, FALSE);
	dbus_connection_setup_with_g_main (conn, ctx);

	connection = dbus_connection_get_g_connection (conn);

	manager = dbus_g_proxy_new_for_name(connection,
					    "net.reactivated.Fprint",
					    "/net/reactivated/Fprint/Manager",
					    "net.reactivated.Fprint.Manager");
	*ret_conn = connection;
	*ret_loop = loop;

	return manager;
}

static void close_and_unref (DBusGConnection *connection)
{
	DBusConnection *conn;

	conn = dbus_g_connection_get_connection (connection);
	dbus_connection_close (conn);
	dbus_g_connection_unref (connection);
}

static void unref_loop (GMainLoop *loop)
{
	GMainContext *ctx;

	/* The main context was created separately, so
	 * we'll need to unref it ourselves */
	ctx = g_main_loop_get_context (loop);
	g_main_loop_unref (loop);
	g_main_context_unref (ctx);
}

#define DBUS_TYPE_G_OBJECT_PATH_ARRAY (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH))

static DBusGProxy *open_device(pam_handle_t *pamh, DBusGConnection *connection, DBusGProxy *manager, gboolean *has_multiple_devices)
{
	GError *error = NULL;
	const char *path;
	DBusGProxy *dev;
	GPtrArray *paths_array;
	const char **paths;

	if (!dbus_g_proxy_call (manager, "GetDevices", &error,
				G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH_ARRAY,
				&paths_array, G_TYPE_INVALID)) {
		D(pamh, "get_devices failed: %s", error->message);
		g_error_free (error);
		return NULL;
	}

	if (paths_array == NULL || paths_array->len == 0) {
		if (paths_array != NULL)
			g_ptr_array_free (paths_array, TRUE);
		D(pamh, "No devices found\n");
		return NULL;
	}

	*has_multiple_devices = (paths_array->len > 1);
	paths = (const char **)paths_array->pdata;
	path = paths[0];

	D(pamh, "Using device %s\n", path);

	dev = dbus_g_proxy_new_for_name(connection,
					"net.reactivated.Fprint",
					path,
					"net.reactivated.Fprint.Device");

	g_ptr_array_free (paths_array, TRUE);

	return dev;
}

typedef struct {
	char *result;
	gboolean is_swipe;
	pam_handle_t *pamh;
	GMainLoop *loop;

	char *driver;
} verify_data;

static void verify_result(GObject *object, const char *result, gboolean done, gpointer user_data)
{
	verify_data *data = user_data;
	const char *msg;

	D(data->pamh, "Verify result: %s\n", result);
	if (done != FALSE) {
		data->result = g_strdup (result);
		g_main_loop_quit (data->loop);
		return;
	}

	msg = TR(verify_result_str_to_msg (result, data->is_swipe));
	send_err_msg (data->pamh, msg);
}

static void verify_finger_selected(GObject *object, const char *finger_name, gpointer user_data)
{
	verify_data *data = user_data;
	char *msg;

	msg = finger_str_to_msg(finger_name, data->driver, data->is_swipe);

	D(data->pamh, "verify_finger_selected %s", msg);
	send_info_msg (data->pamh, msg);
	g_free (msg);
}

static gboolean source_callback(gpointer user_data)
{
	fprintd_state *state = user_data;
	GMainLoop *loop;

	if (state->interrupted)
	{
		loop = state->loop;
		g_main_loop_quit (loop);
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

static int do_verify(GMainLoop *loop, pam_handle_t *pamh, DBusGProxy *dev, fprintd_state *state, gboolean has_multiple_devices)
{
	GError *error = NULL;
	GHashTable *props;
	DBusGProxy *p;
	GSource *source;
	verify_data *data;
	int ret;

	data = g_new0 (verify_data, 1);
	data->pamh = pamh;
	data->loop = loop;

	/* Get some properties for the device */
	p = dbus_g_proxy_new_from_proxy (dev, "org.freedesktop.DBus.Properties", NULL);

	if (dbus_g_proxy_call (p, "GetAll", NULL, G_TYPE_STRING, "net.reactivated.Fprint.Device", G_TYPE_INVALID,
			       dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE), &props, G_TYPE_INVALID)) {
		const char *scan_type;
		if (has_multiple_devices)
			data->driver = g_value_dup_string (g_hash_table_lookup (props, "name"));
		scan_type = g_value_dup_string (g_hash_table_lookup (props, "scan-type"));
		if (g_str_equal (scan_type, "swipe"))
			data->is_swipe = TRUE;
		g_hash_table_destroy (props);
	}

	g_object_unref (p);

	dbus_g_proxy_add_signal(dev, "VerifyStatus", G_TYPE_STRING, G_TYPE_BOOLEAN, NULL);
	dbus_g_proxy_add_signal(dev, "VerifyFingerSelected", G_TYPE_STRING, NULL);
	dbus_g_proxy_connect_signal(dev, "VerifyStatus", G_CALLBACK(verify_result),
				    data, NULL);
	dbus_g_proxy_connect_signal(dev, "VerifyFingerSelected", G_CALLBACK(verify_finger_selected),
				    data, NULL);

	state->loop = loop;
	source = g_timeout_source_new (250);
	g_source_set_callback (source, source_callback, state, NULL);
	g_source_set_priority (source, G_PRIORITY_DEFAULT);
	g_source_attach (source, g_main_loop_get_context (loop));

	ret = PAM_AUTH_ERR;

	while (ret == PAM_AUTH_ERR) {
		if (!dbus_g_proxy_call (dev, "VerifyStart", &error, G_TYPE_STRING, "any", G_TYPE_INVALID, G_TYPE_INVALID)) {
			if (dbus_g_error_has_name(error, "net.reactivated.Fprint.Error.NoEnrolledPrints"))
				ret = PAM_USER_UNKNOWN;

			D(pamh, "VerifyStart failed: %s", error->message);
			g_error_free (error);
			break;
		}

		g_main_loop_run (loop);

		/* Ignore errors from VerifyStop */
		dbus_g_proxy_call (dev, "VerifyStop", NULL, G_TYPE_INVALID, G_TYPE_INVALID);

		if (state->interrupted) {
			ret = PAM_AUTHINFO_UNAVAIL;
			break;
		} else {
			if (g_str_equal (data->result, "verify-no-match")) {
				send_err_msg (data->pamh, "Failed to match fingerprint");
				ret = PAM_AUTH_ERR;
			} else if (g_str_equal (data->result, "verify-match"))
				ret = PAM_SUCCESS;
			else if (g_str_equal (data->result, "verify-unknown-error"))
				ret = PAM_AUTHINFO_UNAVAIL;
			else if (g_str_equal (data->result, "verify-disconnected")) {
				ret = PAM_AUTHINFO_UNAVAIL;
				g_free (data->result);
				break;
			} else {
				send_info_msg (data->pamh, "An unknown error occured");
				ret = PAM_AUTH_ERR;
				g_free (data->result);
				break;
			}
			g_free (data->result);
			data->result = NULL;
		}
	}

	dbus_g_proxy_disconnect_signal(dev, "VerifyStatus", G_CALLBACK(verify_result), data);
	dbus_g_proxy_disconnect_signal(dev, "VerifyFingerSelected", G_CALLBACK(verify_finger_selected), data);

	g_source_destroy (source);

	g_free (data->driver);
	g_free (data);

	return ret;
}

static gboolean user_has_prints(DBusGProxy *dev, const char *username)
{
	char **fingers;
	gboolean have_prints;

	if (!dbus_g_proxy_call (dev, "ListEnrolledFingers", NULL,
				G_TYPE_STRING, username, G_TYPE_INVALID,
				G_TYPE_STRV, &fingers, G_TYPE_INVALID)) {
		/* If ListEnrolledFingers fails then verification should
		 * also fail (both use the same underlying call), so we
		 * report FALSE here and bail out early.  */
		return FALSE;
	}

	have_prints = fingers != NULL && g_strv_length (fingers) > 0;
	g_strfreev (fingers);

	return have_prints;
}

static void release_device(pam_handle_t *pamh, DBusGProxy *dev)
{
	GError *error = NULL;
	if (!dbus_g_proxy_call (dev, "Release", &error, G_TYPE_INVALID, G_TYPE_INVALID)) {
		D(pamh, "ReleaseDevice failed: %s\n", error->message);
		g_error_free (error);
	}
}

static gboolean claim_device(pam_handle_t *pamh, DBusGProxy *dev, const char *username)
{
	GError *error = NULL;

	if (!dbus_g_proxy_call (dev, "Claim", &error, G_TYPE_STRING, username, G_TYPE_INVALID, G_TYPE_INVALID)) {
		D(pamh, "failed to claim device %s\n", error->message);
		g_error_free (error);
		return FALSE;
	}

	return TRUE;
}

static int do_auth(pam_handle_t *pamh, const char *username, fprintd_state *state)
{
	DBusGProxy *manager;
	DBusGConnection *connection;
	DBusGProxy *dev;
	GMainLoop *loop;
	gboolean have_prints;
	gboolean has_multiple_devices;
	int ret = PAM_AUTHINFO_UNAVAIL;

	manager = create_manager (pamh, &connection, &loop);
	if (manager == NULL)
		return PAM_AUTHINFO_UNAVAIL;

	dev = open_device(pamh, connection, manager, &has_multiple_devices);
	g_object_unref (manager);
	if (!dev) {
		unref_loop (loop);
		close_and_unref (connection);
		return PAM_AUTHINFO_UNAVAIL;
	}

	have_prints = user_has_prints(dev, username);
	D(pamh, "prints registered: %s\n", have_prints ? "yes" : "no");

	if (have_prints) {
		if (claim_device (pamh, dev, username)) {
			ret = do_verify (loop, pamh, dev, state, has_multiple_devices);
			release_device (pamh, dev);
		}
	}

	unref_loop (loop);
	g_object_unref (dev);
	close_and_unref (connection);

	return ret;
}

int pam_sm_authenticate_fprintd(pam_handle_t *pamh, fprintd_state *state)
{
	const char *rhost = NULL;
	const char *username;
	guint i;
	int r;

#if !GLIB_CHECK_VERSION (2, 36, 0)
	g_type_init();
#endif

	dbus_g_object_register_marshaller (fprintd_marshal_VOID__STRING_BOOLEAN,
					   G_TYPE_NONE, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_INVALID);

	pam_get_item(pamh, PAM_RHOST, (const void **)(const void*) &rhost);
	if (rhost != NULL && strlen(rhost) > 0) {
		/* remote login (e.g. over SSH) */
		return PAM_AUTHINFO_UNAVAIL;
	}

	r = pam_get_user(pamh, &username, NULL);
	if (r != PAM_SUCCESS)
		return PAM_AUTHINFO_UNAVAIL;

	r = do_auth(pamh, username, state);

	return r;
}

void fprintd_state_init(fprintd_state *state)
{
	state->interrupted = 0;
}

void fprintd_state_cleanup(fprintd_state *state)
{
	state->interrupted = 1;
}
