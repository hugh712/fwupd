/*
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <efivar/efiboot.h>
#include <stdio.h>

#include "fu-uefi-bootmgr.h"
#include "fu-uefi-common.h"
#include "fu-uefi-device.h"

/* XXX PJFIX: this should be in efiboot-loadopt.h in efivar */
#define LOAD_OPTION_ACTIVE 0x00000001

static gboolean
fu_uefi_bootmgr_add_to_boot_order(guint16 boot_entry, GError **error)
{
	gsize boot_order_size = 0;
	guint i = 0;
	guint32 attr = 0;
	g_autofree guint16 *boot_order = NULL;
	g_autofree guint16 *new_boot_order = NULL;

	/* get the current boot order */
	if (!fu_efivar_get_data(FU_EFIVAR_GUID_EFI_GLOBAL,
				"BootOrder",
				(guint8 **)&boot_order,
				&boot_order_size,
				&attr,
				error))
		return FALSE;

	/* already set next */
	for (i = 0; i < boot_order_size / sizeof(guint16); i++) {
		guint16 val = boot_order[i];
		if (val == boot_entry)
			return TRUE;
	}

	/* add the new boot index to the end of the list */
	new_boot_order = g_malloc0(boot_order_size + sizeof(guint16));
	if (boot_order_size != 0)
		memcpy(new_boot_order, boot_order, boot_order_size);

	attr |= FU_EFIVAR_ATTR_NON_VOLATILE | FU_EFIVAR_ATTR_BOOTSERVICE_ACCESS |
		FU_EFIVAR_ATTR_RUNTIME_ACCESS;

	i = boot_order_size / sizeof(guint16);
	new_boot_order[i] = boot_entry;
	boot_order_size += sizeof(guint16);
	return fu_efivar_set_data(FU_EFIVAR_GUID_EFI_GLOBAL,
				  "BootOrder",
				  (guint8 *)new_boot_order,
				  boot_order_size,
				  attr,
				  error);
}

static guint16
fu_uefi_bootmgr_parse_name(const gchar *name)
{
	gint rc;
	gint scanned = 0;
	guint16 entry = 0;

	/* BootXXXX */
	rc = sscanf(name, "Boot%hX%n", &entry, &scanned);
	if (rc != 1 || scanned != 8)
		return G_MAXUINT16;
	return entry;
}

gboolean
fu_uefi_bootmgr_verify_fwupd(GError **error)
{
	g_autoptr(GPtrArray) names = NULL;

	names = fu_efivar_get_names(FU_EFIVAR_GUID_EFI_GLOBAL, error);
	if (names == NULL)
		return FALSE;
	for (guint i = 0; i < names->len; i++) {
		const gchar *desc;
		const gchar *name = g_ptr_array_index(names, i);
		efi_load_option *loadopt;
		gsize var_data_size = 0;
		guint16 entry;
		g_autofree guint8 *var_data_tmp = NULL;
		g_autoptr(GError) error_local = NULL;

		/* not BootXXXX */
		entry = fu_uefi_bootmgr_parse_name(name);
		if (entry == G_MAXUINT16)
			continue;

		/* parse key */
		if (!fu_efivar_get_data(FU_EFIVAR_GUID_EFI_GLOBAL,
					name,
					&var_data_tmp,
					&var_data_size,
					NULL,
					&error_local)) {
			g_debug("failed to get data for name %s: %s", name, error_local->message);
			continue;
		}
		loadopt = (efi_load_option *)var_data_tmp;
		if (!efi_loadopt_is_valid(loadopt, var_data_size)) {
			g_debug("%s -> load option was invalid", name);
			continue;
		}

		desc = (const gchar *)efi_loadopt_desc(loadopt, var_data_size);
		if (g_strcmp0(desc, "Linux Firmware Updater") == 0 ||
		    g_strcmp0(desc, "Linux-Firmware-Updater") == 0) {
			g_debug("found %s at Boot%04X", desc, entry);
			return TRUE;
		}
	}

	/* did not find */
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "no 'Linux Firmware Updater' entry found");
	return FALSE;
}

static gboolean
fu_uefi_setup_bootnext_with_dp(const guint8 *dp_buf, guint8 *opt, gssize opt_size, GError **error)
{
	const gchar *desc = NULL;
	const gchar *name = NULL;
	efi_load_option *loadopt = NULL;
	gsize var_data_size = 0;
	guint32 attr;
	guint16 boot_next = G_MAXUINT16;
	g_autofree guint8 *var_data = NULL;
	g_autofree guint8 *set_entries = g_malloc0(G_MAXUINT16);
	g_autoptr(GPtrArray) names = NULL;

	names = fu_efivar_get_names(FU_EFIVAR_GUID_EFI_GLOBAL, error);
	if (names == NULL)
		return FALSE;
	for (guint i = 0; i < names->len; i++) {
		guint16 entry = 0;
		g_autofree guint8 *var_data_tmp = NULL;
		g_autoptr(GError) error_local = NULL;

		/* not BootXXXX */
		name = g_ptr_array_index(names, i);
		entry = fu_uefi_bootmgr_parse_name(name);
		if (entry == G_MAXUINT16)
			continue;

		/* mark this as used */
		set_entries[entry] = 1;

		if (!fu_efivar_get_data(FU_EFIVAR_GUID_EFI_GLOBAL,
					name,
					&var_data_tmp,
					&var_data_size,
					&attr,
					&error_local)) {
			g_debug("failed to get data for name %s: %s", name, error_local->message);
			continue;
		}

		loadopt = (efi_load_option *)var_data_tmp;
		if (!efi_loadopt_is_valid(loadopt, var_data_size)) {
			g_debug("%s -> load option was invalid", name);
			continue;
		}

		desc = (const gchar *)efi_loadopt_desc(loadopt, var_data_size);
		if (g_strcmp0(desc, "Linux Firmware Updater") != 0 &&
		    g_strcmp0(desc, "Linux-Firmware-Updater") != 0) {
			g_debug("%s -> '%s' : does not match", name, desc);
			continue;
		}

		var_data = g_steal_pointer(&var_data_tmp);
		boot_next = entry;
		break;
	}

	/* already exists */
	if (var_data != NULL) {
		/* is different than before */
		if (var_data_size != (gsize)opt_size || memcmp(var_data, opt, opt_size) != 0) {
			g_debug("%s -> '%s' : updating existing boot entry", name, desc);
			efi_loadopt_attr_set(loadopt, LOAD_OPTION_ACTIVE);
			if (!fu_efivar_set_data(FU_EFIVAR_GUID_EFI_GLOBAL,
						name,
						opt,
						opt_size,
						attr,
						error)) {
				g_prefix_error(error, "could not set boot variable active: ");
				return FALSE;
			}
		} else {
			g_debug("%s -> %s : re-using existing boot entry", name, desc);
		}
		/* create a new one */
	} else {
		g_autofree gchar *boot_next_name = NULL;
		for (guint16 value = 0; value < G_MAXUINT16; value++) {
			if (set_entries[value])
				continue;
			boot_next = value;
			break;
		}
		if (boot_next == G_MAXUINT16) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "no free boot variables (tried %x)",
				    boot_next);
			return FALSE;
		}
		boot_next_name = g_strdup_printf("Boot%04X", (guint)boot_next);
		g_debug("%s -> creating new entry", boot_next_name);
		if (!fu_efivar_set_data(FU_EFIVAR_GUID_EFI_GLOBAL,
					boot_next_name,
					opt,
					opt_size,
					FU_EFIVAR_ATTR_NON_VOLATILE |
					    FU_EFIVAR_ATTR_BOOTSERVICE_ACCESS |
					    FU_EFIVAR_ATTR_RUNTIME_ACCESS,
					error)) {
			g_prefix_error(error, "could not set boot variable %s: ", boot_next_name);
			return FALSE;
		}
	}

	/* TODO: conditionalize this on the UEFI version? */
	if (!fu_uefi_bootmgr_add_to_boot_order(boot_next, error))
		return FALSE;

	/* set the boot next */
	if (!fu_efivar_set_data(FU_EFIVAR_GUID_EFI_GLOBAL,
				"BootNext",
				(guint8 *)&boot_next,
				2,
				FU_EFIVAR_ATTR_NON_VOLATILE | FU_EFIVAR_ATTR_BOOTSERVICE_ACCESS |
				    FU_EFIVAR_ATTR_RUNTIME_ACCESS,
				error)) {
		g_prefix_error(error, "could not set BootNext(%" G_GUINT16_FORMAT "): ", boot_next);
		return FALSE;
	}
	return TRUE;
}

gboolean
fu_uefi_bootmgr_bootnext(FuDevice *device,
			 const gchar *esp_path,
			 const gchar *description,
			 FuUefiBootmgrFlags flags,
			 GError **error)
{
	const gchar *filepath;
	gboolean use_fwup_path = TRUE;
	gboolean secure_boot = FALSE;
	gsize loader_sz = 0;
	gssize opt_size = 0;
	gssize sz, dp_size = 0;
	guint32 attributes = LOAD_OPTION_ACTIVE;
	g_autofree guint16 *loader_str = NULL;
	g_autofree gchar *label = NULL;
	g_autofree gchar *shim_app = NULL;
	g_autofree gchar *shim_cpy = NULL;
	g_autofree guint8 *dp_buf = NULL;
	g_autofree guint8 *opt = NULL;
	g_autofree gchar *source_app = NULL;
	g_autofree gchar *target_app = NULL;

	/* skip for self tests */
	if (g_getenv("FWUPD_UEFI_TEST") != NULL)
		return TRUE;

	/* if secure boot was turned on this might need to be installed separately */
	source_app = fu_uefi_get_built_app_path(error);
	if (source_app == NULL)
		return FALSE;

	/* test if we should use shim */
	secure_boot = fu_efivar_secure_boot_enabled(NULL);
	if (secure_boot) {
		/* test to make sure shim is there if we need it */
		shim_app = fu_uefi_get_esp_app_path(device, esp_path, "shim", error);
		if (shim_app == NULL)
			return FALSE;

		/* try to fallback to use UEFI removable path if the shim path doesn't exist */
		if (!g_file_test(shim_app, G_FILE_TEST_EXISTS)) {
			if (fu_device_has_private_flag(
				device,
				FU_UEFI_DEVICE_FLAG_FALLBACK_TO_REMOVABLE_PATH)) {
				shim_app =
				    fu_uefi_get_fallback_app_path(device, esp_path, "boot", error);
				if (shim_app == NULL)
					return FALSE;
			}
		}

		if (g_file_test(shim_app, G_FILE_TEST_EXISTS)) {
			/* use a custom copy of shim for firmware updates */
			if (flags & FU_UEFI_BOOTMGR_FLAG_USE_SHIM_UNIQUE) {
				shim_cpy =
				    fu_uefi_get_esp_app_path(device, esp_path, "shimfwupd", error);
				if (shim_cpy == NULL)
					return FALSE;
				if (!fu_uefi_cmp_asset(shim_app, shim_cpy)) {
					if (!fu_uefi_copy_asset(shim_app, shim_cpy, error))
						return FALSE;
				}
				filepath = shim_cpy;
			} else {
				filepath = shim_app;
			}
			use_fwup_path = FALSE;
		} else if ((flags & FU_UEFI_BOOTMGR_FLAG_USE_SHIM_FOR_SB) > 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_BROKEN_SYSTEM,
				    "Secure boot is enabled, but shim isn't installed to "
				    "%s",
				    shim_app);
			return FALSE;
		}
	}

	/* test if correct asset in place */
	target_app = fu_uefi_get_esp_app_path(device, esp_path, "fwupd", error);
	if (target_app == NULL)
		return FALSE;
	if (!fu_uefi_cmp_asset(source_app, target_app)) {
		if (!fu_uefi_copy_asset(source_app, target_app, error))
			return FALSE;
	}

	/* no shim, so use this directly */
	if (use_fwup_path)
		filepath = target_app;

	/* generate device path for target */
	sz = efi_generate_file_device_path(dp_buf,
					   dp_size,
					   filepath,
					   EFIBOOT_OPTIONS_IGNORE_FS_ERROR | EFIBOOT_ABBREV_HD);
	if (sz < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "efi_generate_file_device_path(%s) failed",
			    filepath);
		return FALSE;
	}

	/* add the fwupdx64.efi ESP path as the shim loadopt data */
	dp_size = sz;
	dp_buf = g_malloc0(dp_size);
	if (!use_fwup_path) {
		glong items_written = 0;
		g_autofree gchar *fwup_fs_basename = g_path_get_basename(target_app);
		g_autofree gchar *fwup_esp_path = g_strdup_printf("\\%s", fwup_fs_basename);
		loader_str = g_utf8_to_utf16(fwup_esp_path, -1, NULL, &items_written, error);
		if (loader_str == NULL)
			return FALSE;
		if (items_written > 0)
			loader_sz += (items_written + 1) * 2;
	}

	sz = efi_generate_file_device_path(dp_buf,
					   dp_size,
					   filepath,
					   EFIBOOT_OPTIONS_IGNORE_FS_ERROR | EFIBOOT_ABBREV_HD);
	if (sz != dp_size) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "efi_generate_file_device_path(%s) failed",
			    filepath);
		return FALSE;
	}

	label = g_strdup(description);
	sz = efi_loadopt_create(opt,
				opt_size,
				attributes,
				(efidp)dp_buf,
				dp_size,
				(guint8 *)label,
				(guint8 *)loader_str,
				loader_sz);
	if (sz < 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "efi_loadopt_create(%s) failed",
			    label);
		return FALSE;
	}
	opt = g_malloc0(sz);
	opt_size = sz;
	sz = efi_loadopt_create(opt,
				opt_size,
				attributes,
				(efidp)dp_buf,
				dp_size,
				(guint8 *)label,
				(guint8 *)loader_str,
				loader_sz);
	if (sz != opt_size) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "loadopt size was unreasonable.");
		return FALSE;
	}
	return fu_uefi_setup_bootnext_with_dp(dp_buf, opt, opt_size, error);
}
