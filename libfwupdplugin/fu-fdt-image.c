/*
 * Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#define G_LOG_DOMAIN "FuFirmware"

#include "config.h"

//#include <string.h>

//#include "fu-byte-array.h"
//#include "fu-bytes.h"
//#include "fu-common.h"
#include "fu-fdt-image.h"

/**
 * FuFdtImage:
 *
 * A Flattened DeviceTree firmware image.
 *
 * See also: [class@FuFdtImage]
 */

typedef struct {
	GHashTable *hash_props;
} FuFdtImagePrivate;

G_DEFINE_TYPE_WITH_PRIVATE(FuFdtImage, fu_fdt_image, FU_TYPE_FIRMWARE)
#define GET_PRIVATE(o) (fu_fdt_image_get_instance_private(o))

static void
fu_fdt_image_export(FuFirmware *firmware, FuFirmwareExportFlags flags, XbBuilderNode *bn)
{
	FuFdtImage *self = FU_FDT_IMAGE(firmware);
	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	//	fu_xmlb_builder_insert_kx(bn, "cpuid", priv->cpuid);

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, priv->hash_props);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		// FIXME: do something with key and value
	}
}

/**
 * fu_fdt_image_set_prop:
 * @self: a #FuFdtImage
 *
 * Sets the CPUID.
 *
 * Returns: (transfer container) (element-type utf-8): keys
 *
 * Since: 1.8.2
 **/
GPtrArray *
fu_fdt_image_get_props(FuFdtImage *self)
{
	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	GPtrArray *array = g_ptr_array_new_with_free_func(g_free);
	g_autoptr(GList) keys = NULL;

	g_return_val_if_fail(FU_IS_FDT_IMAGE(self), NULL);

	keys = g_hash_table_get_keys(priv->hash_props);
	for (GList *l = keys; l != NULL; l = l->next) {
		const gchar *key = l->data;
		g_ptr_array_add(array, g_strdup(key));
	}
	return array;
}

/**
 * fu_fdt_image_get_prop:
 * @self: a #FuFdtImage
 * @key: string, e.g. `creator`
 * @error: (nullable): optional return location for an error
 *
 * Gets a property from the image.
 *
 * Returns: (transfer none): blob
 *
 * Since: 1.8.2
 **/
GBytes *
fu_fdt_image_get_prop(FuFdtImage *self, const gchar *key, GError **error)
{
	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	GBytes *blob;

	g_return_val_if_fail(FU_IS_FDT_IMAGE(self), NULL);
	g_return_val_if_fail(key != NULL, NULL);

	blob = g_hash_table_lookup(priv->hash_props, key);
	if (blob == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "no data for %s", key);
		return NULL;
	}

	/* success */
	return blob;
}

/**
 * fu_fdt_image_set_prop:
 * @self: a #FuFdtImage
 * @key: string, e.g. `creator`
 * @blob: a #GBytes
 *
 * Sets a property for the image.
 *
 * Since: 1.8.2
 **/
void
fu_fdt_image_set_prop(FuFdtImage *self, const gchar *key, GBytes *blob)
{
	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_FDT_IMAGE(self));
	g_return_if_fail(key != NULL);
	g_hash_table_insert(priv->hash_props, g_strdup(key), g_bytes_ref(blob));
}

static gboolean
fu_fdt_image_parse(FuFirmware *firmware,
		   GBytes *fw,
		   gsize offset,
		   FwupdInstallFlags flags,
		   GError **error)
{
	return TRUE;
}

static GBytes *
fu_fdt_image_write(FuFirmware *firmware, GError **error)
{
	return NULL;
}

static gboolean
fu_fdt_image_build(FuFirmware *firmware, XbNode *n, GError **error)
{
	//	FuFdtImage *self = FU_FDT_IMAGE(firmware);
	//	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	//	guint64 tmp;

	/* optional properties */
	//	tmp = xb_node_query_text_as_uint(n, "cpuid", NULL);
	//	if (tmp != G_MAXUINT64 && tmp <= G_MAXUINT32)
	//		priv->cpuid = tmp;

	/* success */
	return TRUE;
}

static void
fu_fdt_image_init(FuFdtImage *self)
{
	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	priv->hash_props =
	    g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_bytes_unref);
}

static void
fu_fdt_image_finalize(GObject *object)
{
	FuFdtImage *self = FU_FDT_IMAGE(object);
	FuFdtImagePrivate *priv = GET_PRIVATE(self);
	g_hash_table_unref(priv->hash_props);
	G_OBJECT_CLASS(fu_fdt_image_parent_class)->finalize(object);
}

static void
fu_fdt_image_class_init(FuFdtImageClass *klass)
{
	FuFirmwareClass *klass_firmware = FU_FIRMWARE_CLASS(klass);
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = fu_fdt_image_finalize;
	klass_firmware->export = fu_fdt_image_export;
	klass_firmware->parse = fu_fdt_image_parse;
	klass_firmware->write = fu_fdt_image_write;
	klass_firmware->build = fu_fdt_image_build;
}

/**
 * fu_fdt_image_new:
 *
 * Creates a new #FuFirmware of sub type FDT image
 *
 * Since: 1.8.2
 **/
FuFirmware * // FIXME REMOVE?
fu_fdt_image_new(void)
{
	return FU_FIRMWARE(g_object_new(FU_TYPE_FDT_IMAGE, NULL));
}
