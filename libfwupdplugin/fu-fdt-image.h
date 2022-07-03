/*
 * Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-firmware.h"

#define FU_TYPE_FDT_IMAGE (fu_fdt_image_get_type())
G_DECLARE_DERIVABLE_TYPE(FuFdtImage, fu_fdt_image, FU, FDT_IMAGE, FuFirmware)

struct _FuFdtImageClass {
	FuFirmwareClass parent_class;
};

FuFirmware *
fu_fdt_image_new(void);

GBytes *
fu_fdt_image_get_prop(FuFdtImage *self, const gchar *key, GError **error);
void
fu_fdt_image_set_prop(FuFdtImage *self, const gchar *key, GBytes *blob);
GPtrArray *
fu_fdt_image_get_props(FuFdtImage *self);
