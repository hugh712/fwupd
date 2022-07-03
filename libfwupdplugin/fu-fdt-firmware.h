/*
 * Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-firmware.h"

#define FU_TYPE_FDT_FIRMWARE (fu_fdt_firmware_get_type())
G_DECLARE_DERIVABLE_TYPE(FuFdtFirmware, fu_fdt_firmware, FU, FDT_FIRMWARE, FuFirmware)

struct _FuFdtFirmwareClass {
	FuFirmwareClass parent_class;
};

FuFirmware *
fu_fdt_firmware_new(void);
guint16
fu_fdt_firmware_get_vid(FuFdtFirmware *self);
void
fu_fdt_firmware_set_vid(FuFdtFirmware *self, guint16 vid);
