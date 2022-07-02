/*
 * Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-firmware.h"

#define FU_TYPE_FIT_FIRMWARE (fu_fit_firmware_get_type())
G_DECLARE_DERIVABLE_TYPE(FuFitFirmware, fu_fit_firmware, FU, FIT_FIRMWARE, FuFirmware)

struct _FuFitFirmwareClass {
	FuFirmwareClass parent_class;
};

FuFirmware *
fu_fit_firmware_new(void);
guint16
fu_fit_firmware_get_vid(FuFitFirmware *self);
void
fu_fit_firmware_set_vid(FuFitFirmware *self, guint16 vid);
