/*
 * Copyright (C) 2021 Jeffrey Lin <jlin@kinet-ic.com>
 * Copyright (C) 2022 Hai Su <hsu@kinet-ic.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-kinetic-dp-connection.h"

/* Native DPCD fields defined in DP spec. */
#define DPCD_ADDR_IEEE_OUI	    0x00300
#define DPCD_SIZE_IEEE_OUI	    3
#define DPCD_ADDR_BRANCH_DEV_ID_STR 0x00503
#define DPCD_SIZE_BRANCH_DEV_ID_STR 6
#define DPCD_ADDR_BRANCH_FW_SUB	    0x00508
#define DPCD_SIZE_BRANCH_FW_SUB	    1
#define DPCD_ADDR_BRANCH_HW_REV	    0x00509
#define DPCD_SIZE_BRANCH_HW_REV	    1
#define DPCD_ADDR_BRANCH_FW_MAJ_REV 0x0050A
#define DPCD_SIZE_BRANCH_FW_MAJ_REV 1
#define DPCD_ADDR_BRANCH_FW_MIN_REV 0x0050B
#define DPCD_SIZE_BRANCH_FW_MIN_REV 1
/* Vendor-specific DPCD fields defined for Kinetic's usage */
#define DPCD_ADDR_BRANCH_FW_REV 0x0050C
#define DPCD_SIZE_BRANCH_FW_REV 1

gboolean
fu_kinetic_dp_aux_dpcd_read_oui(FuKineticDpConnection *connection,
				guint8 *buf,
				guint32 buf_size,
				GError **error);
gboolean
fu_kinetic_dp_aux_dpcd_write_oui(FuKineticDpConnection *connection,
				 const guint8 *buf,
				 GError **error);
gboolean
fu_kinetic_dp_aux_dpcd_read_branch_id_str(FuKineticDpConnection *connection,
					  guint8 *buf,
					  guint32 buf_size,
					  GError **error);
