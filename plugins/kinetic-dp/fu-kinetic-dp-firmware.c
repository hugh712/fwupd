/*
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2021 Jeffrey Lin <jlin@kinet-ic.com>
 * Copyright (C) 2022 Hai Su <hsu@kinet-ic.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "fu-kinetic-dp-firmware.h"

#include "fu-kinetic-dp-aux-isp.h"
#include "fu-kinetic-dp-connection.h"
#include "fu-kinetic-dp-puma-aux-isp.h"
#include "fu-kinetic-dp-secure-aux-isp.h"

struct _FuKineticDpFirmware {
	FuFirmwareClass parent_instance;
};

typedef struct {
	KtChipId chip_id;
	guint32 isp_drv_size;
	guint32 esm_payload_size;
	guint32 arm_app_code_size;
	guint16 app_init_data_size;
	guint16 cmdb_block_size;
	guint16 cmdb_version;
	guint32 cmdb_revision;
	gboolean is_fw_esm_xip_enabled;
	guint16 fw_bin_flag;
	/* FW info embedded in FW file */
	guint32 std_fw_ver;
	guint32 customer_fw_ver;
	guint8 customer_project_id;
} FuKineticDpFirmwarePrivate;

G_DEFINE_TYPE_WITH_PRIVATE(FuKineticDpFirmware, fu_kinetic_dp_firmware, FU_TYPE_FIRMWARE)
#define GET_PRIVATE(o) (fu_kinetic_dp_firmware_get_instance_private(o))

#define HEADER_LEN_ISP_DRV_SIZE 4
#define APP_ID_STR_LEN		4

typedef struct {
	KtChipId chip_id;
	guint32 app_id_offset;
	guint8 app_id_str[APP_ID_STR_LEN];
	guint16 fw_bin_flag;
} KtDpFwAppIdFlag;

/* Application signature/Identifier table */
static const KtDpFwAppIdFlag kt_dp_app_sign_id_table[] = {
    /* Chip_ID,App ID Offset,App ID,FW Flag */
    {KT_CHIP_JAGUAR_5000, 0x0FFFE4UL, {'J', 'A', 'G', 'R'}, KT_FW_BIN_FLAG_NONE}, /* Jaguar 1024KB*/
    {KT_CHIP_JAGUAR_5000,
     0x0A7036UL,
     {'J', 'A', 'G', 'R'},
     KT_FW_BIN_FLAG_NONE}, /* Jaguar 670KB, for ANZU*/
    {KT_CHIP_JAGUAR_5000,
     0x0FFFE4UL,
     {'J', 'A', 'G', 'X'},
     KT_FW_BIN_FLAG_XIP}, /* Jaguar 1024KB (App 640KB)	*/
    {KT_CHIP_JAGUAR_5000,
     0x0E7036UL,
     {'J', 'A', 'G', 'X'},
     KT_FW_BIN_FLAG_XIP}, /* Jaguar 670KB, for ANZU (App 640KB)	*/
    {KT_CHIP_MUSTANG_5200,
     0x0FFFE4UL,
     {'M', 'S', 'T', 'G'},
     KT_FW_BIN_FLAG_NONE}, /* Mustang 1024KB*/
    {KT_CHIP_MUSTANG_5200,
     0x0A7036UL,
     {'M', 'S', 'T', 'G'},
     KT_FW_BIN_FLAG_NONE}, /* Mustang 670KB, for ANZU*/
    {KT_CHIP_MUSTANG_5200,
     0x0FFFE4UL,
     {'M', 'S', 'T', 'X'},
     KT_FW_BIN_FLAG_XIP}, /* Mustang 1024KB (App 640KB)*/
    {KT_CHIP_MUSTANG_5200,
     0x0E7036UL,
     {'M', 'S', 'T', 'X'},
     KT_FW_BIN_FLAG_XIP}, /* Mustang 670KB, for ANZU (App 640KB)*/
    {KT_CHIP_PUMA_2900, 0x080042UL, {'P', 'U', 'M', 'A'}, KT_FW_BIN_FLAG_NONE} /* Puma 512KB*/
};

static gboolean
fu_kinetic_dp_firmware_get_chip_id_from_fw_buf(const guint8 *fw_bin_buf,
					       const guint32 fw_bin_size,
					       KtChipId *chip_id,
					       guint16 *fw_bin_flag)
{
	guint32 num = G_N_ELEMENTS(kt_dp_app_sign_id_table);
	for (guint32 i = 0; i < num; i++) {
		guint32 app_id_offset = kt_dp_app_sign_id_table[i].app_id_offset;
		if ((app_id_offset + APP_ID_STR_LEN) < fw_bin_size) {
			if (memcmp(&fw_bin_buf[app_id_offset],
				   kt_dp_app_sign_id_table[i].app_id_str,
				   APP_ID_STR_LEN) == 0) {
				/* found corresponding app ID */
				*chip_id = kt_dp_app_sign_id_table[i].chip_id;
				*fw_bin_flag = kt_dp_app_sign_id_table[i].fw_bin_flag;
				g_debug("Chip ID (%s) found in lookup table and f/w flags set.",
					kt_dp_app_sign_id_table[i].app_id_str);
				return TRUE;
			}
		}
	}
	return FALSE;
}

void
fu_kinetic_dp_firmware_set_isp_drv_size(FuKineticDpFirmware *self, guint32 isp_drv_size)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->isp_drv_size = isp_drv_size;
	g_debug("firmware set  isp driver size 0x%x(%u)", priv->isp_drv_size, priv->isp_drv_size);
}

guint32
fu_kinetic_dp_firmware_get_isp_drv_size(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->isp_drv_size;
}

void
fu_kinetic_dp_firmware_set_esm_payload_size(FuKineticDpFirmware *self, guint32 esm_payload_size)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->esm_payload_size = esm_payload_size;
	g_debug("firmware set esm size 0x%x(%u)", priv->esm_payload_size, priv->esm_payload_size);
}

guint32
fu_kinetic_dp_firmware_get_esm_payload_size(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->esm_payload_size;
}

void
fu_kinetic_dp_firmware_set_arm_app_code_size(FuKineticDpFirmware *self, guint32 arm_app_code_size)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->arm_app_code_size = arm_app_code_size;
	g_debug("firmware set arm code size 0x%x(%u)",
		priv->arm_app_code_size,
		priv->arm_app_code_size);
}

guint32
fu_kinetic_dp_firmware_get_arm_app_code_size(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->arm_app_code_size;
}

void
fu_kinetic_dp_firmware_set_app_init_data_size(FuKineticDpFirmware *self, guint16 app_init_data_size)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->app_init_data_size = app_init_data_size;
	g_debug("firmware set app init data size 0x%x(%u)",
		priv->app_init_data_size,
		priv->app_init_data_size);
}

guint16
fu_kinetic_dp_firmware_get_app_init_data_size(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->app_init_data_size;
}

void
fu_kinetic_dp_firmware_set_cmdb_block_size(FuKineticDpFirmware *self, guint16 cmdb_block_size)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->cmdb_block_size = cmdb_block_size;
	g_debug("firmware set cmdb block size 0x%x(%u)",
		priv->cmdb_block_size,
		priv->cmdb_block_size);
}

guint16
fu_kinetic_dp_firmware_get_cmdb_block_size(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->cmdb_block_size;
}
void
fu_kinetic_dp_firmware_set_cmdb_ver(FuKineticDpFirmware *self, guint16 version)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->cmdb_version = version;
	g_debug("firmware set cmdb version  %u", priv->cmdb_version);
}

guint16
fu_kinetic_dp_firmware_get_cmdb_ver(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->cmdb_version;
}

void
fu_kinetic_dp_firmware_set_cmdb_rev(FuKineticDpFirmware *self, guint32 revision)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->cmdb_revision = revision;
	g_debug("firmware set cmdb revision 0x%u", priv->cmdb_revision);
}

guint32
fu_kinetic_dp_firmware_get_cmdb_rev(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->cmdb_revision;
}

void
fu_kinetic_dp_firmware_set_is_fw_esm_xip_enabled(FuKineticDpFirmware *self,
						 gboolean is_fw_esm_xip_enabled)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->is_fw_esm_xip_enabled = is_fw_esm_xip_enabled;
	g_debug("firmware set esm xip enabled.");
}

gboolean
fu_kinetic_dp_firmware_get_is_fw_esm_xip_enabled(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), FALSE);
	return priv->is_fw_esm_xip_enabled;
}

void
fu_kinetic_dp_firmware_set_std_fw_ver(FuKineticDpFirmware *self, guint32 std_fw_ver)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->std_fw_ver = std_fw_ver;
	g_debug("firmware set fw version 0x%x", priv->std_fw_ver);
}

guint32
fu_kinetic_dp_firmware_get_std_fw_ver(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->std_fw_ver;
}

void
fu_kinetic_dp_firmware_set_customer_fw_ver(FuKineticDpFirmware *self, guint32 customer_fw_ver)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->customer_fw_ver = customer_fw_ver;
	g_debug("firmware set customer fw version 0x%x", priv->customer_fw_ver);
}

guint32
fu_kinetic_dp_firmware_get_customer_fw_ver(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->customer_fw_ver;
}

void
fu_kinetic_dp_firmware_set_customer_project_id(FuKineticDpFirmware *self,
					       guint32 customer_project_id)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_if_fail(FU_IS_KINETIC_DP_FIRMWARE(self));
	priv->customer_project_id = customer_project_id;
	g_debug("firmware set customer proj ID 0x%x ", priv->customer_project_id);
}

guint8
fu_kinetic_dp_firmware_get_customer_project_id(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_KINETIC_DP_FIRMWARE(self), 0);
	return priv->customer_project_id;
}

guint32
fu_kinetic_dp_firmware_get_valid_payload_size(const guint8 *payload_data, const guint32 data_size)
{
	guint32 i = 0;
	g_debug("adjust payload size by not counting padded bytes...");
	payload_data += data_size - 1; /* start searching from the end of payload */
	while ((*(payload_data - i) == 0xFF) && (i < data_size))
		i++;
	return (data_size - i);
}

static gboolean
fu_kinetic_dp_firmware_parse(FuFirmware *self,
			     GBytes *fw_bytes,
			     guint64 addr_start,
			     guint64 addr_end,
			     FwupdInstallFlags flags,
			     GError **error)
{
	FuKineticDpFirmware *firmware = FU_KINETIC_DP_FIRMWARE(self);
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(firmware);
	const guint8 *buf;
	gsize bufsz;
	guint32 app_fw_payload_size = 0;
	g_autoptr(GBytes) isp_drv_payload = NULL;
	g_autoptr(GBytes) app_fw_payload = NULL;
	g_autoptr(FuFirmware) isp_drv_img = NULL;
	g_autoptr(FuFirmware) app_fw_img = NULL;

	g_debug("firmware package parsing starts...");
	/* parse firmware according to Kinetic's FW image format
	 * FW binary = 4 bytes Header(Little-Endian) + ISP driver + App FW
	 * 4 bytes Header: size of ISP driver */
	buf = g_bytes_get_data(fw_bytes, &bufsz);
	if (!fu_common_read_uint32_safe(buf, bufsz, 0, &priv->isp_drv_size, G_LITTLE_ENDIAN, error))
		return FALSE;

	g_debug("extracted ISP driver payload size: 0x%x(%u)bytes",
		priv->isp_drv_size,
		priv->isp_drv_size);

	/* app firmware payload size */
	app_fw_payload_size =
	    g_bytes_get_size(fw_bytes) - HEADER_LEN_ISP_DRV_SIZE - priv->isp_drv_size;
	g_debug("calculated App firmware payload size: 0x%x(%u) bytes",
		app_fw_payload_size,
		app_fw_payload_size);

	/* add ISP driver as a new image into firmware */
	isp_drv_payload =
	    g_bytes_new_from_bytes(fw_bytes, HEADER_LEN_ISP_DRV_SIZE, priv->isp_drv_size);
	isp_drv_img = fu_firmware_new_from_bytes(isp_drv_payload);
	fu_firmware_set_idx(isp_drv_img, FU_KT_FW_IMG_IDX_ISP_DRV);
	fu_firmware_add_image(self, isp_drv_img);
	g_debug("ISP driver image added to list");

	/* add App FW as a new image into firmware */
	app_fw_payload = g_bytes_new_from_bytes(fw_bytes,
						HEADER_LEN_ISP_DRV_SIZE + priv->isp_drv_size,
						app_fw_payload_size);

	/* figure out which chip App FW it is for */
	g_debug("figuring out what chip the App firmware is for");
	buf = g_bytes_get_data(app_fw_payload, &bufsz);
	if (!fu_kinetic_dp_firmware_get_chip_id_from_fw_buf(buf,
							    bufsz,
							    &priv->chip_id,
							    &priv->fw_bin_flag)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "no valid Chip ID is found in the firmware");
		return FALSE;
	}
	g_debug("Chip ID found in App firmware image");

	/* parse App FW based upon which chip it is for */
	if (priv->chip_id == KT_CHIP_JAGUAR_5000 || priv->chip_id == KT_CHIP_MUSTANG_5200) {
		g_debug("parsing Jaguar or Mustang App firmware starts...");
		if (!fu_kinetic_dp_secure_aux_isp_parse_app_fw(firmware,
							       buf,
							       bufsz,
							       priv->fw_bin_flag,
							       error)) {
			g_prefix_error(
			    error,
			    "failed to parse info from Jaguar or Mustang App firmware: ");
			return FALSE;
		}
	} else if (priv->chip_id == KT_CHIP_PUMA_2900) {
		g_debug("parsing Puma App firmware starts...");
		if (!fu_kinetic_dp_puma_aux_isp_parse_app_fw(firmware,
							     buf,
							     bufsz,
							     priv->fw_bin_flag,
							     error)) {
			g_prefix_error(error, "failed to parse info from Puma App firmware: ");
			return FALSE;
		}
	} else {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "found unsupported App firmware in firmware package.");
		return FALSE;
	}

	app_fw_img = fu_firmware_new_from_bytes(app_fw_payload);
	fu_firmware_set_idx(app_fw_img, FU_KT_FW_IMG_IDX_APP_FW);
	fu_firmware_add_image(self, app_fw_img);
	g_debug("App firmware image added to list");
	return TRUE;
}

static void
fu_kinetic_dp_firmware_init(FuKineticDpFirmware *self)
{
	FuKineticDpFirmwarePrivate *priv = GET_PRIVATE(self);

	priv->chip_id = KT_CHIP_NONE;
	priv->isp_drv_size = 0;
	priv->esm_payload_size = 0;
	priv->arm_app_code_size = 0;
	priv->app_init_data_size = 0;
	priv->cmdb_block_size = 0;
	priv->is_fw_esm_xip_enabled = FALSE;
	priv->fw_bin_flag = 0;
	g_debug("firmware instance initialized.");
}

static void
fu_kinetic_dp_firmware_class_init(FuKineticDpFirmwareClass *klass)
{
	FuFirmwareClass *klass_firmware = FU_FIRMWARE_CLASS(klass);
	klass_firmware->parse = fu_kinetic_dp_firmware_parse;
	g_debug("firmware class initialized.");
}

FuFirmware *
fu_kinetic_dp_firmware_new(void)
{
	g_debug("instantiate firmware...");
	return FU_FIRMWARE(g_object_new(FU_TYPE_KINETIC_DP_FIRMWARE, NULL));
}
