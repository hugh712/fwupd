/*
 * Copyright (C) 2020 Benson Leung <bleung@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <string.h>

#include "fu-cros-ec-common.h"
#include "fu-cros-ec-firmware.h"
#include "fu-cros-ec-usb-device.h"

#define USB_SUBCLASS_GOOGLE_UPDATE 0x53
#define USB_PROTOCOL_GOOGLE_UPDATE 0xff

#define SETUP_RETRY_CNT			  5
#define MAX_BLOCK_XFER_RETRIES		  10
#define FLUSH_TIMEOUT_MS		  10
#define BULK_SEND_TIMEOUT_MS		  2000
#define BULK_RECV_TIMEOUT_MS		  5000
#define CROS_EC_REMOVE_DELAY_RE_ENUMERATE 20000

#define UPDATE_DONE	 0xB007AB1E
#define UPDATE_EXTRA_CMD 0xB007AB1F

enum update_extra_command {
	UPDATE_EXTRA_CMD_IMMEDIATE_RESET = 0,
	UPDATE_EXTRA_CMD_JUMP_TO_RW = 1,
	UPDATE_EXTRA_CMD_STAY_IN_RO = 2,
	UPDATE_EXTRA_CMD_UNLOCK_RW = 3,
	UPDATE_EXTRA_CMD_UNLOCK_ROLLBACK = 4,
	UPDATE_EXTRA_CMD_INJECT_ENTROPY = 5,
	UPDATE_EXTRA_CMD_PAIR_CHALLENGE = 6,
	UPDATE_EXTRA_CMD_TOUCHPAD_INFO = 7,
	UPDATE_EXTRA_CMD_TOUCHPAD_DEBUG = 8,
	UPDATE_EXTRA_CMD_CONSOLE_READ_INIT = 9,
	UPDATE_EXTRA_CMD_CONSOLE_READ_NEXT = 10,
};

struct _FuCrosEcUsbDevice {
	FuUsbDevice parent_instance;
	guint8 iface_idx;  /* bInterfaceNumber */
	guint8 ep_num;	   /* bEndpointAddress */
	guint16 chunk_len; /* wMaxPacketSize */

	struct first_response_pdu targ;
	guint32 writeable_offset;
	guint16 protocol_version;
	guint16 header_type;
	struct cros_ec_version version;	       /* version of other region */
	struct cros_ec_version active_version; /* version of active region */
	gchar configuration[FU_CROS_EC_STRLEN];
	gboolean in_bootloader;
};

G_DEFINE_TYPE(FuCrosEcUsbDevice, fu_cros_ec_usb_device, FU_TYPE_USB_DEVICE)

typedef union _START_RESP {
	struct first_response_pdu rpdu;
	guint32 legacy_resp;
} START_RESP;

typedef struct {
	FuChunk *block;
	FuProgress *progress;
} FuCrosEcUsbBlockHelper;

#define FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN	   (1 << 0)
#define FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN	   (1 << 1)
#define FU_CROS_EC_USB_DEVICE_FLAG_REBOOTING_TO_RO (1 << 2)
#define FU_CROS_EC_USB_DEVICE_FLAG_SPECIAL	   (1 << 3)

static gboolean
fu_cros_ec_usb_device_get_configuration(FuCrosEcUsbDevice *self, GError **error)
{
	GUsbDevice *usb_device = fu_usb_device_get_dev(FU_USB_DEVICE(self));
	guint8 index;
	g_autofree gchar *configuration = NULL;

#if G_USB_CHECK_VERSION(0, 3, 5)
	index = g_usb_device_get_configuration_index(usb_device);
#else
	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "this version of GUsb is not supported");
	return FALSE;
#endif
	configuration = g_usb_device_get_string_descriptor(usb_device, index, error);
	if (configuration == NULL)
		return FALSE;

	if (g_strlcpy(self->configuration, configuration, FU_CROS_EC_STRLEN) == 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "empty iConfiguration");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_find_interface(FuUsbDevice *device, GError **error)
{
#if G_USB_CHECK_VERSION(0, 3, 3)
	GUsbDevice *usb_device = fu_usb_device_get_dev(device);
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	g_autoptr(GPtrArray) intfs = NULL;

	/* based on usb_updater2's find_interfacei() and find_endpoint() */

	intfs = g_usb_device_get_interfaces(usb_device, error);
	if (intfs == NULL)
		return FALSE;
	for (guint i = 0; i < intfs->len; i++) {
		GUsbInterface *intf = g_ptr_array_index(intfs, i);
		if (g_usb_interface_get_class(intf) == 255 &&
		    g_usb_interface_get_subclass(intf) == USB_SUBCLASS_GOOGLE_UPDATE &&
		    g_usb_interface_get_protocol(intf) == USB_PROTOCOL_GOOGLE_UPDATE) {
			GUsbEndpoint *ep;
			g_autoptr(GPtrArray) endpoints = NULL;

			endpoints = g_usb_interface_get_endpoints(intf);
			if (NULL == endpoints || 0 == endpoints->len)
				continue;
			ep = g_ptr_array_index(endpoints, 0);
			self->iface_idx = g_usb_interface_get_number(intf);
			self->ep_num = g_usb_endpoint_get_address(ep) & 0x7f;
			self->chunk_len = g_usb_endpoint_get_maximum_packet_size(ep);

			return TRUE;
		}
	}
	g_set_error_literal(error, FWUPD_ERROR, FWUPD_ERROR_NOT_FOUND, "no update interface found");
	return FALSE;
#else
	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "this version of GUsb is not supported");
	return FALSE;
#endif
}

static gboolean
fu_cros_ec_usb_device_probe(FuDevice *device, GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);

	/* very much like usb_updater2's usb_findit() */

	if (!fu_cros_ec_usb_device_find_interface(FU_USB_DEVICE(device), error)) {
		g_prefix_error(error, "failed to find update interface: ");
		return FALSE;
	}
	fu_usb_device_add_interface(FU_USB_DEVICE(self), self->iface_idx);

	if (self->chunk_len == 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "wMaxPacketSize isn't valid: %" G_GUINT16_FORMAT,
			    self->chunk_len);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_do_xfer(FuCrosEcUsbDevice *self,
			      const guint8 *outbuf,
			      gsize outlen,
			      guint8 *inbuf,
			      gsize inlen,
			      gboolean allow_less,
			      gsize *rxed_count,
			      GError **error)
{
	GUsbDevice *usb_device = fu_usb_device_get_dev(FU_USB_DEVICE(self));
	gsize actual = 0;

	/* send data out */
	if (outbuf != NULL && outlen > 0) {
		g_autofree guint8 *outbuf_tmp = NULL;

		/* make mutable */
		outbuf_tmp = fu_memdup_safe(outbuf, outlen, error);
		if (outbuf_tmp == NULL)
			return FALSE;

		if (!g_usb_device_bulk_transfer(usb_device,
						self->ep_num,
						outbuf_tmp,
						outlen,
						&actual,
						BULK_SEND_TIMEOUT_MS,
						NULL,
						error)) {
			return FALSE;
		}
		if (actual != outlen) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_PARTIAL_INPUT,
				    "only sent %" G_GSIZE_FORMAT "/%" G_GSIZE_FORMAT " bytes",
				    actual,
				    outlen);
			return FALSE;
		}
	}

	/* read reply back */
	if (inbuf != NULL && inlen > 0) {
		actual = 0;
		if (!g_usb_device_bulk_transfer(usb_device,
						self->ep_num | 0x80,
						inbuf,
						inlen,
						&actual,
						BULK_RECV_TIMEOUT_MS,
						NULL,
						error)) {
			return FALSE;
		}
		if (actual != inlen && !allow_less) {
			g_set_error(error,
				    G_IO_ERROR,
				    G_IO_ERROR_PARTIAL_INPUT,
				    "only received %" G_GSIZE_FORMAT "/%" G_GSIZE_FORMAT " bytes",
				    actual,
				    inlen);
			return FALSE;
		}
	}

	if (rxed_count != NULL)
		*rxed_count = actual;

	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_flush(FuDevice *device, gpointer user_data, GError **error)
{
	GUsbDevice *usb_device = fu_usb_device_get_dev(FU_USB_DEVICE(device));
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	gsize actual = 0;
	g_autofree guint8 *inbuf = g_malloc0(self->chunk_len);

	/* bulk transfer expected to fail normally (ie, no stale data)
	 * but if bulk transfer succeeds, indicates stale bytes on the device
	 * so this will retry until they're emptied */
	if (g_usb_device_bulk_transfer(usb_device,
				       self->ep_num | 0x80,
				       inbuf,
				       self->chunk_len,
				       &actual,
				       FLUSH_TIMEOUT_MS,
				       NULL,
				       NULL)) {
		g_debug("flushing %" G_GSIZE_FORMAT " bytes", actual);
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "flushing %" G_GSIZE_FORMAT " bytes",
			    actual);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_recovery(FuDevice *device, GError **error)
{
	/* flush all data from endpoint to recover in case of error */
	if (!fu_device_retry(device, fu_cros_ec_usb_device_flush, SETUP_RETRY_CNT, NULL, error)) {
		g_prefix_error(error, "failed to flush device to idle state: ");
		return FALSE;
	}

	/* success */
	return TRUE;
}

/*
 * Channel TPM extension/vendor command over USB. The payload of the USB frame
 * in this case consists of the 2 byte subcommand code concatenated with the
 * command body. The caller needs to indicate if a response is expected, and
 * if it is - of what maximum size.
 */
static gboolean
fu_cros_ec_usb_ext_cmd(FuDevice *device,
		       guint16 subcommand,
		       gpointer cmd_body,
		       gsize body_size,
		       gpointer resp,
		       gsize *resp_size,
		       gboolean allow_less,
		       GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	guint16 *frame_ptr;
	gsize usb_msg_size = sizeof(struct update_frame_header) + sizeof(subcommand) + body_size;
	g_autofree struct update_frame_header *ufh = g_malloc0(usb_msg_size);

	ufh->block_size = GUINT32_TO_BE(usb_msg_size);
	ufh->cmd.block_digest = 0;
	ufh->cmd.block_base = GUINT32_TO_BE(UPDATE_EXTRA_CMD);
	frame_ptr = (guint16 *)(ufh + 1);
	*frame_ptr = GUINT16_TO_BE(subcommand);

	if (body_size != 0) {
		gsize offset = sizeof(struct update_frame_header) + sizeof(subcommand);
		if (!fu_memcpy_safe((guint8 *)ufh,
				    usb_msg_size,
				    offset,
				    (const guint8 *)cmd_body,
				    body_size,
				    0x0,
				    body_size,
				    error))
			return FALSE;
	}

	return fu_cros_ec_usb_device_do_xfer(self,
					     (const guint8 *)ufh,
					     usb_msg_size,
					     (guint8 *)resp,
					     resp_size != NULL ? *resp_size : 0,
					     TRUE,
					     NULL,
					     error);
}

static gboolean
fu_cros_ec_usb_device_start_request(FuDevice *device, gpointer user_data, GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	guint8 *start_resp = (guint8 *)user_data;
	struct update_frame_header ufh;
	gsize rxed_size = 0;

	memset(&ufh, 0, sizeof(ufh));
	ufh.block_size = GUINT32_TO_BE(sizeof(ufh));
	if (!fu_cros_ec_usb_device_do_xfer(self,
					   (const guint8 *)&ufh,
					   sizeof(ufh),
					   start_resp,
					   sizeof(START_RESP),
					   TRUE,
					   &rxed_size,
					   error))
		return FALSE;

	/* we got something, so check for errors in response */
	if (rxed_size < 8) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_PARTIAL_INPUT,
			    "unexpected response size %" G_GSIZE_FORMAT,
			    rxed_size);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_setup(FuDevice *device, GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	guint32 error_code;
	START_RESP start_resp;
	g_auto(GStrv) config_split = NULL;

	/* FuUsbDevice->setup */
	if (!FU_DEVICE_CLASS(fu_cros_ec_usb_device_parent_class)->setup(device, error))
		return FALSE;

	if (!fu_cros_ec_usb_device_recovery(device, error))
		return FALSE;

	/* send start request */
	if (!fu_device_retry(device,
			     fu_cros_ec_usb_device_start_request,
			     SETUP_RETRY_CNT,
			     &start_resp,
			     error)) {
		g_prefix_error(error, "failed to send start request: ");
		return FALSE;
	}

	self->protocol_version = GUINT16_FROM_BE(start_resp.rpdu.protocol_version);

	if (self->protocol_version < 5 || self->protocol_version > 6) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_NOT_SUPPORTED,
			    "unsupported protocol version %d",
			    self->protocol_version);
		return FALSE;
	}
	self->header_type = GUINT16_FROM_BE(start_resp.rpdu.header_type);

	error_code = GUINT32_FROM_BE(start_resp.rpdu.return_value);
	if (error_code != 0) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "target reporting error %u",
			    error_code);
		return FALSE;
	}

	self->writeable_offset = GUINT32_FROM_BE(start_resp.rpdu.common.offset);
	if (!fu_memcpy_safe((guint8 *)self->targ.common.version,
			    FU_CROS_EC_STRLEN,
			    0x0,
			    (const guint8 *)start_resp.rpdu.common.version,
			    sizeof(start_resp.rpdu.common.version),
			    0x0,
			    sizeof(start_resp.rpdu.common.version),
			    error))
		return FALSE;
	self->targ.common.maximum_pdu_size =
	    GUINT32_FROM_BE(start_resp.rpdu.common.maximum_pdu_size);
	self->targ.common.flash_protection =
	    GUINT32_FROM_BE(start_resp.rpdu.common.flash_protection);
	self->targ.common.min_rollback = GINT32_FROM_BE(start_resp.rpdu.common.min_rollback);
	self->targ.common.key_version = GUINT32_FROM_BE(start_resp.rpdu.common.key_version);

	/* get active version string and running region from iConfiguration */
	if (!fu_cros_ec_usb_device_get_configuration(self, error))
		return FALSE;
	config_split = g_strsplit(self->configuration, ":", 2);
	if (g_strv_length(config_split) < 2) {
		/* no prefix found so fall back to offset */
		self->in_bootloader = self->writeable_offset != 0x0;
		if (!fu_cros_ec_parse_version(self->configuration, &self->active_version, error)) {
			g_prefix_error(error,
				       "failed parsing device's version: %32s: ",
				       self->configuration);
			return FALSE;
		}
	} else {
		self->in_bootloader = g_strcmp0("RO", config_split[0]) == 0;
		if (!fu_cros_ec_parse_version(config_split[1], &self->active_version, error)) {
			g_prefix_error(error,
				       "failed parsing device's version: %32s: ",
				       config_split[1]);
			return FALSE;
		}
	}

	/* get the other region's version string from targ */
	if (!fu_cros_ec_parse_version(self->targ.common.version, &self->version, error)) {
		g_prefix_error(error,
			       "failed parsing device's version: %32s: ",
			       self->targ.common.version);
		return FALSE;
	}

	if (self->in_bootloader) {
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
		fu_device_set_version(FU_DEVICE(device), self->version.triplet);
		fu_device_set_version_bootloader(FU_DEVICE(device), self->active_version.triplet);
	} else {
		fu_device_remove_flag(device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
		fu_device_set_version(FU_DEVICE(device), self->active_version.triplet);
		fu_device_set_version_bootloader(FU_DEVICE(device), self->version.triplet);
	}
	fu_device_add_instance_id(FU_DEVICE(device), self->version.boardname);

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_transfer_block(FuDevice *device, gpointer user_data, GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	FuCrosEcUsbBlockHelper *helper = (FuCrosEcUsbBlockHelper *)user_data;
	gsize transfer_size = 0;
	guint32 reply = 0;
	g_autoptr(GPtrArray) chunks = NULL;
	struct update_frame_header ufh = {
	    .block_size = GUINT32_TO_BE(fu_chunk_get_data_sz(helper->block) +
					sizeof(struct update_frame_header)),
	    .cmd.block_base = GUINT32_TO_BE(fu_chunk_get_address(helper->block)),
	    .cmd.block_digest = 0,
	};

	/* first send the header */
	if (!fu_cros_ec_usb_device_do_xfer(self,
					   (const guint8 *)&ufh,
					   sizeof(struct update_frame_header),
					   NULL,
					   0,
					   FALSE,
					   NULL,
					   error)) {
		g_autoptr(GError) error_flush = NULL;
		/* flush all data from endpoint to recover in case of error */
		if (!fu_cros_ec_usb_device_recovery(device, &error_flush)) {
			g_debug("failed to flush to idle: %s", error_flush->message);
		}
		g_prefix_error(error, "failed at sending header: ");
		return FALSE;
	}

	/* send the block, chunk by chunk */
	chunks = fu_chunk_array_new(fu_chunk_get_data(helper->block),
				    fu_chunk_get_data_sz(helper->block),
				    0x00,
				    0x00,
				    self->chunk_len);
	fu_progress_set_id(helper->progress, G_STRLOC);
	fu_progress_set_steps(helper->progress, chunks->len);
	for (guint i = 0; i < chunks->len; i++) {
		FuChunk *chk = g_ptr_array_index(chunks, i);

		if (!fu_cros_ec_usb_device_do_xfer(self,
						   fu_chunk_get_data(chk),
						   fu_chunk_get_data_sz(chk),
						   NULL,
						   0,
						   FALSE,
						   NULL,
						   error)) {
			g_autoptr(GError) error_flush = NULL;
			g_prefix_error(error, "failed sending chunk 0x%x: ", i);

			/* flush all data from endpoint to recover in case of error */
			if (!fu_cros_ec_usb_device_recovery(device, &error_flush)) {
				g_debug("failed to flush to idle: %s", error_flush->message);
			}
			return FALSE;
		}
		fu_progress_step_done(helper->progress);
	}

	/* get the reply */
	if (!fu_cros_ec_usb_device_do_xfer(self,
					   NULL,
					   0,
					   (guint8 *)&reply,
					   sizeof(reply),
					   TRUE,
					   &transfer_size,
					   error)) {
		g_autoptr(GError) error_flush = NULL;
		g_prefix_error(error, "failed at reply: ");
		/* flush all data from endpoint to recover in case of error */
		if (!fu_cros_ec_usb_device_recovery(device, &error_flush)) {
			g_debug("failed to flush to idle: %s", error_flush->message);
		}
		return FALSE;
	}
	if (transfer_size == 0) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_FAILED,
				    "zero bytes received for block reply");
		return FALSE;
	}
	if (reply != 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "error: status 0x%#x", reply);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_transfer_section(FuDevice *device,
				       FuFirmware *firmware,
				       FuCrosEcFirmwareSection *section,
				       FuProgress *progress,
				       GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	const guint8 *data_ptr = NULL;
	gsize data_len = 0;
	g_autoptr(GBytes) img_bytes = NULL;
	g_autoptr(GPtrArray) blocks = NULL;

	g_return_val_if_fail(section != NULL, FALSE);

	img_bytes = fu_firmware_get_image_by_idx_bytes(firmware, section->image_idx, error);
	if (img_bytes == NULL) {
		g_prefix_error(error, "failed to find section image: ");
		return FALSE;
	}

	data_ptr = (const guint8 *)g_bytes_get_data(img_bytes, &data_len);
	if (data_ptr == NULL || data_len != section->size) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "image and section sizes do not match: image = %" G_GSIZE_FORMAT
			    " bytes vs section size = %" G_GSIZE_FORMAT " bytes",
			    data_len,
			    section->size);
		return FALSE;
	}

	/* smart update: trim trailing bytes */
	while (data_len != 0 && (data_ptr[data_len - 1] == 0xff))
		data_len--;
	g_debug("trimmed %" G_GSIZE_FORMAT " trailing bytes", section->size - data_len);
	g_debug("sending 0x%zx bytes to %#x", data_len, section->offset);

	/* send in chunks of PDU size */
	blocks = fu_chunk_array_new(data_ptr,
				    data_len,
				    section->offset,
				    0x0,
				    self->targ.common.maximum_pdu_size);
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_steps(progress, blocks->len);
	for (guint i = 0; i < blocks->len; i++) {
		FuCrosEcUsbBlockHelper helper = {
		    .block = g_ptr_array_index(blocks, i),
		    .progress = fu_progress_get_child(progress),
		};
		if (!fu_device_retry(device,
				     fu_cros_ec_usb_device_transfer_block,
				     MAX_BLOCK_XFER_RETRIES,
				     &helper,
				     error)) {
			g_prefix_error(error, "failed to transfer block 0x%x: ", i);
			return FALSE;
		}
		fu_progress_step_done(progress);
	}

	/* success */
	return TRUE;
}

static void
fu_cros_ec_usb_device_send_done(FuDevice *device)
{
	guint32 out = GUINT32_TO_BE(UPDATE_DONE);
	g_autoptr(GError) error_local = NULL;

	/* send stop request, ignoring reply */
	if (!fu_cros_ec_usb_device_do_xfer(FU_CROS_EC_USB_DEVICE(device),
					   (const guint8 *)&out,
					   sizeof(out),
					   (guint8 *)&out,
					   1,
					   FALSE,
					   NULL,
					   &error_local)) {
		g_debug("error on transfer of done: %s", error_local->message);
	}
}

static gboolean
fu_cros_ec_usb_device_send_subcommand(FuDevice *device,
				      guint16 subcommand,
				      gpointer cmd_body,
				      gsize body_size,
				      gpointer resp,
				      gsize *resp_size,
				      gboolean allow_less,
				      GError **error)
{
	fu_cros_ec_usb_device_send_done(device);

	if (!fu_cros_ec_usb_ext_cmd(device,
				    subcommand,
				    cmd_body,
				    body_size,
				    resp,
				    resp_size,
				    FALSE,
				    error)) {
		g_prefix_error(error,
			       "failed to send subcommand %" G_GUINT16_FORMAT ": ",
			       subcommand);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_reset_to_ro(FuDevice *device, GError **error)
{
	guint8 response;
	guint16 subcommand = UPDATE_EXTRA_CMD_IMMEDIATE_RESET;
	guint8 command_body[2]; /* Max command body size. */
	gsize command_body_size = 0;
	gsize response_size = 1;
	g_autoptr(GError) error_local = NULL;

	fu_device_add_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_REBOOTING_TO_RO);
	if (!fu_cros_ec_usb_device_send_subcommand(device,
						   subcommand,
						   command_body,
						   command_body_size,
						   &response,
						   &response_size,
						   FALSE,
						   &error_local)) {
		/* failure here is ok */
		g_debug("ignoring failure: %s", error_local->message);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_jump_to_rw(FuDevice *device)
{
	guint8 response;
	guint16 subcommand = UPDATE_EXTRA_CMD_JUMP_TO_RW;
	guint8 command_body[2]; /* Max command body size. */
	gsize command_body_size = 0;
	gsize response_size = 1;

	if (!fu_cros_ec_usb_device_send_subcommand(device,
						   subcommand,
						   command_body,
						   command_body_size,
						   &response,
						   &response_size,
						   FALSE,
						   NULL)) {
		/* bail out early here if subcommand failed, which is normal */
		return TRUE;
	}

	/* Jump to rw may not work, so if we've reached here, initiate a
	 * full reset using immediate reset */
	subcommand = UPDATE_EXTRA_CMD_IMMEDIATE_RESET;
	fu_cros_ec_usb_device_send_subcommand(device,
					      subcommand,
					      command_body,
					      command_body_size,
					      &response,
					      &response_size,
					      FALSE,
					      NULL);

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_write_firmware(FuDevice *device,
				     FuFirmware *firmware,
				     FuProgress *progress,
				     FwupdInstallFlags flags,
				     GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	g_autoptr(GPtrArray) sections = NULL;
	FuCrosEcFirmware *cros_ec_firmware = FU_CROS_EC_FIRMWARE(firmware);

	fu_device_remove_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_SPECIAL);

	if (fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_REBOOTING_TO_RO)) {
		gsize response_size = 1;
		guint8 response;
		guint16 subcommand = UPDATE_EXTRA_CMD_STAY_IN_RO;
		guint8 command_body[2]; /* Max command body size. */
		gsize command_body_size = 0;
		START_RESP start_resp;

		fu_device_remove_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_REBOOTING_TO_RO);
		if (!fu_cros_ec_usb_device_send_subcommand(device,
							   subcommand,
							   command_body,
							   command_body_size,
							   &response,
							   &response_size,
							   FALSE,
							   error)) {
			g_prefix_error(error, "failed to send stay-in-ro subcommand: ");
			return FALSE;
		}

		/* flush all data from endpoint to recover in case of error */
		if (!fu_cros_ec_usb_device_recovery(device, error)) {
			g_prefix_error(error, "failed to flush device to idle state: ");
			return FALSE;
		}

		/* send start request */
		if (!fu_device_retry(device,
				     fu_cros_ec_usb_device_start_request,
				     SETUP_RETRY_CNT,
				     &start_resp,
				     error)) {
			g_prefix_error(error, "failed to send start request: ");
			return FALSE;
		}
	}

	if (fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN) &&
	    self->in_bootloader) {
		/*
		 * We had previously written to the rw region (while we were
		 * booted from ro region), but somehow landed in ro again after
		 * a reboot. Since we wrote rw already, we wanted to jump
		 * to the new rw so we could evaluate ro.
		 *
		 * This is a transitory state due to the fact that we have to
		 * boot through RO to get to RW. Set another write required to
		 * allow the RO region to auto-jump to RW.
		 *
		 * Special flow: write phase skips actual write -> attach skips
		 * send of reset command, just sets wait for replug, and
		 * device restart status.
		 */
		fu_device_add_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_SPECIAL);
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_ANOTHER_WRITE_REQUIRED);
		return TRUE;
	}

	sections = fu_cros_ec_firmware_get_needed_sections(cros_ec_firmware, error);
	if (sections == NULL)
		return FALSE;

	/* progress */
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_steps(progress, sections->len);
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_WRITE);
	for (guint i = 0; i < sections->len; i++) {
		FuCrosEcFirmwareSection *section = g_ptr_array_index(sections, i);
		g_autoptr(GError) error_local = NULL;

		if (!fu_cros_ec_usb_device_transfer_section(device,
							    firmware,
							    section,
							    fu_progress_get_child(progress),
							    &error_local)) {
			if (g_error_matches(error_local,
					    G_USB_DEVICE_ERROR,
					    G_USB_DEVICE_ERROR_NOT_SUPPORTED)) {
				g_debug("failed to transfer section, trying another write, "
					"ignoring error: %s",
					error_local->message);
				fu_device_add_flag(device,
						   FWUPD_DEVICE_FLAG_ANOTHER_WRITE_REQUIRED);
				fu_progress_finished(progress);
				return TRUE;
			}
			g_propagate_error(error, g_steal_pointer(&error_local));
			return FALSE;
		}

		if (self->in_bootloader) {
			fu_device_set_version(FU_DEVICE(device), section->version.triplet);
		} else {
			fu_device_set_version_bootloader(FU_DEVICE(device),
							 section->version.triplet);
		}

		fu_progress_step_done(progress);
	}
	/* send done */
	fu_cros_ec_usb_device_send_done(device);

	if (self->in_bootloader)
		fu_device_add_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN);
	else
		fu_device_add_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN);

	/* logical XOR */
	if (fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN) !=
	    fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN))
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_ANOTHER_WRITE_REQUIRED);

	/* success */
	return TRUE;
}

static FuFirmware *
fu_cros_ec_usb_device_prepare_firmware(FuDevice *device,
				       GBytes *fw,
				       FwupdInstallFlags flags,
				       GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	FuCrosEcFirmware *cros_ec_firmware = NULL;
	g_autoptr(FuFirmware) firmware = fu_cros_ec_firmware_new();

	if (!fu_firmware_parse(firmware, fw, flags, error))
		return NULL;
	cros_ec_firmware = FU_CROS_EC_FIRMWARE(firmware);

	/* pick sections */
	if (!fu_cros_ec_firmware_pick_sections(cros_ec_firmware, self->writeable_offset, error)) {
		g_prefix_error(error, "failed to pick sections: ");
		return NULL;
	}
	return g_steal_pointer(&firmware);
}

static gboolean
fu_cros_ec_usb_device_attach(FuDevice *device, FuProgress *progress, GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);

	fu_device_set_remove_delay(device, CROS_EC_REMOVE_DELAY_RE_ENUMERATE);
	if (self->in_bootloader &&
	    fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_SPECIAL)) {
		/*
		 * attach after the SPECIAL flag was set. The EC will auto-jump
		 * from ro -> rw, so we do not need to send an explicit
		 * reset_to_ro. We just need to set for another wait for replug
		 * as a detach + reenumeration is expected as we jump from
		 * ro -> rw.
		 */
		fu_device_remove_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_SPECIAL);
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);
		return TRUE;
	}

	if (fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN) &&
	    !fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN)) {
		if (!fu_cros_ec_usb_device_reset_to_ro(device, error)) {
			return FALSE;
		}
	} else {
		fu_cros_ec_usb_device_jump_to_rw(device);
	}
	fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);

	/* success */
	return TRUE;
}

static gboolean
fu_cros_ec_usb_device_detach(FuDevice *device, FuProgress *progress, GError **error)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);

	if (fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN) &&
	    !fu_device_has_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN))
		return TRUE;

	if (self->in_bootloader) {
		g_debug("skipping immediate reboot in case of already in bootloader");
		/* in RO so skip reboot */
		return TRUE;
	} else if (self->targ.common.flash_protection != 0x0) {
		/* in RW, and RO region is write protected, so jump to RO */
		fu_device_add_private_flag(device, FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN);
		fu_device_set_remove_delay(device, CROS_EC_REMOVE_DELAY_RE_ENUMERATE);
		if (!fu_cros_ec_usb_device_reset_to_ro(device, error))
			return FALSE;
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);
	}

	/* success */
	return TRUE;
}

static void
fu_cros_ec_usb_device_init(FuCrosEcUsbDevice *self)
{
	fu_device_add_protocol(FU_DEVICE(self), "com.google.usb.crosec");
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_REPLUG_MATCH_GUID);
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_DUAL_IMAGE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_SIGNED_PAYLOAD);
	fu_device_register_private_flag(FU_DEVICE(self),
					FU_CROS_EC_USB_DEVICE_FLAG_RO_WRITTEN,
					"ro-written");
	fu_device_register_private_flag(FU_DEVICE(self),
					FU_CROS_EC_USB_DEVICE_FLAG_RW_WRITTEN,
					"rw-written");
	fu_device_register_private_flag(FU_DEVICE(self),
					FU_CROS_EC_USB_DEVICE_FLAG_REBOOTING_TO_RO,
					"rebooting-to-ro");
	fu_device_register_private_flag(FU_DEVICE(self),
					FU_CROS_EC_USB_DEVICE_FLAG_SPECIAL,
					"special");
}

static void
fu_cros_ec_usb_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuCrosEcUsbDevice *self = FU_CROS_EC_USB_DEVICE(device);
	g_autofree gchar *min_rollback = NULL;

	fu_string_append(str, idt, "GitHash", self->version.sha1);
	fu_string_append_kb(str, idt, "Dirty", self->version.dirty);
	fu_string_append_ku(str, idt, "ProtocolVersion", self->protocol_version);
	fu_string_append_ku(str, idt, "HeaderType", self->header_type);
	fu_string_append_ku(str, idt, "MaxPDUSize", self->targ.common.maximum_pdu_size);
	fu_string_append_kx(str, idt, "FlashProtectionStatus", self->targ.common.flash_protection);
	fu_string_append(str, idt, "RawVersion", self->targ.common.version);
	fu_string_append_ku(str, idt, "KeyVersion", self->targ.common.key_version);
	min_rollback = g_strdup_printf("%" G_GINT32_FORMAT, self->targ.common.min_rollback);
	fu_string_append(str, idt, "MinRollback", min_rollback);
	fu_string_append_kx(str, idt, "WriteableOffset", self->writeable_offset);
}

static void
fu_cros_ec_usb_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 2, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 94, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 2, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 2, "reload");
}

static void
fu_cros_ec_usb_device_class_init(FuCrosEcUsbDeviceClass *klass)
{
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);
	klass_device->attach = fu_cros_ec_usb_device_attach;
	klass_device->detach = fu_cros_ec_usb_device_detach;
	klass_device->prepare_firmware = fu_cros_ec_usb_device_prepare_firmware;
	klass_device->setup = fu_cros_ec_usb_device_setup;
	klass_device->to_string = fu_cros_ec_usb_device_to_string;
	klass_device->write_firmware = fu_cros_ec_usb_device_write_firmware;
	klass_device->probe = fu_cros_ec_usb_device_probe;
	klass_device->set_progress = fu_cros_ec_usb_device_set_progress;
}
