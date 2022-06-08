/*
 * Copyright (C) 2017 Mario Limonciello <mario.limonciello@dell.com>
 * Copyright (C) 2017 Peichen Huang <peichenhuang@tw.kinetic.com>
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2021 Jeffrey Lin <jlin@kinet-ic.com>
 * Copyright (C) 2022 Hai Su <hsu@kinet-ic.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include <fwupdplugin.h>

#include "fu-kinetic-dp-common.h"
#include "fu-kinetic-dp-device.h"
#include "fu-kinetic-dp-firmware.h"

#define FU_KINETIC_DP_DRM_REPLUG_DELAY 5 /* Unit: sec */

struct FuPluginData {
  GPtrArray *devices;
  guint drm_changed_id;
};

/* start scanning for device existance */
static void
fu_plugin_kinetic_dp_device_rescan(FuPlugin *plugin, FuDevice *device)
{
  const gchar* device_logical_id = fu_device_get_logical_id(device);
  g_autoptr(FuDeviceLocker) locker = NULL;
  g_autoptr(GError) error_local = NULL;

  /* open fd */
  g_debug("plugin scanning device logical id: %s",device_logical_id);
  locker = fu_device_locker_new(device, &error_local);
  if (locker == NULL) {
    g_debug("failed to open device %s: %s",device_logical_id,error_local->message);
    return;
  }
  /* scan device and add if found */
  if (!fu_device_rescan(device, &error_local)) {
    g_debug("no device found with id %s: %s",device_logical_id,error_local->message);
    if (fu_device_has_flag(device, FWUPD_DEVICE_FLAG_REGISTERED)){
      g_debug("plugin removed device id %s",device_logical_id);
      fu_plugin_device_remove(plugin, device);
    }
  } else {
    fu_plugin_device_add(plugin, device);
    g_debug("plugin added device id %s",device_logical_id);
  }
}

/* reprobe all existing devices added by this plugin */
static void
fu_plugin_kinetic_dp_rescan(FuPlugin *plugin)
{
  FuPluginData *priv = fu_plugin_get_data(plugin);
  g_debug("plugin rescan all devices...");
  for (guint i = 0; i < priv->devices->len; i++) {
    FuDevice *device = FU_DEVICE(g_ptr_array_index(priv->devices, i));
    fu_plugin_kinetic_dp_device_rescan(plugin, device);
  }
}

/* rescan after device changed (cold-plug) */
static gboolean
fu_plugin_kinetic_dp_rescan_cb(gpointer user_data)
{
  FuPlugin *plugin = FU_PLUGIN(user_data);
  FuPluginData *priv = fu_plugin_get_data(plugin);
  g_debug("plugin backend device changed callback to rescan.");
  fu_plugin_kinetic_dp_rescan(plugin);
  priv->drm_changed_id = 0;
  return FALSE;
}

/* device changes entry point */
static gboolean
fu_plugin_kinetic_dp_backend_device_changed(FuPlugin *plugin, 
                                                                                                            FuDevice *device, GError **error)
{
  FuPluginData *priv = fu_plugin_get_data(plugin);
  g_debug("plugin bankend device is changing...");

  /* check to see if this is device we care about? */
  if (!FU_IS_UDEV_DEVICE(device)){
    return TRUE;
  }
  if (g_strcmp0(fu_udev_device_get_subsystem(FU_UDEV_DEVICE(device)), "drm") != 0){
    return TRUE;
  }
  /* cold-plug again all drm_dp_aux_dev devices after a *long* delay */
  if (priv->drm_changed_id != 0){
    g_source_remove(priv->drm_changed_id);
  }
  priv->drm_changed_id = g_timeout_add_seconds(FU_KINETIC_DP_DRM_REPLUG_DELAY,
                                                                                                  fu_plugin_kinetic_dp_rescan_cb,plugin);
  return TRUE;
}

/*plugin entry point 3 to be call during scanning process */
static gboolean
fu_plugin_kinetic_dp_backend_device_added(FuPlugin *plugin, 
                                                                                                          FuDevice *device, GError **error)
{
  FuContext *ctx = fu_plugin_get_context(plugin);
  FuPluginData *priv = fu_plugin_get_data(plugin);
  g_autoptr(FuDeviceLocker) locker = NULL;
  g_autoptr(FuKineticDpDevice) dev = NULL;

  g_debug("plugin adding backend device...");
  /* check to see if this is device we care about? */
  if (!FU_IS_UDEV_DEVICE(device)){
    return TRUE;
  }
  /* instantiate a new device */
  dev = fu_kinetic_dp_device_new(FU_UDEV_DEVICE(device));
  locker = fu_device_locker_new(dev, error);
  if (locker == NULL){
    return FALSE;
  }
  /* for DeviceKind=system devices */
  fu_kinetic_dp_device_set_system_type(
                                            FU_KINETIC_DP_DEVICE(dev),
                                            fu_context_get_hwid_value(ctx, FU_HWIDS_KEY_PRODUCT_SKU));

  /* get fd and scan, it might fail if there is nothing connected */
  fu_plugin_kinetic_dp_device_rescan(plugin, FU_DEVICE(dev));

  /* add device to list to keep track */
  g_ptr_array_add(priv->devices, g_steal_pointer(&dev));

  return TRUE;
}

/* plugin starting point of firmware action */
static gboolean
fu_plugin_kinetic_dp_write_firmware(FuPlugin *plugin,
                                                                                                          FuDevice *device,
                                                                                                          GBytes *blob_fw,
                                                                                                          FuProgress *progress,
                                                                                                          FwupdInstallFlags flags,
                                                                                                          GError **error)
{
  g_autoptr(FuDeviceLocker) locker = fu_device_locker_new(device, error);
  g_debug("plugin write firmware starts...");
  if (locker == NULL){
    return FALSE;
  }
  if (!fu_device_write_firmware(device, blob_fw, progress, flags, error)){
    return FALSE;
  }
  return TRUE;
}

/* plugin entry point 2 register device type and firmware type*/
static void
fu_plugin_kinetic_dp_init(FuPlugin *plugin)
{
  FuPluginData *priv = fu_plugin_alloc_data(plugin, sizeof(FuPluginData));

  /* devices added by this plugin */
  priv->devices = g_ptr_array_new_with_free_func((GDestroyNotify)g_object_unref);

  fu_plugin_add_udev_subsystem(plugin, "drm");
  fu_plugin_add_udev_subsystem(plugin, "drm_dp_aux_dev");
  fu_plugin_add_firmware_gtype(plugin, NULL, FU_TYPE_KINETIC_DP_FIRMWARE);
  g_debug("plugin instance initialized.");
}

static void
fu_plugin_kinetic_dp_destroy(FuPlugin *plugin)
{
  FuPluginData *priv = fu_plugin_get_data(plugin);
  if (priv->drm_changed_id != 0){
    g_source_remove(priv->drm_changed_id);
   }
  g_ptr_array_unref(priv->devices);
  g_debug("plugin instance destroyed.");
}

/* plugin entry point 1 virtual functions setup*/
void
fu_plugin_init_vfuncs(FuPluginVfuncs *vfuncs)
{
  vfuncs->build_hash = FU_BUILD_HASH;
  vfuncs->init = fu_plugin_kinetic_dp_init;
  vfuncs->destroy = fu_plugin_kinetic_dp_destroy;
  vfuncs->write_firmware = fu_plugin_kinetic_dp_write_firmware;
  vfuncs->backend_device_added = fu_plugin_kinetic_dp_backend_device_added;
  vfuncs->backend_device_changed = fu_plugin_kinetic_dp_backend_device_changed;
  g_debug("plugin virtual functions realized.");
}
