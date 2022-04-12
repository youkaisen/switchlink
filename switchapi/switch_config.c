/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2019 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/

/* Local header includes */
#include "switch_internal.h"
#include "switch_config_int.h"
#include <openvswitch/vlog.h>
#include <config.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define __FILE_ID__ SWITCH_CONFIG
switch_config_info_t config_info;
VLOG_DEFINE_THIS_MODULE(switch_config);

switch_status_t switch_config_init(switch_config_t *switch_config) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (config_info.config_inited) {
    status = SWITCH_STATUS_ITEM_ALREADY_EXISTS;
    VLOG_ERR("config init failed : %s", switch_error_to_string(status));
    return status;
  }

  SWITCH_MEMSET(&config_info, 0x0, sizeof(config_info));

  config_info.api_switch_config.max_devices = SWITCH_MAX_DEVICE;
  config_info.api_switch_config.add_ports = FALSE;
  config_info.api_switch_config.default_port_speed = SWITCH_PORT_SPEED_10G;
  config_info.api_switch_config.program_smac = TRUE;
  //config_info.api_switch_config.default_log_level = SWITCH_LOG_LEVEL_ERROR;
  //config_info.api_switch_config.default_stp_state =
  //    SWITCH_PORT_STP_STATE_FORWARDING;
  //SWITCH_MEMCPY(config_info.api_switch_config.cpu_interface,
  //              SWITCH_CPU_ETH_INTF_DEFAULT,
  //              SWITCH_CPU_ETH_INTF_DEFAULT_LEN);

  if (switch_config) {
    SWITCH_ASSERT(switch_config->max_devices < SWITCH_MAX_DEVICE);
    if (switch_config->max_devices) {
      config_info.api_switch_config.max_devices = switch_config->max_devices;
    }

    if (!switch_config->use_pcie) {
      SWITCH_MEMCPY(config_info.api_switch_config.cpu_interface,
                    switch_config->cpu_interface,
                    SWITCH_HOSTIF_NAME_SIZE);
    }

    if (switch_config->add_ports) {
      config_info.api_switch_config.add_ports = switch_config->add_ports;
      config_info.api_switch_config.default_port_speed =
          switch_config->default_port_speed;
    }

    config_info.api_switch_config.enable_ports = switch_config->enable_ports;
    config_info.api_switch_config.use_pcie = switch_config->use_pcie;
    config_info.api_switch_config.program_smac = switch_config->program_smac;
    config_info.api_switch_config.acl_group_optimization =
        switch_config->acl_group_optimization;
  }

  SWITCH_ASSERT(config_info.api_switch_config.max_devices != 0);

  config_info.config_inited = TRUE;

  //switch_log_init(config_info.api_switch_config.default_log_level);

  return status;
}

switch_status_t switch_config_free(void) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!config_info.config_inited) {
    return status;
  }

  config_info.config_inited = FALSE;

  SWITCH_MEMSET(&config_info, 0x0, sizeof(config_info));

  return status;
}

switch_status_t switch_config_device_context_set(
    switch_device_t device, switch_device_context_t *device_ctx) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (device_ctx && config_info.device_inited[device]) {
    status = SWITCH_STATUS_ITEM_ALREADY_EXISTS;
    VLOG_ERR("config free failed for device %d: %s",
                     device,
                     switch_error_to_string(status));
    return status;
  }

  if (device_ctx) {
    config_info.device_ctx[device] = device_ctx;
    config_info.device_inited[device] = TRUE;
  } else {
    config_info.device_ctx[device] = NULL;
    config_info.device_inited[device] = FALSE;
  }

  return status;
}

switch_status_t switch_config_device_context_get(
    switch_device_t device, switch_device_context_t **device_ctx) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!config_info.device_inited[device]) {
    status = SWITCH_STATUS_UNINITIALIZED;
    VLOG_ERR("config free failed for device %d: %s",
                     device,
                     switch_error_to_string(status));
    return status;
  }

  *device_ctx = config_info.device_ctx[device];

  return status;
}

switch_status_t switch_config_table_sizes_get(switch_device_t device,
                                              switch_size_t *table_sizes) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_table_default_sizes_get(table_sizes);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("config table sizes get failed for device %d: %s",
                     device,
                     switch_error_to_string(status));
    return status;
  }

  return status;
}

#ifdef __cplusplus
}
#endif
