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

#ifndef _switch_config_h
#define _switch_config_h

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_port.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct switch_config_s {
  bool use_pcie;

  bool add_ports;

  bool enable_ports;

  bool program_smac;

  switch_port_speed_t default_port_speed;

  switch_char_t cpu_interface[SWITCH_HOSTIF_NAME_SIZE];

  switch_uint16_t max_devices;

  switch_table_t table_info[SWITCH_TABLE_MAX];

  bool acl_group_optimization;

} switch_config_t;

switch_status_t switch_config_init(switch_config_t *switch_config);

switch_status_t switch_config_free();

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _switch_config_h */
