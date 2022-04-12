/*
Copyright 2013-present Barefoot Networks, Inc.
Copyright(c) 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <config.h>
#include <openvswitch/util.h>
#include <openvswitch/vlog.h>
#include "switch_base_types.h"
#include "switch_port.h"
#include "switch_status.h"
#include "switch_port_int.h"


VLOG_DEFINE_THIS_MODULE(switch_port);

switch_status_t switch_api_port_add(
    switch_device_t device,
    switch_api_port_info_t *api_port_info,
    switch_handle_t *port_handle) {

  switch_port_t port = SWITCH_PORT_INVALID;
  // switch_port_speed_t port_speed = SWITCH_PORT_SPEED_NONE;
  switch_uint32_t mtu = SWITCH_PORT_RX_MTU_DEFAULT;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ovs_assert(api_port_info != NULL);

  port = api_port_info->port;
  mtu = api_port_info->rx_mtu;

  VLOG_INFO("switch_pd_port_add called with three parameters:\n");
  VLOG_INFO("device=%d\n", device);
  VLOG_INFO("port=%d\n", port);
  VLOG_INFO("mtu=%d\n", mtu);

  status = switch_pd_device_port_add(device, port, mtu);
  if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "port add failed on device %d port %d: "
          "port pd add failed(%s)\n",
          device,
          port,
          switch_error_to_string(status));
      return status;
   }
   return status;
}
