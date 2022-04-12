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

#include <sairouterinterface.h>
#include "saiinternal.h"
#include <config.h>
#include <switchapi/switch_rif.h>
#include <switchapi/switch_rmac.h>
#include <switchapi/switch_interface.h>
#include <switchapi/switch_l3.h>
#include <openvswitch/vlog.h>

VLOG_DEFINE_THIS_MODULE(sairouterinterface);

static sai_api_t api_id = SAI_API_ROUTER_INTERFACE;

#define SAI_API_DEFAULT_L3_MTU_SIZE 9400
/*
* Routine Description:
*    Create router interface.
*
* Arguments:
*    [out] rif_id - router interface id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/

sai_status_t sai_create_router_interface(
    _Out_ sai_object_id_t *rif_id,
    _In_ sai_object_id_t switch_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_api_rif_info_t api_rif_info = {0};
  switch_api_interface_info_t intf_api_info = {0};

  const sai_attribute_t *attribute;
  sai_router_interface_type_t sai_intf_type = -1;
  uint32_t index = 0;
  switch_handle_t rmac_handle = 0;
  switch_handle_t intf_handle = SWITCH_API_INVALID_HANDLE;
  switch_handle_t rif_handle = SWITCH_API_INVALID_HANDLE;
  switch_handle_t mtu_handle = SWITCH_API_INVALID_HANDLE;
  switch_mtu_t mtu_size = 0;
  switch_mac_addr_t mac;

  *rif_id = SAI_NULL_OBJECT_ID;

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  attribute =
      get_attr_from_list(SAI_ROUTER_INTERFACE_ATTR_TYPE, attr_list, attr_count);
  if (attribute == NULL) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("missing attribute %s", sai_status_to_string(status));
    return status;
  }
  sai_intf_type = attribute->value.s32;

  switch (sai_intf_type) {
    case SAI_ROUTER_INTERFACE_TYPE_PORT:
      api_rif_info.rif_type = SWITCH_RIF_TYPE_INTF;
      intf_api_info.type = SWITCH_INTERFACE_TYPE_ACCESS;
      intf_api_info.handle = attribute->value.oid;
      break;
    default:
      VLOG_ERR("Unsupported intf type %d\n", sai_intf_type);
      return SAI_STATUS_NOT_SUPPORTED;
      break;
  }

  VLOG_INFO("Get default RMAC handle");
  switch_status =
      switch_api_device_default_rmac_handle_get(0, &rmac_handle);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to create router interface: %s",
                  sai_status_to_string(status));
    return status;
  }

  for (index = 0; index < attr_count; index++) {
    attribute = &attr_list[index];
    switch (attribute->id) {
      case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
        VLOG_INFO("RMAC group create");
        switch_status = switch_api_router_mac_group_create(
            0, SWITCH_RMAC_TYPE_ALL, &rmac_handle);
        //        SAI_ASSERT(status == SWITCH_STATUS_SUCCESS);
        if (switch_status == SWITCH_STATUS_SUCCESS) {
          memcpy(&mac.mac_addr, &attribute->value.mac, 6);
          VLOG_INFO("MAC: %02x:%02x:%02x:%02x:%02x:%02x, add to group",
                     mac.mac_addr[0], mac.mac_addr[1], mac.mac_addr[2],
                     mac.mac_addr[3], mac.mac_addr[4], mac.mac_addr[5]);
          switch_status =
              switch_api_router_mac_add(0, rmac_handle, &mac);
          api_rif_info.rmac_handle = rmac_handle;
        }
        break;
      default:
        break;
    }
  }
  api_rif_info.rmac_handle = rmac_handle;

  VLOG_INFO("Calling switch api create router interface");
  switch_status = switch_api_rif_create(0, &api_rif_info, &rif_handle);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to create router interface: %s",
                  sai_status_to_string(status));
    return status;
  }

  *rif_id = rif_handle;
  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

sai_status_t sai_remove_router_interface(_In_ sai_object_id_t rif_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_api_rif_info_t api_rif_info;
  switch_handle_t rmac_handle = SWITCH_API_INVALID_HANDLE;
  switch_handle_t tmp_rmac_handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("Get RIF attributes");
  switch_status = switch_api_rif_attribute_get(
      0, rif_id, (switch_uint64_t)UINT64_MAX, &api_rif_info);
  if ((status = sai_switch_status_to_sai_status(switch_status)) !=
      SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to remove router interface: %s",
                  sai_status_to_string(status));
    return status;
  }

  rmac_handle = api_rif_info.rmac_handle;
  switch_api_device_default_rmac_handle_get(0, &tmp_rmac_handle);
  if (tmp_rmac_handle != rmac_handle) {
      VLOG_INFO("Delete router MAC");
      switch_status = switch_api_router_mac_group_delete(0, rmac_handle);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        VLOG_ERR("failed to remove router interface: %s",
                  sai_status_to_string(status));
      }
  }

  VLOG_INFO("Calling switch api delete router interface");
  switch_status = switch_api_rif_delete(0, (switch_handle_t)rif_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to remove router interface: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
*  Routing interface methods table retrieved with sai_api_query()
*/
sai_router_interface_api_t rif_api = {
    .create_router_interface = sai_create_router_interface,
    .remove_router_interface = sai_remove_router_interface};

sai_status_t sai_router_interface_initialize(
    sai_api_service_t *sai_api_service) {
  VLOG_DBG("Initializing router interface");
  sai_api_service->rif_api = rif_api;
  return SAI_STATUS_SUCCESS;
}
