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

#include <config.h>
#include <saivirtualrouter.h>
#include "saiinternal.h"
#include <switchapi/switch_vrf.h>
#include <openvswitch/vlog.h>
#include "switch_base_types.h"

VLOG_DEFINE_THIS_MODULE(saivirtualrouter);

static void
sai_vrf_entry_attribute_parse(uint32_t attr_count,
                              const sai_attribute_t *attr_list)
{
  const sai_attribute_t *attribute;
  uint32_t i = 0;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE:  // TODO
        break;
      case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE:  // TODO
        break;
      case SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS:  // TODO
        break;
      default:
        break;
    }
  }
}

/*
* Routine Description:
*    Create virtual router
*
* Arguments:
*    [out] vr_id - virtual router id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*  - SAI_STATUS_SUCCESS on success
*  - SAI_STATUS_ADDR_NOT_FOUND if neither SAI_SWITCH_ATTR_SRC_MAC_ADDRESS nor
*    SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS is set.
*/
static sai_status_t
sai_create_virtual_router_entry(_Out_ sai_object_id_t *vr_id,
                                _In_ sai_object_id_t switch_id,
                                _In_ uint32_t attr_count,
                                _In_ const sai_attribute_t *attr_list)
{

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_vrf_t vrf_id = 0;
  switch_handle_t vrf_handle = SWITCH_API_INVALID_HANDLE;
  *vr_id = SAI_NULL_OBJECT_ID;

  if (attr_list) {
    sai_vrf_entry_attribute_parse(attr_count, attr_list);
  }

  status = (sai_object_id_t)switch_api_vrf_create(0, vrf_id, &vrf_handle);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to create virtual router entry : %s",
                  sai_status_to_string(status));
  }
  *vr_id = vrf_handle;

  return (sai_status_t)status;
}

/*
* Routine Description:
*    Remove virtual router
*
* Arguments:
*    [in] vr_id - virtual router id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
static sai_status_t
sai_remove_virtual_router_entry(_In_ sai_object_id_t vr_id)
{
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(vr_id) == SAI_OBJECT_TYPE_VIRTUAL_ROUTER);
  switch_status = switch_api_vrf_delete(0, vr_id);
  status = sai_switch_status_to_sai_status(switch_status);

  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to remove virtual router entry %lx : %s",
                  vr_id,
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/*
*  Virtual router methods table retrieved with sai_api_query()
*/
sai_virtual_router_api_t vr_api = {
    .create_virtual_router = sai_create_virtual_router_entry,
    .remove_virtual_router = sai_remove_virtual_router_entry};

sai_status_t
sai_virtual_router_initialize(sai_api_service_t *sai_api_service)
{
  VLOG_DBG("Initializing virtual router");
  sai_api_service->vr_api = vr_api;
  return SAI_STATUS_SUCCESS;
}
