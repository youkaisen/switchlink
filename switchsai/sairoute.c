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

#include <sairoute.h>
#include <config.h>
#include "saiinternal.h"
#include <switchapi/switch_device.h>
#include <switchapi/switch_rif.h>
#include <switchapi/switch_interface.h>
#include <switchapi/switch_l3.h>
#include <openvswitch/vlog.h>

VLOG_DEFINE_THIS_MODULE(sairoute);

static sai_api_t api_id = SAI_API_ROUTE;

static void sai_route_entry_to_string(_In_ const sai_route_entry_t *route_entry,
                                      _Out_ char *entry_string) {
  int count = 0;
  int len = 0;
  count = snprintf(entry_string,
                   SAI_MAX_ENTRY_STRING_LEN,
                   "route: vrf %" PRIx64 " ",
                   route_entry->vr_id);
  sai_ipprefix_to_string(route_entry->destination,
                         SAI_MAX_ENTRY_STRING_LEN - count,
                         entry_string + count,
                         &len);
  return;
}

static void sai_route_entry_parse(_In_ const sai_route_entry_t *route_entry,
                                  _Out_ switch_handle_t *vrf_handle,
                                  _Out_ switch_ip_addr_t *ip_addr) {
  const sai_ip_prefix_t *sai_ip_prefix;

  *vrf_handle = (switch_handle_t)route_entry->vr_id;

  memset(ip_addr, 0, sizeof(switch_ip_addr_t));
  sai_ip_prefix = &route_entry->destination;
  sai_ip_prefix_to_switch_ip_addr(sai_ip_prefix, ip_addr);
}

static void sai_route_entry_attribute_parse(
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    switch_handle_t *nhop_handle,
    int *action,
    int *pri) {
  const sai_attribute_t *attribute;
  uint32_t index = 0;

  for (index = 0; index < attr_count; index++) {
    attribute = &attr_list[index];
    switch (attribute->id) {
      case SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID:
        *nhop_handle = (switch_handle_t)attribute->value.oid;
        break;
      case SAI_ROUTE_ENTRY_ATTR_USER_TRAP_ID:
        // TODO: Retrieve trap priority
        break;
      case SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION:
        *action = attribute->value.s32;
        break;
    }
  }
}

sai_status_t sai_route_entry_update(const sai_route_entry_t *route_entry,
                                    uint32_t attr_count,
                                    const sai_attribute_t *attr_list) {
  switch_ip_addr_t ip_addr;
  switch_handle_t nhop_handle = 0;
  switch_handle_t vrf_handle = 0;
  switch_api_route_entry_t api_route_entry;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  sai_status_t status = SAI_STATUS_SUCCESS;
  char entry_string[SAI_MAX_ENTRY_STRING_LEN];
  int action = -1, pri = -1;
  if (!route_entry) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null unicast entry: %s", sai_status_to_string(status));
    return status;
  }

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  sai_route_entry_parse(route_entry, &vrf_handle, &ip_addr);
  sai_route_entry_attribute_parse(
      attr_count, attr_list, &nhop_handle, &action, &pri);
  sai_route_entry_to_string(route_entry, entry_string);

  // Considering only IP address as a nexthop.
  // CR if (nhop_handle) {
    memset(&api_route_entry, 0, sizeof(switch_api_route_entry_t));
    api_route_entry.vrf_handle = vrf_handle;
    api_route_entry.nhop_handle = nhop_handle;
    api_route_entry.neighbor_installed = FALSE;
    memcpy(&api_route_entry.ip_address, &ip_addr, sizeof(switch_ip_addr_t));

    VLOG_INFO("Add route via switch_api_l3_route_add for: %s", entry_string);
    switch_status = switch_api_l3_route_add(0, &api_route_entry);

    status = sai_switch_status_to_sai_status(switch_status);
    /* Always return success as in case of fail SONiC will shutdown. */
    status = SAI_STATUS_SUCCESS;
  // CR } else {
  // CR  status = SAI_STATUS_INVALID_PARAMETER;
  // CR  VLOG_ERR("nhop_handle is not available for the route: %s", entry_string);
  // CR  return status;
  //}

  return status;
}
/*
* Routine Description:
*    Create Route
*
* Arguments:
*    [in] route_entry - route entry
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*
* Note: IP prefix/mask expected in Network Byte Order.
*
*/
sai_status_t sai_create_route_entry(_In_ const sai_route_entry_t *route_entry,
                                    _In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t *attr_list) {

  sai_status_t status = SAI_STATUS_SUCCESS;
  char entry_string[SAI_MAX_ENTRY_STRING_LEN];

  sai_route_entry_to_string(route_entry, entry_string);

  status = sai_route_entry_update(route_entry, attr_count, attr_list);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("Route entry create failed for route entry %s: %s",
                  entry_string,
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/*
* Routine Description:
*    Remove Route
*
* Arguments:
*    [in] route_entry - route entry
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*
* Note: IP prefix/mask expected in Network Byte Order.
*/
sai_status_t sai_remove_route_entry(_In_ const sai_route_entry_t *route_entry) {

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  switch_ip_addr_t ip_addr;
  switch_api_route_entry_t api_route_entry;
  switch_handle_t vrf_handle = 0;
  switch_handle_t nhop_handle = 0;

  if (!route_entry) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null unicast entry: %s", sai_status_to_string(status));
    return status;
  }

  sai_route_entry_parse(route_entry, &vrf_handle, &ip_addr);
  memset(&api_route_entry, 0, sizeof(switch_api_route_entry_t));
  api_route_entry.vrf_handle = vrf_handle;
  memcpy(&api_route_entry.ip_address, &ip_addr, sizeof(switch_ip_addr_t));
  api_route_entry.neighbor_installed = FALSE;

  VLOG_INFO("Delete l3 route via switch_api_l3_route_delete");
  switch_status = switch_api_l3_route_delete(0, &api_route_entry);
  status = sai_switch_status_to_sai_status(switch_status);

  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to remove route entry: %s",
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/*
*  Router entry methods table retrieved with sai_api_query()
*/
sai_route_api_t route_api = {
    .create_route_entry = sai_create_route_entry,
    .remove_route_entry = sai_remove_route_entry};

sai_status_t sai_route_initialize(sai_api_service_t *sai_api_service) {
  VLOG_DBG("Initializing route");
  sai_api_service->route_api = route_api;
  return SAI_STATUS_SUCCESS;
}
