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
#include <config.h>
#include <openvswitch/util.h>
#include <openvswitch/vlog.h>

#include "switch_internal.h"
#include "switch_l3.h"
#include "switch_pd_routing.h"

VLOG_DEFINE_THIS_MODULE(switch_l3);

switch_status_t switch_route_table_entry_key_init(void *args,
                                                  switch_uint8_t *key,
                                                  switch_uint32_t *len) {
  switch_route_entry_t *route_entry = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!args || !key || !len) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    return status;
  }

  *len = 0;
  route_entry = (switch_route_entry_t *)args;

  SWITCH_MEMCPY(key, &route_entry->vrf_handle, sizeof(switch_handle_t));
  *len += sizeof(switch_handle_t);

  SWITCH_MEMCPY((key + *len), &route_entry->ip, sizeof(switch_ip_addr_t));
  *len += sizeof(switch_ip_addr_t);

  SWITCH_MEMCPY((key + *len), &route_entry->neighbor_installed, sizeof(bool));
  *len += sizeof(bool);

  SWITCH_ASSERT(*len == SWITCH_ROUTE_HASH_KEY_SIZE);

  return status;
}

switch_int32_t switch_route_entry_hash_compare(const void *key1,
                                               const void *key2) {
  VLOG_INFO("%s", __func__);

  return SWITCH_MEMCMP(key1, key2, SWITCH_ROUTE_HASH_KEY_SIZE);
}

switch_status_t switch_l3_init(switch_device_t device) {
  switch_l3_context_t *l3_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  l3_ctx = SWITCH_MALLOC(device, sizeof(switch_l3_context_t), 0x1);
  if (!l3_ctx) {
    status = SWITCH_STATUS_NO_MEMORY;
    VLOG_ERR(
        "l3 init failed on device %d "
        "l3 device context memoary allocation failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status =
      switch_device_api_context_set(device, SWITCH_API_TYPE_L3, (void *)l3_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 init failed on device %d "
        "l3 context set failed(%s)\n",
        device,
        switch_error_to_string(status));
  }
  
  l3_ctx->route_hashtable.size = IPV4_TABLE_SIZE;
  l3_ctx->route_hashtable.compare_func = switch_route_entry_hash_compare;
  l3_ctx->route_hashtable.key_func = switch_route_table_entry_key_init;
  l3_ctx->route_hashtable.hash_seed = SWITCH_ROUTE_HASH_SEED;
  
  status = SWITCH_HASHTABLE_INIT(&l3_ctx->route_hashtable);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 init failed on device %d: "
        "l3 hashtable init failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_handle_type_init(
      device, SWITCH_HANDLE_TYPE_ROUTE, IPV4_TABLE_SIZE);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 init failed on device %d: "
        "route handle init failed (%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  return status;
} 

switch_status_t switch_l3_free(switch_device_t device) {
  switch_l3_context_t *l3_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L3, (void **)&l3_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 free failed on device %d: "
        "l3 context get failed(%s)\n",
        device,
        switch_error_to_string(status));
  }

  status = SWITCH_HASHTABLE_DONE(&l3_ctx->route_hashtable);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 free failed on device %d: "
        "l3 hashtable done failed(%s)\n",
        device,
        switch_error_to_string(status));
  }

  status = switch_handle_type_free(device, SWITCH_HANDLE_TYPE_ROUTE);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 free failed on device %d: "
        "route handle free failed(%s)\n",
        device,
        switch_error_to_string(status));
  }

  SWITCH_FREE(device, l3_ctx);
  status = switch_device_api_context_set(device, SWITCH_API_TYPE_L3, NULL);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}

switch_status_t switch_route_table_hash_lookup(
    switch_device_t device,
    switch_route_entry_t *route_entry,
    switch_handle_t *route_handle) {
  switch_l3_context_t *l3_ctx = NULL;
  switch_route_info_t *route_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!route_entry) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR(
        "route table entry find failed on device %d: "
        "parameters invalid(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L3, (void **)&l3_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route table entry find failed on device %d: "
        "l3 context get failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = SWITCH_HASHTABLE_SEARCH(
      &l3_ctx->route_hashtable, (void *)route_entry, (void **)&route_info);
  if (status == SWITCH_STATUS_SUCCESS) {
    *route_handle = route_info->api_route_info.route_handle;
  }

  return status;
}

switch_status_t switch_route_hashtable_insert(switch_device_t device,
                                              switch_handle_t route_handle) {
  switch_l3_context_t *l3_ctx = NULL;
  switch_route_info_t *route_info = NULL;
  switch_route_entry_t *route_entry = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!SWITCH_ROUTE_HANDLE(route_handle)) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    VLOG_ERR(
        "route hashtable insert failed on device %d "
        "route handle 0x%lx: route handle invalid(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_route_get(device, route_handle, &route_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route hashtable insert failed on device %d "
        "route handle 0x%lx: route get failed(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  route_entry = &route_info->route_entry;

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L3, (void **)&l3_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route hashtable insert failed on device %d "
        "route handle 0x%lx: l3 context get failed(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  status = SWITCH_HASHTABLE_INSERT(&l3_ctx->route_hashtable,
                                   &((route_info)->node),
                                   (void *)route_entry,
                                   (void *)(route_info));
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route hashtable insert failed on device %d "
        "route handle 0x%lx: hashtable insert failed(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  return status;
}

switch_status_t switch_route_hashtable_remove(switch_device_t device,
                                              switch_handle_t route_handle) {
  switch_l3_context_t *l3_ctx = NULL;
  switch_route_info_t *route_info = NULL;
  switch_route_entry_t *route_entry = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!SWITCH_ROUTE_HANDLE(route_handle)) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    VLOG_ERR(
        "route hashtable delete failed on device %d "
        "route handle 0x%lx: route handle invalid(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_route_get(device, route_handle, &route_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route hashtable delete failed on device %d "
        "route handle 0x%lx: route get failed(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  route_entry = &route_info->route_entry;

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L3, (void **)&l3_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route hashtable delete failed on device %d "
        "route handle 0x%lx: l3 context get failed(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  status = SWITCH_HASHTABLE_DELETE(
      &l3_ctx->route_hashtable, (void *)route_entry, (void **)&route_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "route hashtable delete failed on device %d "
        "route handle 0x%lx: l3 hashtable delete failed(%s)\n",
        device,
        route_handle,
        switch_error_to_string(status));
    return status;
  }

  return status;
}

switch_status_t switch_api_l3_route_add(
    switch_device_t device, switch_api_route_entry_t *api_route_entry) 
{
  switch_route_info_t *route_info = NULL;
  switch_handle_t handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_route_entry_t route_entry;
  switch_handle_t vrf_handle;
  switch_handle_t route_handle;

  VLOG_INFO("%s", __func__);

  if (!api_route_entry) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR(
        "l3 route table add failed on device %d "
        "parameters invalid(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }
  
  vrf_handle = api_route_entry->vrf_handle;
  if (!SWITCH_VRF_HANDLE(vrf_handle)) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    VLOG_ERR(
        "l3 route table add failed on device %d "
        "vrf handle 0x%lx "
        "vrf handle invalid(%s)\n",
        device,
        vrf_handle,
        switch_error_to_string(status));
    return status;
  }

  memset(&route_entry, 0, sizeof(route_entry));
  route_entry.vrf_handle = vrf_handle;
  SWITCH_MEMCPY(&route_entry.ip, &api_route_entry->ip_address, sizeof(switch_ip_addr_t));

  status = switch_route_table_hash_lookup(device, &route_entry, &route_handle);
  if (status == SWITCH_STATUS_SUCCESS) {
    status = SWITCH_STATUS_ITEM_ALREADY_EXISTS;
    VLOG_ERR(
        "l3 route table add failed on device %d "
        "vrf handle 0x%lx "
        "route table lookup failed(%s)\n",
        device,
        vrf_handle,
        switch_error_to_string(status));
    return status;
  }

  handle = switch_route_handle_create(device);
  if (handle == SWITCH_API_INVALID_HANDLE) {
    VLOG_ERR(
        "l3 route table add failed on device %d "
        "route handle create failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_route_get(device, handle, &route_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 route table add failed on device %d "
        "route get failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  //SWITCH_ASSERT(SWITCH_NHOP_HANDLE(api_route_entry->nhop_handle));
  if(api_route_entry->nhop_handle)
  {  
    status = switch_pd_ipv4_table_entry(device, api_route_entry, true, SWITCH_ACTION_NHOP);
    SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
      if(status != SWITCH_STATUS_SUCCESS)
        VLOG_ERR("ipv4 table update failed \n");
  }

  //SWITCH_ASSERT(SWITCH_NHOP_HANDLE(api_route_entry->ecmp_group_id));
  if(api_route_entry->ecmp_group_id)
  {
    status = switch_pd_ipv4_table_entry(device, api_route_entry, true, SWITCH_ACTION_ECMP);
    SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
    if(status != SWITCH_STATUS_SUCCESS)
      VLOG_ERR("ipv4 table update failed \n");
  }

  api_route_entry->route_handle = handle;
  SWITCH_MEMCPY(&route_info->api_route_info,
                api_route_entry,
                sizeof(switch_api_route_entry_t));
  route_info->route_entry.vrf_handle = vrf_handle;
  route_info->nhop_handle = api_route_entry->nhop_handle;
  SWITCH_MEMCPY(&route_info->route_entry.ip,
                &api_route_entry->ip_address,
                sizeof(switch_ip_addr_t));

  status = switch_route_hashtable_insert(device, handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 route table add failed on device %d "
        "vrf handle 0x%lx "
        "route table insert failed(%s)\n",
        device,
        vrf_handle,
        switch_error_to_string(status));
    return status;
  }

  return status;
}

switch_status_t switch_api_l3_route_delete(switch_device_t device,
    switch_api_route_entry_t *api_route_entry) {
  switch_route_info_t *route_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_route_entry_t route_entry;
  switch_handle_t route_handle;  

  VLOG_INFO("%s", __func__);

  if (!api_route_entry) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR(
        "l3 route table delete failed on device %d "
        "parameters invalid(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  route_entry.vrf_handle = api_route_entry->vrf_handle;
  SWITCH_MEMCPY(&route_entry.ip, &api_route_entry->ip_address, sizeof(switch_ip_addr_t));
  route_entry.neighbor_installed = api_route_entry->neighbor_installed;

  status = switch_route_table_hash_lookup(device, &route_entry, &route_handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 route table delete failed on device %d "
        "route entry hash find failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_route_get(device, route_handle, &route_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 route table delete failed on device %d "
        "route get failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  if (route_info->nhop_handle) {
    status = switch_pd_ipv4_table_entry(device, &route_info->api_route_info, false, SWITCH_ACTION_NONE);
    SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
    if(status != SWITCH_STATUS_SUCCESS)
      VLOG_ERR("ipv4 table delete] failed \n");
  }

  status = switch_route_hashtable_remove(device, route_handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l3 route table delete failed on device %d "
        "route table delete failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_route_handle_delete(device, route_handle);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}
