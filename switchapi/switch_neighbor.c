/*
Copyright 2013-present Barefoot Networks, Inc.
Copyright(c) 2021 Intel Corporation.

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
#include "switch_neighbor_int.h"
#include "switch_neighbor.h"
#include "switch_nhop.h"
#include "switch_nhop_int.h"
#include "switch_rif_int.h"
#include "switch_rmac_int.h"
#include "switch_internal.h"

/* Local header includes */
#include "switch_internal.h"

VLOG_DEFINE_THIS_MODULE(switch_neighbor);

switch_status_t switch_neighbor_init(switch_device_t device) {
  switch_neighbor_context_t *neighbor_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  neighbor_ctx = SWITCH_MALLOC(device, sizeof(switch_neighbor_context_t), 0x1);
  if (!neighbor_ctx) {
    status = SWITCH_STATUS_NO_MEMORY;
    VLOG_ERR("neighbor init failed for device %d: %s\n",
                     device,
                     switch_error_to_string(status));
    return status;
  }

  status = switch_device_api_context_set(
      device, SWITCH_API_TYPE_NEIGHBOR, (void *)neighbor_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("neighbor init failed for device %d: %s\n",
                     device,
                     switch_error_to_string(status));
    return status;
  }
  
  status = switch_handle_type_init(
      device, SWITCH_HANDLE_TYPE_NEIGHBOR, NEIGHBOR_MOD_TABLE_SIZE);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("neighbor init failed for device %d: %s\n",
                     device,
                     switch_error_to_string(status));
    goto cleanup;
  }

  return status;

cleanup:
  status = switch_neighbor_free(device);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
  return status;
}

switch_status_t switch_neighbor_free(switch_device_t device) {
  switch_neighbor_context_t *neighbor_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_NEIGHBOR, (void **)&neighbor_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("neighbor free failed for device %d: %s\n",
                     device,
                     switch_error_to_string(status));
    return status;
  }
  
  status = switch_handle_type_free(device, SWITCH_HANDLE_TYPE_NEIGHBOR);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("neighbor free failed for device %d: %s\n",
                     device,
                     switch_error_to_string(status));
  }
  
  SWITCH_FREE(device, neighbor_ctx);
  status =
      switch_device_api_context_set(device, SWITCH_API_TYPE_NEIGHBOR, NULL);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}

switch_status_t switch_api_neighbor_create(
    switch_device_t device,
    switch_api_neighbor_info_t *api_neighbor_info,
    switch_handle_t *neighbor_handle) {
  switch_neighbor_info_t *neighbor_info = NULL;
  switch_handle_t nhop_handle = SWITCH_API_INVALID_HANDLE;
  switch_nhop_info_t *nhop_info = NULL;
  switch_handle_t handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_routing_info_t pd_neighbor_info;
  switch_rif_info_t *rif_info = NULL;
  switch_handle_t rmac_handle;
  switch_mac_addr_t src_rmac;
  switch_rmac_info_t *rmac_info;
  switch_rmac_entry_t *rmac_entry = NULL;
  switch_node_t *node = NULL;
  int i;

  VLOG_INFO("%s", __func__);

  memset(&pd_neighbor_info, 0, sizeof(switch_pd_routing_info_t));

  if (!api_neighbor_info) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR(
        "neighbor create failed on device %d: "
        "neighbor info invalid:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  if (!SWITCH_NHOP_HANDLE(api_neighbor_info->nhop_handle)) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    VLOG_ERR(
        "neighbor create failed on device %d nhop handle 0x%lx: "
        "nhop handle invalid:(%s)\n",
        device,
        api_neighbor_info->nhop_handle,
        switch_error_to_string(status));
    return status;
  }
  nhop_handle = api_neighbor_info->nhop_handle;

  handle = switch_neighbor_handle_create(device);
  if (handle == SWITCH_API_INVALID_HANDLE) {
    status = SWITCH_STATUS_NO_MEMORY;
    VLOG_ERR(
        "neighbor create failed on device %d: "
        "handle create failed:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_neighbor_get(device, handle, &neighbor_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "neighbor create failed on device %d: "
        "neighbor get failed:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_nhop_get(device, nhop_handle, &nhop_info);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
  nhop_info->spath.neighbor_handle = handle;

  neighbor_info->neighbor_handle = handle;
  neighbor_info->nhop_handle = nhop_handle;
  SWITCH_MEMCPY(&neighbor_info->api_neighbor_info,
                api_neighbor_info,
                sizeof(switch_api_neighbor_info_t));

  *neighbor_handle = handle;

  if((nhop_handle && handle))
  {
      pd_neighbor_info.neighbor_handle = handle;
      pd_neighbor_info.nexthop_handle = nhop_handle;

      //get rif_info to access port_id
      pd_neighbor_info.rif_handle = api_neighbor_info->rif_handle;
      status = switch_rif_get(device, pd_neighbor_info.rif_handle, &rif_info);
      CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);
      pd_neighbor_info.port_id = rif_info->api_rif_info.port_id;

      SWITCH_MEMCPY(&pd_neighbor_info.dst_mac_addr, &api_neighbor_info->mac_addr, sizeof(switch_mac_addr_t));

      //rmac_handle will have source mac info. get rmac_info from rmac_handle      
      rmac_handle = rif_info->api_rif_info.rmac_handle;
      status = switch_rmac_get(device, rmac_handle, &rmac_info);
      CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);
      SWITCH_LIST_GET_HEAD(rmac_info->rmac_list, node);
      rmac_entry = (switch_rmac_entry_t *)node->data;
      //split source mac address into start, mid and end
      SWITCH_MEMCPY(src_rmac.mac_addr, rmac_entry->mac.mac_addr, sizeof(switch_mac_addr_t));
      i=0;
      SWITCH_MEMCPY(pd_neighbor_info.src_mac_addr.mac_addr_start, src_rmac.mac_addr, 2);
      i += 2;
      SWITCH_MEMCPY(pd_neighbor_info.src_mac_addr.mac_addr_mid, src_rmac.mac_addr+i, 2);
      i += 2;
      SWITCH_MEMCPY(pd_neighbor_info.src_mac_addr.mac_addr_end, src_rmac.mac_addr+i, 2);

      status = switch_routing_table_entry(device, &pd_neighbor_info, true);
      if(status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("routing tables update failed \n");
        return status;
      }
  }

  SWITCH_MEMCPY(&neighbor_info->switch_device_pd_routing_info,
                &pd_neighbor_info,
                sizeof(switch_pd_routing_info_t));
  VLOG_INFO(
      "neighbor created on device %d neighbor handle 0x%lx\n", device, handle);

  return status;
}

switch_status_t switch_api_neighbor_delete(
    switch_device_t device, switch_handle_t neighbor_handle) {
  switch_neighbor_info_t *neighbor_info = NULL;
  switch_api_neighbor_info_t *api_neighbor_info = NULL;
  switch_handle_t nhop_handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!SWITCH_NEIGHBOR_HANDLE(neighbor_handle)) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    VLOG_ERR(
        "neighbor delete failed on device %d neighbor handle 0x%lx: "
        "neighbor handle invalid(%s)\n",
        device,
        neighbor_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_neighbor_get(device, neighbor_handle, &neighbor_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "neighbor delete failed on device %d neighbor handle 0x%lx: "
        "neighbor get failed(%s)\n",
        device,
        neighbor_handle,
        switch_error_to_string(status));
    return status;
  }

  nhop_handle = neighbor_info->nhop_handle;
  api_neighbor_info = &neighbor_info->api_neighbor_info;

  if (SWITCH_NHOP_HANDLE(nhop_handle)) {
    status = switch_routing_table_entry(device, &neighbor_info->switch_device_pd_routing_info, false);
    if(status != SWITCH_STATUS_SUCCESS)
      VLOG_ERR("routing tables update failed \n");
  }
     status = switch_pd_nexthop_table_entry(device, &neighbor_info->switch_device_pd_routing_info, false);
     if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "nexthop pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
      return status;
    }

    status = switch_pd_neighbor_table_entry(device, &neighbor_info->switch_device_pd_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "neighbor pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    status = switch_pd_rif_mod_start_entry(device, &neighbor_info->switch_device_pd_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "rif mod start pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    status = switch_pd_rif_mod_mid_entry(device, &neighbor_info->switch_device_pd_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "rif mod mid pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    status = switch_pd_rif_mod_end_entry(device, &neighbor_info->switch_device_pd_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "rif mod end pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    if (api_neighbor_info->neighbor_type == SWITCH_NEIGHBOR_TYPE_IP) {
      status = switch_api_nhop_delete(device, nhop_handle);
      if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR(
            "neighbor delete failed on device %d neighbor handle 0x%lx: "
            "nhop delete failed:(%s)\n",
            device,
            neighbor_handle,
            switch_error_to_string(status));
        return status;
      }
    }

  status = switch_neighbor_handle_delete(device, neighbor_handle);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  VLOG_INFO("neighbor deleted on device %d neighbor handle 0x%lx\n",
                   device,
                   neighbor_handle);

  return status;
}
