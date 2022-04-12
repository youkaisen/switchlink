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
#include <openvswitch/util.h>
#include <openvswitch/vlog.h>

/* Local header includes */
#include "switch_internal.h"
#include "switch_base_types.h"
#include "switch_status.h"
#include "switch_fdb.h"

VLOG_DEFINE_THIS_MODULE(switch_fdb);

switch_status_t switch_l2_hash_key_init(void *args,
                                          switch_uint8_t *key,
                                          switch_uint32_t *len) {
  switch_mac_addr_t *l2_key = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!args || !key || !len) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    return status;
  }

  l2_key = (switch_mac_addr_t *)args;
  *len = 0;

  SWITCH_MEMCPY((key + *len), l2_key, sizeof(switch_mac_addr_t));
  *len += sizeof(switch_mac_addr_t);

  SWITCH_ASSERT(*len == SWITCH_L2_HASH_KEY_SIZE);

  return status;
}

switch_int32_t switch_l2_hash_compare(const void *key1, const void *key2) {
  VLOG_INFO("%s", __func__);

  return SWITCH_MEMCMP(key1, key2, SWITCH_L2_HASH_KEY_SIZE);
}

switch_status_t switch_l2_init(switch_device_t device)
{
  switch_l2_context_t *l2_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_status_t tmp_status = SWITCH_STATUS_SUCCESS;
 
  VLOG_INFO("%s", __func__);

  l2_ctx = SWITCH_MALLOC(device, sizeof(switch_l2_context_t), 0x1);
  if (!l2_ctx) {
      status = SWITCH_STATUS_NO_MEMORY;
      VLOG_ERR(
        "l2 init failed on device %d: "
        "l2 context malloc failed:(%s)\n",
        device,
        switch_error_to_string(status));
      return status;
  }
   
  SWITCH_MEMSET(l2_ctx, 0x0, sizeof(switch_l2_context_t));

  status = switch_device_api_context_set(
      device, SWITCH_API_TYPE_L2, (void *)l2_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
        "l2 init failed on device %d: "
        "l2 context set failed:(%s)\n",
        device,
        switch_error_to_string(status));
      return status;
  }

  l2_ctx->l2_hashtable.size = L2_FWD_RX_TABLE_SIZE;
  l2_ctx->l2_hashtable.compare_func = switch_l2_hash_compare;
  l2_ctx->l2_hashtable.key_func = switch_l2_hash_key_init;
  l2_ctx->l2_hashtable.hash_seed = SWITCH_L2_HASH_SEED;

  status = SWITCH_HASHTABLE_INIT(&l2_ctx->l2_hashtable);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("l2 init failed for device %d\n",
                     device);
    return status;
  }

  status = switch_handle_type_init(
    device, SWITCH_HANDLE_TYPE_L2_FWD_RX, L2_FWD_RX_TABLE_SIZE);
  if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
        "l2 rx init failed on device %d: "
        "l2 rx handle init failed:(%s)\n",
        device,
        switch_error_to_string(status));
      goto cleanup;
  }

  status = switch_handle_type_init(
      device, SWITCH_HANDLE_TYPE_L2_FWD_TX, L2_FWD_TX_TABLE_SIZE);
  if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
        "l2 tx init failed on device %d: "
        "l2 tx handle init failed:(%s)\n",
        device,
        switch_error_to_string(status));
      goto cleanup;
  }

  return status;   

cleanup:
  tmp_status = switch_l2_free(device);
  SWITCH_ASSERT(tmp_status == SWITCH_STATUS_SUCCESS);
  return status;
 
}

switch_status_t switch_l2_free(switch_device_t device)
{
  switch_l2_context_t *l2_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L2, (void **)&l2_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l2 free failed on device %d: "
        "l2 context get failed:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }
  
  status = SWITCH_HASHTABLE_DONE(&l2_ctx->l2_hashtable);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("l2 free failed for device %d: %s\n",
                     device,
                     switch_error_to_string(status));
  }

  status = switch_handle_type_free(device, SWITCH_HANDLE_TYPE_L2_FWD_TX);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l2 free failed on device %d: "
        "l2 handle free failed:(%s)\n",
        device,
        switch_error_to_string(status));
  }

  status = switch_handle_type_free(device, SWITCH_HANDLE_TYPE_L2_FWD_RX);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR(
        "l2 free failed on device %d: "
        "l2 handle free failed:(%s)\n",
        device,
        switch_error_to_string(status));
  }

  SWITCH_FREE(device, l2_ctx);
  status = switch_device_api_context_set(device, SWITCH_API_TYPE_L2, NULL);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}

switch_status_t switch_api_l2_handle_get(
    const switch_device_t device,
    const switch_mac_addr_t *l2_key,
    switch_handle_t *l2_handle) {
  switch_l2_context_t *l2_ctx = NULL;
  switch_api_l2_info_t *api_l2_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if (!l2_key || !l2_handle) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("l2 key find failed \n");
    return status;
  }

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L2, (void **)&l2_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("l2_key find failed \n");
    return status;
  }

  status = SWITCH_HASHTABLE_SEARCH(
      &l2_ctx->l2_hashtable, (void *)l2_key, (void **)&api_l2_info);
  if (status == SWITCH_STATUS_SUCCESS) {
    *l2_handle = api_l2_info->l2_handle;
  }

  return status;
}

switch_status_t switch_api_l2_forward_create(
    const switch_device_t device,
    switch_api_l2_info_t *api_l2_info,
    switch_handle_t *l2_handle)
{
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_handle_t handle = SWITCH_API_INVALID_HANDLE;
  switch_handle_t tnl_handle = SWITCH_API_INVALID_HANDLE;
  switch_l2_info_t *l2_info = NULL;
  switch_l2_context_t *l2_ctx = NULL;
  switch_mac_addr_t l2_mac;

  VLOG_INFO("%s", __func__);

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L2, (void **)&l2_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("l2_key find failed \n");
    return status;
  }

  SWITCH_MEMCPY(&l2_mac, &api_l2_info->dst_mac, sizeof(switch_mac_addr_t));
  status = switch_api_l2_handle_get(device, &l2_mac, &handle);
  if (status != SWITCH_STATUS_SUCCESS &&
      status != SWITCH_STATUS_ITEM_NOT_FOUND) {
    VLOG_ERR(
        "l2 create failed on device %d: "
        "l2 get failed:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  if (status == SWITCH_STATUS_SUCCESS) {
    VLOG_INFO(
        "l2 create failed on device %d nhop handle 0x%lx: "
        "l2 already exists\n",
        device,
        handle);
    *l2_handle = handle;
    return status;
  }

  if(api_l2_info->type == SWITCH_L2_FWD_TX)
  {
    handle = switch_l2_tx_handle_create(device);
    if (handle == SWITCH_API_INVALID_HANDLE) {
        status = SWITCH_STATUS_NO_MEMORY;
        VLOG_ERR("l2 create failed on device %d: "
                 "l2 handle create failed:(%s)\n",
                 device, switch_error_to_string(status));
        return status;
    }

    status = switch_l2_tx_get(device, handle, &l2_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR(
            "l2 create failed on device %d: "
            "l2 get failed:(%s)\n",
            device,
            switch_error_to_string(status));
        return status;
    }

    switch_tunnel_info_t *tunnel_info = NULL;
    switch_api_tunnel_info_t *api_tunnel_info = NULL;

    tnl_handle = api_l2_info->rif_handle;
    status = switch_tunnel_get(device, tnl_handle, &tunnel_info);
    CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

    api_tunnel_info = &tunnel_info->api_tunnel_info;

    status = switch_pd_l2_tx_forward_table_entry (device, api_l2_info,
                                                  api_tunnel_info,  true);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR(
            "l2 create failed on device %d: "
            "l2 pd create failed :(%s)\n",
            device,
            switch_error_to_string(status));
        return status;
    }

    status = switch_pd_tunnel_entry(device, api_tunnel_info, true);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR(
            "tunnel create failed on device %d: "
            "tunnel pd create failed :(%s)\n",
            device,
            switch_error_to_string(status));
        return status;
    }
  }
  else if(api_l2_info->type == SWITCH_L2_FWD_RX)
  {
    handle = switch_l2_rx_handle_create(device);
    if (handle == SWITCH_API_INVALID_HANDLE) {
        status = SWITCH_STATUS_NO_MEMORY;
        VLOG_ERR("l2 create failed on device %d: "
                 "l2 handle create failed:(%s)\n",
                 device, switch_error_to_string(status));
        return status;
    }

    status = switch_l2_rx_get(device, handle, &l2_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR(
            "l2 create failed on device %d: "
            "l2 get failed:(%s)\n",
            device,
            switch_error_to_string(status));
        return status;
    }

    status = switch_pd_l2_rx_forward_table_entry (device, api_l2_info, true);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "l2 create failed on device %d: "
          "l2 pd create failed :(%s)\n",
          device,
          switch_error_to_string(status));
      return status;
    }
  } else {
    VLOG_ERR("Invalid L2 FWD type");
    return SWITCH_STATUS_NOT_SUPPORTED;
  }

  api_l2_info->l2_handle = handle;
  SWITCH_MEMCPY(&l2_info->api_l2_info,
              api_l2_info,
              sizeof(switch_api_l2_info_t));

  status = SWITCH_HASHTABLE_INSERT(&l2_ctx->l2_hashtable,
                                   &(api_l2_info->node),
                                   (void *)&l2_mac,
                                   (void *)api_l2_info);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  *l2_handle = handle;

  return SWITCH_STATUS_SUCCESS; 
}

switch_status_t switch_api_l2_forward_delete (
    const switch_device_t device,
    const switch_api_l2_info_t *api_l2_info) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_handle_t l2_handle;
  switch_l2_context_t *l2_ctx = NULL;
  switch_mac_addr_t l2_mac;

  VLOG_INFO("%s", __func__);

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_L2, (void **)&l2_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("l2_key find failed \n");
    return status;
  }

  SWITCH_MEMCPY(&l2_mac, &api_l2_info->dst_mac, sizeof(switch_mac_addr_t));
  status = switch_api_l2_handle_get(device, &l2_mac, &l2_handle);
  if (status != SWITCH_STATUS_SUCCESS &&
      status != SWITCH_STATUS_ITEM_NOT_FOUND) {
    VLOG_ERR(
        "l2 create failed on device %d: "
        "l2 get failed:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  if(api_l2_info->type == SWITCH_L2_FWD_TX)
  {
    status = switch_pd_l2_tx_forward_table_entry (device, api_l2_info, NULL,
                                                  false);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR(
            "l2 tx forward delete failed on device %d: "
            "l2 tx forward pd table delete failed :(%s)\n",
            device,
            switch_error_to_string(status));
        return status;
    }
    status = switch_l2_tx_handle_delete(device, l2_handle, 1);
    SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
  }
  else if(api_l2_info->type == SWITCH_L2_FWD_RX)
  {
    status = switch_pd_l2_rx_forward_table_entry (device, api_l2_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "l2 rx forward delete failed on device %d: "
          "l2 rx forward pd table delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
      return status;
    }
    status = switch_l2_rx_handle_delete(device, l2_handle, 1);
    SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);
  } else {
      VLOG_ERR("Invalid L2 FWD type");
      return SWITCH_STATUS_NOT_SUPPORTED;
  }

  status = SWITCH_HASHTABLE_DELETE(
      &l2_ctx->l2_hashtable, (void *)(&l2_mac), (void **)&api_l2_info);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}

