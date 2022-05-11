/*
 * Copyright (c) 2022 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openvswitch/vlog.h>
#include "switch_internal.h"
#include "switch_base_types.h"
#include "switch_pd_routing.h"
#include <config.h>

#include <bf_types/bf_types.h>
#include <port_mgr/dpdk/bf_dpdk_port_if.h>
#include "bf_rt/bf_rt_common.h"
#include "bf_rt/bf_rt_session.h"
#include "bf_rt/bf_rt_init.h"
#include "bf_rt/bf_rt_info.h"
#include "bf_rt/bf_rt_table.h"
#include "bf_rt/bf_rt_table_key.h"
#include "bf_rt/bf_rt_table_data.h"
#include "switch_pd_utils.h"
#include "switch_pd_p4_name_mapping.h"

VLOG_DEFINE_THIS_MODULE(switch_pd_routing);

switch_status_t switch_pd_nexthop_table_entry(
    switch_device_t device,
    const switch_pd_routing_info_t  *api_nexthop_pd_info,
    bool entry_add) {

  bf_status_t status;

  bf_rt_id_t field_id;
  bf_rt_id_t action_id;
  bf_rt_id_t data_field_id;

  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session;
  bf_rt_info_hdl *bfrt_info_hdl;
  bf_rt_table_key_hdl *key_hdl;
  bf_rt_table_data_hdl *data_hdl;
  const bf_rt_table_hdl *table_hdl;

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;
  
  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                              &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to allocate pd handle session");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_NEXTHOP_TABLE,
                                       &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for: %s", LNW_NEXTHOP_TABLE);
      goto dealloc_handle_session;
  }
    
  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to allocate key handle for: %s", LNW_NEXTHOP_TABLE);
      goto dealloc_handle_session;
  }

  status = bf_rt_key_field_id_get(
                  table_hdl,
                  LNW_NEXTHOP_TABLE_KEY_NEXTHOP_ID,
                  &field_id);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get field ID for key: %s",
                LNW_NEXTHOP_TABLE_KEY_NEXTHOP_ID);
      goto dealloc_handle_session;
  }
  VLOG_ERR("SANDY 1:%d", field_id);

  status = bf_rt_key_field_set_value(key_hdl, field_id,
                                     (api_nexthop_pd_info->nexthop_handle &
                                      ~(SWITCH_HANDLE_TYPE_NHOP<<25)));
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d for nexthop_table",
               field_id);
      goto dealloc_handle_session;
  }

  if (entry_add) {
      /* Add an entry to target */
      VLOG_INFO("Populate set_nexthop action in nexthop_table");

      status = bf_rt_action_name_to_id(
                          table_hdl,
                          LNW_NEXTHOP_TABLE_ACTION_SET_NEXTHOP,
                          &action_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator ID for: %s",
                    LNW_NEXTHOP_TABLE_ACTION_SET_NEXTHOP);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 31297949: %d", action_id);

      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                                  table_hdl,
                                  LNW_ACTION_SET_NEXTHOP_PARAM_RIF,
                                  action_id, &data_field_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                    LNW_ACTION_SET_NEXTHOP_PARAM_RIF);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 1: %d", data_field_id);

      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          (api_nexthop_pd_info->rif_handle &
                                           ~(SWITCH_HANDLE_TYPE_RIF << 25)));
                                            
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                                  table_hdl,
                                  LNW_ACTION_SET_NEXTHOP_PARAM_NEIGHBOR_ID,
                                  action_id, &data_field_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                    LNW_ACTION_SET_NEXTHOP_PARAM_NEIGHBOR_ID);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 2: %d", data_field_id);

      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                         (api_nexthop_pd_info->neighbor_handle &
                                         ~(SWITCH_HANDLE_TYPE_NEIGHBOR << 25)));
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                                  table_hdl,
                                  LNW_ACTION_SET_NEXTHOP_PARAM_EGRESS_PORT,
                                  action_id, &data_field_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                    LNW_ACTION_SET_NEXTHOP_PARAM_EGRESS_PORT);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 3: %d", data_field_id);

      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          api_nexthop_pd_info->port_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }
        
      status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                     data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to add nexthop_table entry");
          goto dealloc_handle_session;
      }
  } else {
        /* Delete an entry from target */
      VLOG_INFO("Delete nexthop_table entry");
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete nexthop_table entry");
          goto dealloc_handle_session;
      }
  }

dealloc_handle_session:
  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                               entry_add);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_neighbor_table_entry(
    switch_device_t device,
    const switch_pd_routing_info_t  *api_neighbor_pd_info,
    bool entry_add) {

  bf_status_t status;

  bf_rt_id_t field_id;
  bf_rt_id_t action_id;
  bf_rt_id_t data_field_id;

  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session;
  bf_rt_info_hdl *bfrt_info_hdl;
  bf_rt_table_key_hdl *key_hdl;
  bf_rt_table_data_hdl *data_hdl;
  const bf_rt_table_hdl *table_hdl;

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                             &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to allocate pd handle session");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_NEIGHBOR_MOD_TABLE,
                                       &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for: %s",
               LNW_NEIGHBOR_MOD_TABLE);
      goto dealloc_handle_session;
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to allocate key handle for: %s",
                LNW_NEIGHBOR_MOD_TABLE);
      goto dealloc_handle_session;
  }

  status = bf_rt_key_field_id_get(
                  table_hdl,
                  LNW_NEIGHBOR_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR,
                  &field_id);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get field ID for key: %s",
                LNW_NEIGHBOR_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR);
      goto dealloc_handle_session;
  }
  VLOG_ERR("SANDY 1:%d", field_id);

  status = bf_rt_key_field_set_value(key_hdl, field_id,
                                     (api_neighbor_pd_info->neighbor_handle &
                                      ~(SWITCH_HANDLE_TYPE_NEIGHBOR << 25)));
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d for neighbor_mod_table",
                field_id);
      goto dealloc_handle_session;
  }

  if (entry_add) {
      /* Add an entry to target */
      VLOG_INFO("Populate set_outer_mac action in neighbor_mod_table for "
                "neighbor handle %x",
                (unsigned int) api_neighbor_pd_info->neighbor_handle);

      status = bf_rt_action_name_to_id(
                          table_hdl,
                          LNW_NEIGHBOR_MOD_TABLE_ACTION_SET_OUTER_MAC,
                          &action_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator ID for: %s",
                    LNW_NEIGHBOR_MOD_TABLE_ACTION_SET_OUTER_MAC);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 31671750: %d", action_id);

      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                                  table_hdl,
                                  LNW_ACTION_SET_OUTER_MAC_PARAM_DST_MAC_ADDR,
                                  action_id, &data_field_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                    LNW_ACTION_SET_OUTER_MAC_PARAM_DST_MAC_ADDR);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 1: %d", data_field_id);

      status = bf_rt_data_field_set_value_ptr(
                                data_hdl, data_field_id,
                                (const uint8_t *)
                                &api_neighbor_pd_info->dst_mac_addr.mac_addr,
                                SWITCH_MAC_LENGTH);

      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add neighbor_mod_table entry");
            goto dealloc_handle_session;
        }
    } else {
        /* Delete an entry from target */
        VLOG_INFO("Delete neighbor_mod_table entry");
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete neighbor_mod_table entry");
            goto dealloc_handle_session;
        }
  }

dealloc_handle_session:
  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                               entry_add);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_rif_mod_start_entry(
  switch_device_t device,
  switch_rmac_entry_t *rmac_entry,
  switch_handle_t rif_handle,
  bool entry_add) {
  bf_status_t status;

  bf_rt_id_t field_id;
  bf_rt_id_t action_id;
  bf_rt_id_t data_field_id;

  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session;
  bf_rt_info_hdl *bfrt_info_hdl;
  bf_rt_table_key_hdl *key_hdl;
  bf_rt_table_data_hdl *data_hdl;
  const bf_rt_table_hdl *table_hdl;

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                             &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to allocate pd handle session");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_RIF_MOD_TABLE_START,
                                     &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for: %s",
                LNW_RIF_MOD_TABLE_START);
      goto dealloc_handle_session;
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to allocate key handle for: %s",
                LNW_RIF_MOD_TABLE_START);
      goto dealloc_handle_session;
  }

  status = bf_rt_key_field_id_get(
                  table_hdl,
                  LNW_RIF_MOD_TABLE_START_KEY_RIF_MOD_MAP_ID,
                  &field_id);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get field ID for key: %s",
                LNW_RIF_MOD_TABLE_START_KEY_RIF_MOD_MAP_ID);
      goto dealloc_handle_session;
  }
  VLOG_ERR("SANDY 1:%d", field_id);

  status = bf_rt_key_field_set_value(key_hdl, field_id,
                                     (rif_handle &
                                     ~(SWITCH_HANDLE_TYPE_RIF << 25)));
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d for rif_mod_table_start",
               field_id);
      goto dealloc_handle_session;
  }

  if (entry_add) {
    /* Add an entry to target */
    VLOG_INFO("Populate set_src_mac_start action in rif_mod_table_start");

    status = bf_rt_action_name_to_id(
                        table_hdl,
                        LNW_RIF_MOD_TABLE_START_ACTION_SET_SRC_MAC_START,
                        &action_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get action allocator ID for: %s",
                  LNW_RIF_MOD_TABLE_START_ACTION_SET_SRC_MAC_START);
        goto dealloc_handle_session;
    }
    VLOG_ERR("SANDY: 23093409: %d", action_id);

    status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                             &data_hdl);
    if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
      goto dealloc_handle_session;
   }

   status = bf_rt_data_field_id_with_action_get(
                        table_hdl,
                        LNW_ACTION_SET_SRC_MAC_START_PARAM_SRC_MAC_ADDR_FIRST,
                        action_id, &data_field_id);
   if(status != BF_SUCCESS) {
       VLOG_ERR("Unable to get data field id param for: %s",
                 LNW_ACTION_SET_SRC_MAC_START_PARAM_SRC_MAC_ADDR_FIRST);
       goto dealloc_handle_session;
   }
   VLOG_ERR("SANDY: 1: %d", data_field_id);

   status = bf_rt_data_field_set_value_ptr(
                                data_hdl, data_field_id,
                                (const uint8_t *)
                                &rmac_entry->mac.mac_addr+RMAC_START_OFFSET,
                                RMAC_BYTES_OFFSET);

    if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
      goto dealloc_handle_session;
    }

   status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                   data_hdl);
      if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to add rif_mod_table_start entry");
        goto dealloc_handle_session;
      }
    } else {
    /* Delete an entry from target */
    VLOG_INFO("Delete rif_mod_table_start entry");
    status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
    if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to delete rif_mod_table_start entry");
      goto dealloc_handle_session;
    }
  }

dealloc_handle_session:
  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                               entry_add);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to deallocate session and handles");
    return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_rif_mod_mid_entry(
  switch_device_t device,
  switch_rmac_entry_t *rmac_entry,
  switch_handle_t rif_handle,
  bool entry_add) {
  bf_status_t status;

  bf_rt_id_t field_id;
  bf_rt_id_t action_id;
  bf_rt_id_t data_field_id;

  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session;
  bf_rt_info_hdl *bfrt_info_hdl;
  bf_rt_table_key_hdl *key_hdl;
  bf_rt_table_data_hdl *data_hdl;
  const bf_rt_table_hdl *table_hdl;

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                           &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Failed to allocate pd handle session");
    return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_RIF_MOD_TABLE_MID,
                                   &table_hdl);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to get table handle for: %s", LNW_RIF_MOD_TABLE_MID);
    goto dealloc_handle_session;
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to allocate key handle for: %s", LNW_RIF_MOD_TABLE_MID);
    goto dealloc_handle_session;
  }

  status = bf_rt_key_field_id_get(
                  table_hdl,
                  LNW_RIF_MOD_TABLE_MID_KEY_RIF_MOD_MAP_ID,
                  &field_id);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get field ID for key: %s",
                LNW_RIF_MOD_TABLE_MID_KEY_RIF_MOD_MAP_ID);
      goto dealloc_handle_session;
  }
  VLOG_ERR("SANDY 1:%d", field_id);

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id,
                                     (rif_handle &
                                     ~(SWITCH_HANDLE_TYPE_RIF << 25)));
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to set value for key ID: %d for rif_mod_table_mid",
             field_id);
    goto dealloc_handle_session;
  }

  if (entry_add) {
    /* Add an entry to target */
    VLOG_INFO("Populate set_src_mac_mid action in rif_mod_table_mid");

    status = bf_rt_action_name_to_id(
                        table_hdl,
                        LNW_RIF_MOD_TABLE_MID_ACTION_SET_SRC_MAC_MID,
                        &action_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get action allocator ID for: %s",
                  LNW_RIF_MOD_TABLE_MID_ACTION_SET_SRC_MAC_MID);
        goto dealloc_handle_session;
    }
    VLOG_ERR("SANDY: 30315892: %d", action_id);

    status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                              &data_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
        goto dealloc_handle_session;
    }

    status = bf_rt_data_field_id_with_action_get(
                        table_hdl,
                        LNW_ACTION_SET_SRC_MAC_MID_PARAM_SRC_MAC_ADDR_MID,
                        action_id, &data_field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get data field id param for: %s",
                  LNW_ACTION_SET_SRC_MAC_MID_PARAM_SRC_MAC_ADDR_MID);
        goto dealloc_handle_session;
    }
    VLOG_ERR("SANDY: 1: %d", data_field_id);

    status = bf_rt_data_field_set_value_ptr(
                                data_hdl, data_field_id,
                                (const uint8_t *)
                                &rmac_entry->mac.mac_addr+RMAC_MID_OFFSET,
                                RMAC_BYTES_OFFSET);

    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
        goto dealloc_handle_session;
    }

    status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                   data_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to add rif_mod_table_mid entry");
        goto dealloc_handle_session;
    }
  } else {
      /* Delete an entry from target */
      VLOG_INFO("Delete rif_mod_table_mid entry");
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete rif_mod_table_mid entry");
          goto dealloc_handle_session;
      }
  }

dealloc_handle_session:
  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                               entry_add);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_rif_mod_end_entry(
  switch_device_t device,
  switch_rmac_entry_t *rmac_entry,
  switch_handle_t rif_handle,
  bool entry_add) {
  bf_status_t status;

  bf_rt_id_t field_id;
  bf_rt_id_t action_id;
  bf_rt_id_t data_field_id;

  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session;
  bf_rt_info_hdl *bfrt_info_hdl;
  bf_rt_table_key_hdl *key_hdl;
  bf_rt_table_data_hdl *data_hdl;
  const bf_rt_table_hdl *table_hdl;

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                             &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to allocate pd handle session");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_RIF_MOD_TABLE_LAST,
                                     &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for: %s", LNW_RIF_MOD_TABLE_LAST);
      goto dealloc_handle_session;
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to allocate key handle for: %s", LNW_RIF_MOD_TABLE_LAST);
      goto dealloc_handle_session;
  }

  status = bf_rt_key_field_id_get(
                  table_hdl,
                  LNW_RIF_MOD_TABLE_LAST_KEY_RIF_MOD_MAP_ID,
                  &field_id);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get field ID for key: %s",
                LNW_RIF_MOD_TABLE_LAST_KEY_RIF_MOD_MAP_ID);
      goto dealloc_handle_session;
  }
  VLOG_ERR("SANDY 1:%d", field_id);

  status = bf_rt_key_field_set_value(key_hdl, field_id,
                                     (rif_handle &
                                     ~(SWITCH_HANDLE_TYPE_RIF << 25)));
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d for rif_mod_table_last",
               field_id);
      goto dealloc_handle_session;
  }

  if (entry_add) {
      /* Add an entry to target */
      VLOG_INFO("Populate set_src_mac_last action in rif_mod_table_last");

      status = bf_rt_action_name_to_id(
                          table_hdl,
                          LNW_RIF_MOD_TABLE_LAST_ACTION_SET_SRC_MAC_LAST,
                          &action_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator ID for: %s",
                    LNW_RIF_MOD_TABLE_LAST_ACTION_SET_SRC_MAC_LAST);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 32740970: %d", action_id);

      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                           table_hdl,
                           LNW_ACTION_SET_SRC_MAC_LAST_PARAM_SRC_MAC_ADDR_LAST,
                           action_id, &data_field_id);
      if (status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                   LNW_ACTION_SET_SRC_MAC_LAST_PARAM_SRC_MAC_ADDR_LAST);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 1: %d", data_field_id);

      status = bf_rt_data_field_set_value_ptr(
                                data_hdl, data_field_id,
                                (const uint8_t *)
                                &rmac_entry->mac.mac_addr+RMAC_END_OFFSET,
                                RMAC_BYTES_OFFSET);

      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                     data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to add rif_mod_table_last entry");
          goto dealloc_handle_session;
      }
  } else {
      /* Delete an entry from target */
      VLOG_INFO("Delete rif_mod_table_last entry");
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete rif_mod_table_last entry");
          goto dealloc_handle_session;
      }
  }

dealloc_handle_session:
  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                               entry_add);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_ipv4_table_entry (switch_device_t device,
    const switch_api_route_entry_t *api_route_entry,
    bool entry_add, switch_ipv4_table_action_t action)
{
  bf_status_t status;

  bf_rt_id_t field_id;
  bf_rt_id_t action_id;
  bf_rt_id_t data_field_id;

  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session;
  bf_rt_info_hdl *bfrt_info_hdl;
  bf_rt_table_key_hdl *key_hdl;
  bf_rt_table_data_hdl *data_hdl;
  const bf_rt_table_hdl *table_hdl;
  uint32_t network_byte_order;

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                               &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to allocate pd handle session");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_IPV4_TABLE,
                                       &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for: %s", LNW_IPV4_TABLE);
      goto dealloc_handle_session;
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to allocate key handle");
      goto dealloc_handle_session;
  }

  status = bf_rt_key_field_id_get(
                  table_hdl,
                  LNW_IPV4_TABLE_KEY_IPV4_DST_MATCH,
                  &field_id);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get field ID for key: %s",
                LNW_IPV4_TABLE_KEY_IPV4_DST_MATCH);
      goto dealloc_handle_session;
  }
  VLOG_ERR("SANDY 1:%d", field_id);

  /* Use LPM API for LPM match type*/
  network_byte_order = ntohl(api_route_entry->ip_address.ip.v4addr);
  status = bf_rt_key_field_set_value_lpm_ptr(
                        key_hdl, field_id,
                        (const uint8_t *)&network_byte_order,
                        (const uint16_t)api_route_entry->ip_address.prefix_len,
                        sizeof(uint32_t));

  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d for ipv4_table", field_id);
      goto dealloc_handle_session;
  }

  if (entry_add) {
    if(action == SWITCH_ACTION_NHOP)
    {
      VLOG_INFO("Populate set_nexthop_id action in ipv4_table for "
                "route handle %x",
                (unsigned int) api_route_entry->route_handle);

      status = bf_rt_action_name_to_id(
                          table_hdl,
                          LNW_IPV4_TABLE_ACTION_SET_NEXTHOP_ID,
                          &action_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator ID for: %s",
                    LNW_IPV4_TABLE_ACTION_SET_NEXTHOP_ID);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 29883644: %d", action_id);

      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                           table_hdl,
                           LNW_ACTION_SET_NEXTHOP_ID_PARAM_NEXTHOP_ID,
                           action_id, &data_field_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                    LNW_ACTION_SET_NEXTHOP_ID_PARAM_NEXTHOP_ID);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 1: %d", data_field_id);

      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          (api_route_entry->nhop_handle &
                                           ~(SWITCH_HANDLE_TYPE_NHOP<<25)));
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }
    }

    if(action == SWITCH_ACTION_ECMP)
    {
      status = bf_rt_action_name_to_id(
                          table_hdl,
                          LNW_IPV4_TABLE_ACTION_ECMP_HASH_ACTION,
                          &action_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator ID for: %s",
                    LNW_IPV4_TABLE_ACTION_ECMP_HASH_ACTION);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 16874810: %d", action_id);

      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          goto dealloc_handle_session;
      }

      status = bf_rt_data_field_id_with_action_get(
                           table_hdl,
                           LNW_ACTION_ECMP_HASH_ACTION_PARAM_ECMP_GROUP_ID,
                           action_id, &data_field_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get data field id param for: %s",
                    LNW_ACTION_ECMP_HASH_ACTION_PARAM_ECMP_GROUP_ID);
          goto dealloc_handle_session;
      }
      VLOG_ERR("SANDY: 1: %d", data_field_id);

      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          api_route_entry->ecmp_group_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          goto dealloc_handle_session;
      }
    }

    status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to add ipv4_table entry");
        goto dealloc_handle_session;
    }
  } else {
      /* Delete an entry from target */
      VLOG_INFO("Delete ipv4_table entry");
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete ipv4_table entry");
          goto dealloc_handle_session;
      }
  }

dealloc_handle_session:
  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                               entry_add);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_routing_table_entry (
        switch_device_t device,
        const switch_pd_routing_info_t *api_routing_info,
        bool entry_type)
{
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  //update nexthop table
  status = switch_pd_nexthop_table_entry(device, api_routing_info, entry_type);
  if(status != SWITCH_STATUS_SUCCESS){
     VLOG_ERR("nexthop table update failed \n");
     return status;
  }

  //update neighbor mod table
  status = switch_pd_neighbor_table_entry(device, api_routing_info, entry_type);
  if(status != SWITCH_STATUS_SUCCESS){
      VLOG_ERR( "neighbor table update failed \n");
      return status;
  }
  return status;
}

switch_status_t switch_pd_rmac_table_entry (
        switch_device_t device,
        switch_rmac_entry_t *rmac_entry,
        switch_handle_t rif_handle,
        bool entry_type)
{
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!rmac_entry) {
      VLOG_ERR("Empty router_mac entry \n");
      return status;
  }
  //update rif mod tables start
  status = switch_pd_rif_mod_start_entry(device, rmac_entry, rif_handle,
                                             entry_type);
  if (status != SWITCH_STATUS_SUCCESS){
      VLOG_ERR("rid mod start table entry failed \n");
      return status;
  }

  //update rif mod tables mid
  status = switch_pd_rif_mod_mid_entry(device, rmac_entry, rif_handle,
                                       entry_type);
  if(status != SWITCH_STATUS_SUCCESS){
      VLOG_ERR("rid mod mid table entry failed \n");
      return status;
  }

  //update rif mod tables end
  status = switch_pd_rif_mod_end_entry(device, rmac_entry, rif_handle,
                                       entry_type);
  if (status != SWITCH_STATUS_SUCCESS){
      VLOG_ERR("rid mod end table entry failed \n");
      return status;
  }
  return status;
}
