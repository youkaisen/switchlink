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

  VLOG_INFO("%s", __func__);
  
  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                              &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Switch PD handle fail");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, "nexthop_table",
                                       &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for nexthop_table");
      return switch_pd_status_to_status(status);
  }
    
  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get key handle");
      return switch_pd_status_to_status(status);
  }

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id,
                                     (api_nexthop_pd_info->nexthop_handle &
                                      ~(SWITCH_HANDLE_TYPE_NHOP<<25)));
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d", field_id);
      return switch_pd_status_to_status(status);
  }

  if (entry_add) {
      /* Add an entry to target */
      action_id = 31297949; //action id for nexthop_table, action: set_nexthop
      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 1;
      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          (api_nexthop_pd_info->neighbor_handle &
                                          ~(SWITCH_HANDLE_TYPE_NEIGHBOR << 25)));
                                            
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 2;
      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          (api_nexthop_pd_info->rif_handle &
                                           ~(SWITCH_HANDLE_TYPE_RIF << 25)));
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 3;
      status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id,
                                          (const uint8_t *)&api_nexthop_pd_info->port_id,
                                          sizeof(uint32_t));
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }
        
      status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                     data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to add table entry");
          return switch_pd_status_to_status(status);
      }
  } else {
        /* Delete an entry from target */
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete table entry");
          return switch_pd_status_to_status(status);
      }
  }

  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session);
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

  VLOG_INFO("%s", __func__);

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                             &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Switch PD handle fail");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, "neighbor_mod_table",
                                       &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for nexthop_table");
      return switch_pd_status_to_status(status);
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get key handle");
      return switch_pd_status_to_status(status);
  }

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id, api_neighbor_pd_info->neighbor_handle);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d", field_id);
      return switch_pd_status_to_status(status);
  }

  if (entry_add) {
      /* Add an entry to target */
      action_id = 31671750; //action id for neighbor_mod_table, action: set_outer_mac
      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 1;
      status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id,
                                          (const uint8_t *)&api_neighbor_pd_info->dst_mac_addr.mac_addr,
                                          SWITCH_MAC_LENGTH);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }

      status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add table entry");
            return switch_pd_status_to_status(status);
        }
    } else {
        /* Delete an entry from target */
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete table entry");
            return switch_pd_status_to_status(status);
        }
  }

  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_rif_mod_start_entry(
  switch_device_t device,
  const switch_pd_routing_info_t  *api_rif_mod_start_pd_info,
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

  VLOG_INFO("%s", __func__);

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                             &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Switch PD handle fail");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, "rif_mod_table_start",
                                     &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle");
      return switch_pd_status_to_status(status);
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get key handle");
      return switch_pd_status_to_status(status);
  }

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id, api_rif_mod_start_pd_info->rif_handle);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d", field_id);
      return switch_pd_status_to_status(status);
  }

  if (entry_add) {
    /* Add an entry to target */
    action_id = 23093409; //action for rif_mod_table_start, action: set_src_mac_start
    status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                             &data_hdl);
    if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
      return switch_pd_status_to_status(status);
   }

   data_field_id = 1;
   status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id,
                                      (const uint8_t *)&api_rif_mod_start_pd_info->src_mac_addr.mac_addr_start,
                                      SWITCH_MAC_LENGTH_START);
    if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
      return switch_pd_status_to_status(status);
    }

   status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                   data_hdl);
      if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to add table entry");
        return switch_pd_status_to_status(status);
      }
    } else {
    /* Delete an entry from target */
    status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
    if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to delete table entry");
      return switch_pd_status_to_status(status);
    }
  }

  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to deallocate session and handles");
    return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_rif_mod_mid_entry(
  switch_device_t device,
  const switch_pd_routing_info_t  *api_rif_mod_mid_pd_info,
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

  VLOG_INFO("%s", __func__);

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                           &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Switch PD handle fail");
    return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, "rif_mod_table_mid",
                                   &table_hdl);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to get table handle");
    return switch_pd_status_to_status(status);
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to get key handle");
    return switch_pd_status_to_status(status);
  }

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id, api_rif_mod_mid_pd_info->rif_handle);
  if(status != BF_SUCCESS) {
    VLOG_ERR("Unable to set value for key ID: %d", field_id);
    return switch_pd_status_to_status(status);
  }

  if (entry_add) {
        /* Add an entry to target */
    action_id = 30315892; //action for rif_mod_table_mid table, action: set_src_mac_mid
    status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                              &data_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
        return switch_pd_status_to_status(status);
    }

    data_field_id = 1;
    status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id,
                                        (const uint8_t *)&api_rif_mod_mid_pd_info->src_mac_addr.mac_addr_mid,
                                        SWITCH_MAC_LENGTH_MID);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                   data_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to add table entry");
        return switch_pd_status_to_status(status);
    }
  } else {
      /* Delete an entry from target */
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete table entry");
          return switch_pd_status_to_status(status);
      }
  }

  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_pd_rif_mod_end_entry(
  switch_device_t device,
  const switch_pd_routing_info_t  *api_rif_mod_end_pd_info,
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

  VLOG_INFO("%s", __func__);

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                             &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Switch PD handle fail");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, "rif_mod_table_end",
                                     &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle");
      return switch_pd_status_to_status(status);
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get key handle");
      return switch_pd_status_to_status(status);
  }

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id, api_rif_mod_end_pd_info->rif_handle);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d", field_id);
      return switch_pd_status_to_status(status);
  }

  if (entry_add) {
      /* Add an entry to target */
      action_id = 32740970; //action for rif_mod_table_last, action: set_src_mac_last
      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 1;
      status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id,
                                          (const uint8_t *)&api_rif_mod_end_pd_info->src_mac_addr.mac_addr_end,
                                          SWITCH_MAC_LENGTH_END);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }

      status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                     data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to add table entry");
          return switch_pd_status_to_status(status);
      }
  } else {
      /* Delete an entry from target */
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete table entry");
          return switch_pd_status_to_status(status);
      }
  }

  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session);
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

  dev_tgt.dev_id = device;
  dev_tgt.pipe_id = 0;
  dev_tgt.direction = 0xFF;
  dev_tgt.prsr_id = 0xFF;

  VLOG_INFO("%s", __func__);

  status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                               &bfrt_info_hdl, &session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Switch PD handle fail");
      return switch_pd_status_to_status(status);
  }

  table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
  status = bf_rt_table_from_name_get(bfrt_info_hdl, "ipv4_table",
                                       &table_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get table handle for ipv4_table");
      return switch_pd_status_to_status(status);
  }

  status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to get key handle");
      return switch_pd_status_to_status(status);
  }

  field_id = 1;
  status = bf_rt_key_field_set_value(key_hdl, field_id, 0);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d", field_id);
      return switch_pd_status_to_status(status);
  }

  field_id = 2;
  status = bf_rt_key_field_set_value_ptr(key_hdl, field_id, (const uint8_t *)&api_route_entry->ip_address.ip.v4addr,
                                            sizeof(uint32_t));
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to set value for key ID: %d", field_id);
      return switch_pd_status_to_status(status);
  }

  if (entry_add) {
    if(action == SWITCH_ACTION_NHOP)
    {
      /* Add an entry to target */
      action_id = 29883644; //action id for ipv_table, action: set_nexthop_id
      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 1;
      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          api_route_entry->nhop_handle);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }
    }

    if(action == SWITCH_ACTION_ECMP)
    {
      action_id = 16874810; //action id for ipv4_table, action: ecmp_hash_action
      status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                &data_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
          return switch_pd_status_to_status(status);
      }

      data_field_id = 1;
      status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                          api_route_entry->ecmp_group_id);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
          return switch_pd_status_to_status(status);
      }
    }

    status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to add table entry");
        return switch_pd_status_to_status(status);
    }
  } else {
      /* Delete an entry from target */
      status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Unable to delete table entry");
          return switch_pd_status_to_status(status);
      }
  }

  status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Unable to deallocate session and handles");
      return switch_pd_status_to_status(status);
  }

  return switch_pd_status_to_status(status);
}

switch_status_t switch_routing_table_entry (
        switch_device_t device,
        const switch_pd_routing_info_t *api_routing_info,
        bool flag)
{
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  VLOG_INFO("%s", __func__);

  if(flag == true)
  {
    //update nexthop table
    status = switch_pd_nexthop_table_entry(device, api_routing_info, true);
    if(status != SWITCH_STATUS_SUCCESS){
       VLOG_ERR("nexthop table update failed \n");
       return status;
    }

    //update neighbor mod table
    status = switch_pd_neighbor_table_entry(device, api_routing_info, true);
    if(status != SWITCH_STATUS_SUCCESS){
        VLOG_ERR( "neighbor table update failed \n");
        return status;
    }

    //update rif mod tables start, mid, end
    status = switch_pd_rif_mod_start_entry(device, api_routing_info, true);
    if(status != SWITCH_STATUS_SUCCESS){
        VLOG_ERR("rid mod start table entry failed \n");
        return status;
    }

    status = switch_pd_rif_mod_mid_entry(device, api_routing_info, true);
    if(status != SWITCH_STATUS_SUCCESS){
        VLOG_ERR("rid mod mid table entry failed \n");
        return status;
    }

    status = switch_pd_rif_mod_end_entry(device, api_routing_info, true);
    if(status != SWITCH_STATUS_SUCCESS){
        VLOG_ERR("rid mod end table entry failed \n");
        return status;
    }
  }
  else
  {
    status = switch_pd_nexthop_table_entry(device, api_routing_info, false);
     if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "nexthop pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
      return status;
    }

    status = switch_pd_neighbor_table_entry(device, api_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "neighbor pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    status = switch_pd_rif_mod_start_entry(device, api_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "rif mod start pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    status = switch_pd_rif_mod_mid_entry(device, api_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "rif mod mid pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }

    status = switch_pd_rif_mod_end_entry(device, api_routing_info, false);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "neighbor delete failed on device %d: "
          "rif mod end pd delete failed :(%s)\n",
          device,
          switch_error_to_string(status));
    }
  }
  return status;
}
