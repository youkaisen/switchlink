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
#include "switch_internal.h"
#include "switch_fdb.h"
#include "switch_rif_int.h"
#include "switch_base_types.h"
#include "switch_pd_p4_name_mapping.h"

VLOG_DEFINE_THIS_MODULE(switch_pd_fdb);

switch_status_t switch_pd_l2_tx_forward_table_entry(
    switch_device_t device,
    const switch_api_l2_info_t *api_l2_tx_info,
    const switch_api_tunnel_info_t *api_tunnel_info,
    bool entry_add) {

    bf_status_t status;

    bf_rt_id_t field_id;
    bf_rt_id_t action_id;
    bf_rt_id_t data_field_id;

    bf_rt_target_t dev_tgt;
    bf_rt_session_hdl *session = NULL;
    bf_rt_info_hdl *bfrt_info_hdl = NULL;
    bf_rt_table_key_hdl *key_hdl = NULL;
    bf_rt_table_data_hdl *data_hdl = NULL;
    const bf_rt_table_hdl *table_hdl = NULL;
    uint32_t network_byte_order;

    dev_tgt.dev_id = device;
    dev_tgt.pipe_id = 0;
    dev_tgt.direction = 0xFF;
    dev_tgt.prsr_id = 0xFF;

    VLOG_DBG("%s", __func__);

    status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                               &bfrt_info_hdl, &session);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Switch PD handle fail");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_from_name_get(bfrt_info_hdl, LNW_L2_FWD_TX_TABLE,
                                       &table_hdl);
    if(status != BF_SUCCESS || !table_hdl) {
        VLOG_ERR("Unable to get table handle for: %s, error: %d",
                 LNW_L2_FWD_TX_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get key handle for %s, error: %d",
                 LNW_L2_FWD_TX_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_L2_FWD_TX_TABLE_KEY_DST_MAC,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_L2_FWD_TX_TABLE_KEY_DST_MAC, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_set_value_ptr (key_hdl, field_id, 
                            (const uint8_t *)&api_l2_tx_info->dst_mac.mac_addr,
                                        SWITCH_MAC_LENGTH);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d, error: %d",
                  field_id, status);
        goto dealloc_handle_session;
    }

    if (entry_add &&
        api_l2_tx_info->learn_from == SWITCH_L2_FWD_LEARN_TUNNEL_INTERFACE) {

        VLOG_INFO("Populate set_tunnel action in %s for tunnel "
                  "interface %x", LNW_L2_FWD_TX_TABLE,
                  (unsigned int)api_l2_tx_info->rif_handle);

        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_L2_FWD_TX_TABLE_ACTION_SET_TUNNEL,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_L2_FWD_TX_TABLE_ACTION_SET_TUNNEL, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID: %d, error: %d",
                      action_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_SET_TUNNEL_PARAM_TUNNEL_ID,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_SET_TUNNEL_PARAM_TUNNEL_ID, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value_ptr (data_hdl, data_field_id,
                                                 0, sizeof(uint32_t));
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_SET_TUNNEL_PARAM_DST_ADDR,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_SET_TUNNEL_PARAM_DST_ADDR, status);
            goto dealloc_handle_session;
        }

        network_byte_order = ntohl(api_tunnel_info->dst_ip.ip.v4addr);
        status = bf_rt_data_field_set_value_ptr (data_hdl, data_field_id,
                                                 (const uint8_t *)
                                                 &network_byte_order,
                                                 sizeof(uint32_t));
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }
        status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add table entry, error: %d", status);
            goto dealloc_handle_session;
        }
    } else if (entry_add &&
               api_l2_tx_info->learn_from ==
               SWITCH_L2_FWD_LEARN_VLAN_INTERFACE) {

        VLOG_INFO("Populate l2_fwd action in %s "
                  "for VLAN netdev: vlan%d", LNW_L2_FWD_TX_TABLE,
                  api_l2_tx_info->port_id+1);

        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID: %d, error: %d",
                     action_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_L2_FWD_PARAM_PORT,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_L2_FWD_PARAM_PORT, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                            api_l2_tx_info->port_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add %s table entry, error: %d",
                      LNW_L2_FWD_TX_TABLE, status);
            goto dealloc_handle_session;
        }
    } else if (entry_add &&
               api_l2_tx_info->learn_from ==
               SWITCH_L2_FWD_LEARN_PHYSICAL_INTERFACE) {

        VLOG_INFO("Populate l2_fwd action in %s "
                  "for physical port: %d",
                  LNW_L2_FWD_TX_TABLE, api_l2_tx_info->port_id);
        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID: %d, error: %d",
                      action_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_L2_FWD_PARAM_PORT,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_L2_FWD_PARAM_PORT, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                            api_l2_tx_info->port_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add %s entry, error: %d",
                      LNW_L2_FWD_TX_TABLE, status);
            goto dealloc_handle_session;
        }
    } else {
        /* Delete an entry from target */
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete %s entry, error: %d",
                      LNW_L2_FWD_TX_TABLE, status);
            goto dealloc_handle_session;
        }
    }

dealloc_handle_session:
    status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                                 entry_add);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to deallocate handle session");
        return switch_pd_status_to_status(status);
    }

    return switch_pd_status_to_status(status);
}


switch_status_t switch_pd_l2_rx_forward_table_entry(
    switch_device_t device,
    const switch_api_l2_info_t *api_l2_rx_info,
    bool entry_add) {

    bf_status_t status;

    bf_rt_id_t field_id;
    bf_rt_id_t action_id;
    bf_rt_id_t data_field_id;

    bf_rt_target_t dev_tgt;
    bf_rt_session_hdl *session = NULL;
    bf_rt_info_hdl *bfrt_info_hdl = NULL;
    bf_rt_table_key_hdl *key_hdl = NULL;
    bf_rt_table_data_hdl *data_hdl = NULL;
    const bf_rt_table_hdl *table_hdl = NULL;

    dev_tgt.dev_id = device;
    dev_tgt.pipe_id = 0;
    dev_tgt.direction = 0xFF;
    dev_tgt.prsr_id = 0xFF;

    switch_handle_t rif_handle;
    switch_rif_info_t *rif_info = NULL;
    switch_port_t port_id;

    VLOG_DBG("%s", __func__);

    status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                               &bfrt_info_hdl, &session);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Switch PD handle fail");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_from_name_get(bfrt_info_hdl,
                                       LNW_L2_FWD_RX_TABLE,
                                       &table_hdl);
    if(status != BF_SUCCESS || !table_hdl) {
        VLOG_ERR("Unable to get table handle for: %s, error: %d",
                 LNW_L2_FWD_RX_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get key handle for: %s, error: %d",
                  LNW_L2_FWD_RX_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_L2_FWD_RX_TABLE_KEY_DST_MAC,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_L2_FWD_RX_TABLE_KEY_DST_MAC, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_set_value_ptr (key_hdl, field_id, 
                                            (const uint8_t *)
                                            &api_l2_rx_info->dst_mac.mac_addr, 
                                            SWITCH_MAC_LENGTH);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d, error: %d",
                  field_id, status);
        goto dealloc_handle_session;
    }

    if (entry_add) {
        /* Add an entry to target */
        VLOG_INFO("Populate l2_fwd action in %s for rif handle "
                  "%x ", LNW_L2_FWD_RX_TABLE,
                  (unsigned int) api_l2_rx_info->rif_handle);

        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_L2_FWD_RX_TABLE_ACTION_L2_FWD,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID: %d, error: %d",
                      action_id, status);
            goto dealloc_handle_session;
        }

        rif_handle = api_l2_rx_info->rif_handle;
        switch_status_t switch_status = switch_rif_get(device, rif_handle,
                                                       &rif_info);
        if (switch_status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("Unable to get rif info, error: %d", switch_status);
            goto dealloc_handle_session;
        }

        if (rif_info->api_rif_info.port_id == -1) {
          switch_pd_to_get_port_id(&(rif_info->api_rif_info));
        }

        /* While matching l2_fwd_rx_table should receive packet on phy-port
         * and send to control port. */
        port_id = rif_info->api_rif_info.port_id;

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_L2_FWD_PARAM_PORT,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_L2_FWD_PARAM_PORT, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                            port_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add %s entry, error: %d",
                      LNW_L2_FWD_RX_TABLE, status);
            goto dealloc_handle_session;
        }
    } else {
        /* Delete an entry from target */
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete %s entry, error: %d",
                      LNW_L2_FWD_RX_TABLE, status);
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

switch_status_t switch_pd_l2_rx_forward_with_tunnel_table_entry(
    switch_device_t device,
    const switch_api_l2_info_t *api_l2_rx_info,
    bool entry_add) {

    bf_status_t status;

    bf_rt_id_t field_id;
    bf_rt_id_t action_id;
    bf_rt_id_t data_field_id;

    bf_rt_target_t dev_tgt;
    bf_rt_session_hdl *session = NULL;
    bf_rt_info_hdl *bfrt_info_hdl = NULL;
    bf_rt_table_key_hdl *key_hdl = NULL;
    bf_rt_table_data_hdl *data_hdl = NULL;
    const bf_rt_table_hdl *table_hdl = NULL;

    dev_tgt.dev_id = device;
    dev_tgt.pipe_id = 0;
    dev_tgt.direction = 0xFF;
    dev_tgt.prsr_id = 0xFF;

    VLOG_DBG("%s", __func__);

    status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                               &bfrt_info_hdl, &session);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Switch PD handle fail");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_from_name_get(bfrt_info_hdl,
                                       LNW_L2_FWD_RX_WITH_TUNNEL_TABLE,
                                       &table_hdl);
    if(status != BF_SUCCESS || !table_hdl) {
        VLOG_ERR("Unable to get table handle for: %s, error: %d",
                  LNW_L2_FWD_RX_WITH_TUNNEL_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get key handle for: %s, error: %d",
                  LNW_L2_FWD_RX_WITH_TUNNEL_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_KEY_DST_MAC,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_KEY_DST_MAC, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_set_value_ptr (key_hdl, field_id, 
                                            (const uint8_t *)
                                            &api_l2_rx_info->dst_mac.mac_addr, 
                                            SWITCH_MAC_LENGTH);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d, error: %d",
                  field_id, status);
        goto dealloc_handle_session;
    }

    if (entry_add) {
        /* Add an entry to target */
        VLOG_INFO("Populate l2_fwd action in %s for rif handle %x",
                  LNW_L2_FWD_RX_WITH_TUNNEL_TABLE,
                  (unsigned int) api_l2_rx_info->rif_handle);

        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_ACTION_L2_FWD,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_ACTION_L2_FWD, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID: %d, error: %d",
                      action_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_L2_FWD_PARAM_PORT,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_L2_FWD_PARAM_PORT, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                            api_l2_rx_info->port_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add %s entry, error: %d",
                     LNW_L2_FWD_RX_WITH_TUNNEL_TABLE,
                     status);
            goto dealloc_handle_session;
        }
    } else {
        /* Delete an entry from target */
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete %s entry, error: %d",
                      LNW_L2_FWD_RX_WITH_TUNNEL_TABLE, status);
            goto dealloc_handle_session;
        }
    }

dealloc_handle_session:
    status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                                 entry_add);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to deallocate handle session");
        return switch_pd_status_to_status(status);
    }

    return switch_pd_status_to_status(status);
}
