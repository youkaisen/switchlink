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
#include "switch_fdb.h"
#include "switch_rif_int.h"
#include "switch_base_types.h"
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
    status = bf_rt_table_from_name_get(bfrt_info_hdl, "l2_fwd_tx_table",
                                       &table_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get table handle for l2_fwd_tx_table");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get key handle");
        return switch_pd_status_to_status(status);
    }

    field_id = 1;
    status = bf_rt_key_field_set_value_ptr (key_hdl, field_id, 
                            (const uint8_t *)&api_l2_tx_info->dst_mac.mac_addr,
                                        SWITCH_MAC_LENGTH);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d", field_id);
        return switch_pd_status_to_status(status);
    }

    if (entry_add) {
        /* Add an entry to target */
        action_id = 22384992; //action id for l2_fwd_tx_table, action: set_tunnel
        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
            return switch_pd_status_to_status(status);
        }

        data_field_id = 1;
        status = bf_rt_data_field_set_value_ptr (data_hdl, data_field_id,
                                                 0, sizeof(uint32_t));
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d", data_field_id);
            return switch_pd_status_to_status(status);
        }

        data_field_id = 2;
        status = bf_rt_data_field_set_value_ptr (data_hdl, data_field_id,
                                            (const uint8_t *)&api_tunnel_info->dst_ip.ip.v4addr,
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

    status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                                 entry_add);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to deallocate session and handles");
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
    bf_rt_session_hdl *session;
    bf_rt_info_hdl *bfrt_info_hdl;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
    const bf_rt_table_hdl *table_hdl;

    dev_tgt.dev_id = device;
    dev_tgt.pipe_id = 0;
    dev_tgt.direction = 0xFF;
    dev_tgt.prsr_id = 0xFF;

    switch_handle_t rif_handle;
    switch_rif_info_t *rif_info = NULL;
    switch_port_t port_id;

    VLOG_INFO("%s", __func__);

    status = switch_pd_allocate_handle_session(device, PROGRAM_NAME,
                                               &bfrt_info_hdl, &session);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Switch PD handle fail");
        return switch_pd_status_to_status(status);
    }

    table_hdl = (bf_rt_table_hdl *)malloc(sizeof(table_hdl));
    status = bf_rt_table_from_name_get(bfrt_info_hdl, "l2_fwd_rx_table",
                                       &table_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get table handle for l2_fwd_rx_table");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get key handle");
        return switch_pd_status_to_status(status);
    }

    field_id = 1;
    status = bf_rt_key_field_set_value_ptr (key_hdl, field_id, 
                                (const uint8_t *)&api_l2_rx_info->dst_mac.mac_addr, 
                                SWITCH_MAC_LENGTH);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d", field_id);
        return switch_pd_status_to_status(status);
    }

    if (entry_add) {
        /* Add an entry to target */
        action_id = 19169916;//action id for l2_fwd_rx_table, action: l2_fwd
        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID : %d", action_id);
            return switch_pd_status_to_status(status);
        }

        rif_handle = api_l2_rx_info->rif_handle;
        status = switch_rif_get(device, rif_handle, &rif_info);
        CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);
        port_id = rif_info->api_rif_info.port_id;

        data_field_id = 1;
        status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id,
                                            (const uint8_t *)&port_id,
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

    status = switch_pd_deallocate_handle_session(key_hdl, data_hdl, session,
                                                 entry_add);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to deallocate session and handles");
        return switch_pd_status_to_status(status);
    }

    return switch_pd_status_to_status(status);
}
