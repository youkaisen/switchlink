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
#include "switch_tunnel.h"
#include "switch_internal.h"
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

VLOG_DEFINE_THIS_MODULE(switch_pd_tunnel);

switch_status_t switch_pd_tunnel_entry(
    switch_device_t device,
    const switch_api_tunnel_info_t *api_tunnel_info_t,
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
        VLOG_ERR("Failed to allocate pd handle session");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_from_name_get(bfrt_info_hdl,
                                       LNW_VXLAN_ENCAP_MOD_TABLE,
                                       &table_hdl);
    if(status != BF_SUCCESS || !table_hdl) {
        VLOG_ERR("Unable to get table handle for: %s, error: %d",
                  LNW_VXLAN_ENCAP_MOD_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to allocate key handle for: %s, error: %d",
                  LNW_VXLAN_ENCAP_MOD_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_VXLAN_ENCAP_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_VXLAN_ENCAP_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR,
                  status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_set_value(key_hdl, field_id, 0 /*vni value*/);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d for vxlan_encap_mod_table"
                 ", error: %d", field_id, status);
        goto dealloc_handle_session;
    }

    if (entry_add) {
        /* Add an entry to target */
        VLOG_INFO("Populate vxlan encap action in vxlan_encap_mod_table for "
                  "tunnel interface %x",
                  (unsigned int) api_tunnel_info_t->overlay_rif_handle);

        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_VXLAN_ENCAP_MOD_TABLE_ACTION_VXLAN_ENCAP,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_VXLAN_ENCAP_MOD_TABLE_ACTION_VXLAN_ENCAP, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data handler for acion: %s, error: %d",
                     LNW_VXLAN_ENCAP_MOD_TABLE_ACTION_VXLAN_ENCAP, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_VXLAN_ENCAP_PARAM_SRC_ADDR,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_VXLAN_ENCAP_PARAM_SRC_ADDR, status);
            goto dealloc_handle_session;
        }

        network_byte_order = ntohl(api_tunnel_info_t->src_ip.ip.v4addr);
        status = bf_rt_data_field_set_value_ptr(
                                    data_hdl, data_field_id,
                                    (const uint8_t *)&network_byte_order,
                                    sizeof(uint32_t));

        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_VXLAN_ENCAP_PARAM_DST_ADDR,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_VXLAN_ENCAP_PARAM_DST_ADDR, status);
            goto dealloc_handle_session;
        }

        network_byte_order = ntohl(api_tunnel_info_t->dst_ip.ip.v4addr);
        status = bf_rt_data_field_set_value_ptr(
                                    data_hdl, data_field_id,
                                    (const uint8_t *)&network_byte_order,
                                    sizeof(uint32_t));

        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_VXLAN_ENCAP_PARAM_DST_PORT,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_VXLAN_ENCAP_PARAM_DST_PORT, status);
            goto dealloc_handle_session;
        }

        uint16_t network_byte_order_udp = ntohs(api_tunnel_info_t->udp_port);
        status = bf_rt_data_field_set_value_ptr(
                                    data_hdl, data_field_id,
                                    (const uint8_t *)&network_byte_order_udp,
                                    sizeof(uint16_t));

        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_VXLAN_ENCAP_PARAM_VNI,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_VXLAN_ENCAP_PARAM_DST_PORT, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value_ptr(data_hdl, data_field_id, 0,
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
    } else {
        /* Delete an entry from target */
        VLOG_INFO("Delete vxlan_encap_mod_table entry");
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete vxlan_encap_mod_table entry, error"
                     ": %d", status);
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

switch_status_t switch_pd_tunnel_term_entry(
    switch_device_t device,
    const switch_api_tunnel_term_info_t *api_tunnel_term_info_t,
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
        VLOG_ERR("Failed to allocate pd handle session");
        return switch_pd_status_to_status(status);
    }

    status = bf_rt_table_from_name_get(bfrt_info_hdl,
                                       LNW_IPV4_TUNNEL_TERM_TABLE,
                                       &table_hdl);
    if(status != BF_SUCCESS || !table_hdl) {
        VLOG_ERR("Unable to get table handle for: %s, error: %d",
                  LNW_IPV4_TUNNEL_TERM_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_table_key_allocate(table_hdl, &key_hdl);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to allocate key handle for: %s, error: %d",
                  LNW_IPV4_TUNNEL_TERM_TABLE, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_IPV4_TUNNEL_TERM_TABLE_KEY_TUNNEL_TYPE,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_IPV4_TUNNEL_TERM_TABLE_KEY_TUNNEL_TYPE, status);
        goto dealloc_handle_session;
    }

    /* From p4 file the value expected is TUNNEL_TYPE_VXLAN=2 */
    status = bf_rt_key_field_set_value(key_hdl, field_id, 2);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d of ipv4_tunnel_term_table"
                 ", error: %d", field_id, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_IPV4_TUNNEL_TERM_TABLE_KEY_IPV4_SRC,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_IPV4_TUNNEL_TERM_TABLE_KEY_IPV4_SRC, status);
        goto dealloc_handle_session;
    }

    /* This refers to incoming packet fields, where SIP will be the remote_ip
     * configured while creating tunnel */
    network_byte_order = ntohl(api_tunnel_term_info_t->dst_ip.ip.v4addr);
    status = bf_rt_key_field_set_value_ptr(key_hdl, field_id,
                                           (const uint8_t *)&network_byte_order,
                                           sizeof(uint32_t));
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d, error: %d",
                  field_id, status);
        goto dealloc_handle_session;
    }

    status = bf_rt_key_field_id_get(
                    table_hdl,
                    LNW_IPV4_TUNNEL_TERM_TABLE_KEY_IPV4_DST,
                    &field_id);
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to get field ID for key: %s, error: %d",
                  LNW_IPV4_TUNNEL_TERM_TABLE_KEY_IPV4_DST, status);
        goto dealloc_handle_session;
    }

    /* This refers to incoming packet fields, where DIP will be the local_ip
     * configured while creating tunnel */
    network_byte_order = ntohl(api_tunnel_term_info_t->src_ip.ip.v4addr);
    status = bf_rt_key_field_set_value_ptr(key_hdl, field_id,
                                           (const uint8_t *)&network_byte_order,
                                           sizeof(uint32_t));
    if(status != BF_SUCCESS) {
        VLOG_ERR("Unable to set value for key ID: %d, error: %d",
                  field_id, status);
        goto dealloc_handle_session;
    }

    if (entry_add) {
        VLOG_INFO("Populate decap_outer_ipv4 action in ipv4_tunnel_term_table "
                  "for tunnel interface %x",
                   (unsigned int) api_tunnel_term_info_t->tunnel_handle);

        status = bf_rt_action_name_to_id(
                            table_hdl,
                            LNW_IPV4_TUNNEL_TERM_TABLE_ACTION_DECAP_OUTER_IPV4,
                            &action_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator ID for: %s, error: %d",
                      LNW_IPV4_TUNNEL_TERM_TABLE_ACTION_DECAP_OUTER_IPV4,
                      status);
            goto dealloc_handle_session;
        }

        /* Add an entry to target */
        status = bf_rt_table_action_data_allocate(table_hdl, action_id,
                                                  &data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get action allocator for ID: %d, error: %d",
                      action_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_id_with_action_get(
                                    table_hdl,
                                    LNW_ACTION_DECAP_OUTER_IPV4_PARAM_TUNNEL_ID,
                                    action_id, &data_field_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to get data field id param for: %s, error: %d",
                      LNW_ACTION_DECAP_OUTER_IPV4_PARAM_TUNNEL_ID, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_data_field_set_value(data_hdl, data_field_id,
                                            api_tunnel_term_info_t->tunnel_id);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to set action value for ID: %d, error: %d",
                      data_field_id, status);
            goto dealloc_handle_session;
        }

        status = bf_rt_table_entry_add(table_hdl, session, &dev_tgt, key_hdl,
                                       data_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to add ipv4_tunnel_term_table entry, error: %d",
                      status);
            goto dealloc_handle_session;
        }
    } else {
        /* Delete an entry from target */
        VLOG_INFO("Delete ipv4_tunnel_term_table entry");
        status = bf_rt_table_entry_del(table_hdl, session, &dev_tgt, key_hdl);
        if(status != BF_SUCCESS) {
            VLOG_ERR("Unable to delete ipv4_tunnel_term_table entry, error: %d",
                      status);
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
