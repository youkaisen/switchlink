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
#include <net/if.h>
#include <bf_types/bf_types.h>
#include <port_mgr/dpdk/bf_dpdk_port_if.h>

#include "bf_rt/bf_rt_common.h"
#include "bf_rt/bf_rt_session.h"
#include "bf_rt/bf_rt_init.h"
#include "bf_rt/bf_rt_info.h"
#include "bf_rt/bf_rt_table.h"
#include "bf_rt/bf_rt_table_key.h"
#include "bf_rt/bf_rt_table_data.h"
#include "switch_internal.h"
#include "switch_base_types.h"
#include "switch_pd_utils.h"

VLOG_DEFINE_THIS_MODULE(switch_pd_utils);

/* TODO: check if session can be created only once and reuse it */
bf_status_t switch_pd_allocate_handle_session(const bf_dev_id_t device_id,
                                              const char *pipeline_name,
                                              bf_rt_info_hdl **bfrt_info_hdl_t,
                                              bf_rt_session_hdl **session_t) {
  bf_status_t status;

  status = bf_rt_session_create(session_t);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to create bfrt session");
      return status;
  }

  *bfrt_info_hdl_t = (bf_rt_info_hdl *)malloc(sizeof(bf_rt_info_hdl));
  status = bf_rt_info_get(device_id, pipeline_name,
                          (const bf_rt_info_hdl **)bfrt_info_hdl_t);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to get bfrt handle for pipeline: %s", pipeline_name);
      return status;
  }

  return status;
}

bf_status_t switch_pd_deallocate_handle_session(bf_rt_table_key_hdl *key_hdl_t,
                                                bf_rt_table_data_hdl *data_hdl_t,
                                                bf_rt_session_hdl *session_t,
                                                bool entry_type) {

  bf_status_t status;

  if (entry_type) {
      // Data handle is created only when entry is added to backend
      status = bf_rt_table_data_deallocate(data_hdl_t);
      if(status != BF_SUCCESS) {
          VLOG_ERR("Failed to deallocate data handler");
          return status;
      }
  }

  status = bf_rt_table_key_deallocate(key_hdl_t);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to deallocate key handler");
      return status;
  }

  status = bf_rt_session_destroy(session_t);
  if(status != BF_SUCCESS) {
      VLOG_ERR("Failed to destroy session");
      return status;
  }

  return status;
}

void
switch_pd_to_get_port_id(switch_api_rif_info_t **port_rif_info)
{
    char if_name[16] = {0};
    int i = 0;
    bf_dev_id_t bf_dev_id = 0;
    bf_dev_port_t bf_dev_port;
    bf_status_t bf_status;

    if (!if_indextoname((*port_rif_info)->rif_ifindex, if_name)) {
        VLOG_ERR("Failed to get ifname for the index: %d",
                 (*port_rif_info)->rif_ifindex);
        return;
    }

    for(i = 0; i < MAX_NO_OF_PORTS; i++) {
        struct port_info_t *port_info = NULL;
        bf_dev_port = (bf_dev_port_t)i;
        bf_status = (bf_pal_port_info_get(bf_dev_id,
                                          bf_dev_port,
                                          &port_info));
        if (port_info == NULL)
            continue;

        if (!strcmp((port_info)->port_attrib.port_name, if_name)) {
            // With multi-pipeline support, return target dp index
            // for both direction
            VLOG_DBG("found the target dp index %d for sdk port id %d",
                      port_info->port_attrib.port_in_id, i);
            (*port_rif_info)->port_id = port_info->port_attrib.port_in_id;
            if (i > CONFIG_PORT_INDEX) {
                bf_dev_port_t bf_dev_port_control = i - CONFIG_PORT_INDEX;
                port_info = NULL;
                bf_pal_port_info_get(bf_dev_id, bf_dev_port_control,
                                     &port_info);
                if (port_info == NULL) {
                    VLOG_ERR("Failed to find the target dp index for "
                             "control port associated with : %s", if_name);
                    return;
                }
                (*port_rif_info)->phy_port_id = 
                                        port_info->port_attrib.port_in_id;
            }
            return;
        }
    }

    VLOG_ERR("Failed to find the target dp index for ifname : %s", if_name);

    return;
}

