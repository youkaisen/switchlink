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

#include <saifdb.h>
#include "saiinternal.h"
#include <config.h>
#include <switchapi/switch_fdb.h>
#include <switchapi/switch_interface.h>
#include <switchapi/switch_device.h>
#include <linux/if_ether.h>
#include <openvswitch/vlog.h>

VLOG_DEFINE_THIS_MODULE(saifdb);

//static sai_api_t api_id = SAI_API_FDB;

static void sai_fdb_entry_to_string(_In_ const sai_fdb_entry_t *fdb_entry,
                                    _Out_ char *entry_string) {
  snprintf(entry_string,
           SAI_MAX_ENTRY_STRING_LEN,
           "fdb entry mac [%02x:%02x:%02x:%02x:%02x:%02x]",
           fdb_entry->mac_address[0],
           fdb_entry->mac_address[1],
           fdb_entry->mac_address[2],
           fdb_entry->mac_address[3],
           fdb_entry->mac_address[4],
           fdb_entry->mac_address[5]);
}

static sai_status_t sai_fdb_entry_parse(const sai_fdb_entry_t *fdb_entry,
                                        switch_api_l2_info_t *mac_entry) {

  memcpy(mac_entry->dst_mac.mac_addr, fdb_entry->mac_address, ETH_ALEN);
  return SWITCH_STATUS_SUCCESS;
}

static void sai_fdb_entry_attribute_parse(uint32_t attr_count,
                                          const sai_attribute_t *attr_list,
                                          switch_api_l2_info_t *mac_entry) {
  const sai_attribute_t *attribute;
  uint32_t i = 0;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID:
        mac_entry->rif_handle = attribute->value.oid;
        break;
    }
  }
}

/*
* Routine Description:
*    Create FDB entry
*
* Arguments:
*    [in] fdb_entry - fdb entry
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
static sai_status_t sai_create_fdb_entry(_In_ const sai_fdb_entry_t *fdb_entry,
                                  _In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t *attr_list) {
  switch_api_l2_info_t mac_entry;
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  char entry_string[SAI_MAX_ENTRY_STRING_LEN];
  switch_handle_t mac_handle;

  if (!fdb_entry) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null fdb entry: %s", sai_status_to_string(status));
    return status;
  }

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  memset(&mac_entry, 0, sizeof(mac_entry));
  sai_fdb_entry_parse(fdb_entry, &mac_entry);
  sai_fdb_entry_attribute_parse(attr_count, attr_list, &mac_entry);
  mac_entry.type = SWITCH_L2_FWD_TX;
  mac_entry.learn_from = SWITCH_L2_FWD_LEARN_PHYSICAL_INTERFACE;

  VLOG_INFO("Call switch API FDB entry create");
  switch_status = switch_api_l2_forward_create(0, &mac_entry,
                                               &mac_handle);
  status = sai_switch_status_to_sai_status(switch_status);

  if (status != SAI_STATUS_SUCCESS &&
      status != SWITCH_STATUS_ITEM_ALREADY_EXISTS) {
    sai_fdb_entry_to_string(fdb_entry, entry_string);
    VLOG_ERR("failed to create fdb entry %s : %s",
                  entry_string,
                  sai_status_to_string(status));
    return status;
  }

  return (sai_status_t)SAI_STATUS_SUCCESS;
}

/*
* Routine Description:
*    Remove FDB entry
*
* Arguments:
*    [in] fdb_entry - fdb entry
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
static sai_status_t sai_remove_fdb_entry(_In_ const sai_fdb_entry_t *fdb_entry) {
  switch_api_l2_info_t mac_entry;
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  char entry_string[SAI_MAX_ENTRY_STRING_LEN];

  if (!fdb_entry) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null fdb entry: %s", sai_status_to_string(status));
    return status;
  }

  memset(&mac_entry, 0, sizeof(mac_entry));
  sai_fdb_entry_parse(fdb_entry, &mac_entry);
  mac_entry.type = SWITCH_L2_FWD_TX;

  VLOG_INFO("Call switch API FDB entry delete");
  switch_status = switch_api_l2_forward_delete(0, &mac_entry);
  status = sai_switch_status_to_sai_status(switch_status);

  if (status != SAI_STATUS_SUCCESS) {
    sai_fdb_entry_to_string(fdb_entry, entry_string);
    VLOG_ERR("failed to remove fdb entry %s : %s",
                  entry_string,
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/*
*  FDB methods table retrieved with sai_api_query()
*/
sai_fdb_api_t fdb_api = {.create_fdb_entry = sai_create_fdb_entry,
                         .remove_fdb_entry = sai_remove_fdb_entry};

sai_status_t sai_fdb_initialize(sai_api_service_t *sai_api_service) {
  VLOG_DBG("initializing fdb");
  sai_api_service->fdb_api = fdb_api;
  return SAI_STATUS_SUCCESS;
}
