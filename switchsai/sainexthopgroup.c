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

#include <config.h>
#include <sainexthopgroup.h>
#include "saiinternal.h"
//#include <switchapi/switch_interface.h>
#include <switchapi/switch_nhop.h>
//#include <switchapi/switch_mcast.h>
#include <openvswitch/vlog.h>

VLOG_DEFINE_THIS_MODULE(sainexthopgroup);

/*
* Routine Description:
*    Create next hop group
*
* Arguments:
*    [out] next_hop_group_id - next hop group id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
static sai_status_t sai_create_next_hop_group_entry(
    _Out_ sai_object_id_t *next_hop_group_id,
    _In_ sai_object_id_t switch_id,

    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list) {

  sai_status_t status = SAI_STATUS_SUCCESS;
  sai_attribute_t attribute;
  sai_next_hop_group_type_t nhgroup_type = -1;
  uint32_t index = 0;
  switch_handle_t next_hop_group_handle = SWITCH_API_INVALID_HANDLE;
  *next_hop_group_id = SAI_NULL_OBJECT_ID;

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  for (index = 0; index < attr_count; index++) {
    attribute = attr_list[index];
    switch (attribute.id) {
      case SAI_NEXT_HOP_GROUP_ATTR_TYPE:
        nhgroup_type = attribute.value.s32;
        break;
    }
  }

  if (nhgroup_type != SAI_NEXT_HOP_GROUP_TYPE_ECMP) {
    return SAI_STATUS_INVALID_PARAMETER;
  }

  status = switch_api_ecmp_create(switch_id, &next_hop_group_handle);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to create ECMP group %s",
                  sai_status_to_string(status));
    return status;
  }
  *next_hop_group_id = next_hop_group_handle;

  return (sai_status_t)status;
}

/*
* Routine Description:
*    Remove next hop group
*
* Arguments:
*    [in] next_hop_group_id - next hop group id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
static sai_status_t sai_remove_next_hop_group_entry(_In_ sai_object_id_t
                                                 next_hop_group_id) {

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  switch_status =
      switch_api_ecmp_delete(0, (switch_handle_t)next_hop_group_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to remove ECMP group %lx: %s",
                  next_hop_group_id,
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/**
 * @brief Create next hop group member
 *
 * @param[out] next_hop_group_member_id - next hop group member id
 * @param[in] attr_count - number of attributes
 * @param[in] attr_list - array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t sai_create_next_hop_group_member(
    _Out_ sai_object_id_t *next_hop_group_member_id,
    _In_ sai_object_id_t switch_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list) {

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  switch_handle_t nhop_group_id = 0;
  switch_handle_t nhop_id = 0;
  sai_attribute_t attribute;
  uint32_t index = 0;
  switch_handle_t member_id = SWITCH_API_INVALID_HANDLE;
  *next_hop_group_member_id = SAI_NULL_OBJECT_ID;

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    VLOG_ERR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  for (index = 0; index < attr_count; index++) {
    attribute = attr_list[index];
    switch (attribute.id) {
      case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID:
        nhop_group_id = attribute.value.oid;
        break;

      case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID:
        nhop_id = attribute.value.oid;
        break;
      default:
        break;
    }
  }

  switch_status = switch_api_ecmp_member_add(switch_id,
                                             (switch_handle_t)nhop_group_id,
                                             0x1,
                                             (switch_handle_t *)&nhop_id,
                                             &member_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to add member to ECMP group %lx : %s",
                  nhop_group_id,
                  sai_status_to_string(status));
  }

  *next_hop_group_member_id = (sai_object_id_t)member_id;

  return (sai_status_t)status;
}

/**
 * @brief Remove next hop group member
 *
 * @param[in] next_hop_group_member_id - next hop group member id
 *
 * @return SAI_STATUS_SUCCESS on success Failure status code on error
 */
static sai_status_t sai_remove_next_hop_group_member(_In_ sai_object_id_t
                                                     next_hop_group_member_id) {
  switch_handle_t nhop_group_id = 0;
  switch_handle_t nhop_id = 0;

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  switch_status = switch_api_ecmp_nhop_by_member_get(
      0, next_hop_group_member_id, &nhop_group_id, &nhop_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to ECMP group and nhop for member ID %lx : %s",
                  next_hop_group_member_id,
                  sai_status_to_string(status));
  }

  switch_status = switch_api_ecmp_member_delete(
      0, (switch_handle_t)nhop_group_id, 0x1, (switch_handle_t *)&nhop_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    VLOG_ERR("failed to remove member from ECMP group %lx : %s",
                  next_hop_group_member_id,
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/*
*  Next Hop group methods table retrieved with sai_api_query()
*/
sai_next_hop_group_api_t nhop_group_api = {
    .create_next_hop_group = sai_create_next_hop_group_entry,
    .remove_next_hop_group = sai_remove_next_hop_group_entry,
    .create_next_hop_group_member = sai_create_next_hop_group_member,
    .remove_next_hop_group_member = sai_remove_next_hop_group_member};

sai_status_t sai_next_hop_group_initialize(sai_api_service_t *sai_api_service) {
  VLOG_DBG("Initializing ECMP group");
  sai_api_service->nhop_group_api = nhop_group_api;
  return SAI_STATUS_SUCCESS;
}
