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

#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"

#include "switch_internal.h"
#include <openvswitch/vlog.h>
#include <config.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define __FILE_ID__ SWITCH_HANDLE
VLOG_DEFINE_THIS_MODULE(switch_handle);

switch_handle_type_t switch_handle_type_get(switch_handle_t handle) {
  switch_handle_type_t type = SWITCH_HANDLE_TYPE_NONE;
  type = handle >> SWITCH_HANDLE_TYPE_SHIFT;
  return type;
}

switch_status_t switch_handle_type_init(switch_device_t device,
                                        switch_handle_type_t type,
                                        switch_size_t size) {
  // Modified grow_on_demand to false, for linux_newtorking.p4
  return switch_handle_type_allocator_init(
      device, type, size * 4, false /*grow*/, false /*zero_based*/);
}

switch_status_t switch_handle_type_allocator_init(switch_device_t device,
                                                  switch_handle_type_t type,
                                                  switch_uint32_t num_handles,
                                                  bool grow_on_demand,
                                                  bool zero_based) {
  switch_device_context_t *device_ctx = NULL;
  switch_handle_info_t *handle_info = NULL;
  switch_id_allocator_t *allocator = NULL;
  switch_size_t size = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (device > SWITCH_MAX_DEVICE) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  if (type >= SWITCH_HANDLE_TYPE_MAX) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  handle_info = SWITCH_MALLOC(device, sizeof(switch_handle_info_t), 1);
  if (!handle_info) {
    status = SWITCH_STATUS_NO_MEMORY;
    VLOG_ERR("handle %s init failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }

  SWITCH_MEMSET(handle_info, 0x0, sizeof(switch_handle_info_t));

  size = (num_handles + 3) / 4;
  status = switch_api_id_allocator_new(device, size, zero_based, &allocator);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_FREE(device, handle_info);
    status = SWITCH_STATUS_FAILURE;
    VLOG_ERR("handle %s init failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }

  handle_info->type = type;
  handle_info->initial_size = size;
  handle_info->allocator = allocator;
  handle_info->num_in_use = 0;
  handle_info->num_handles = num_handles;
  handle_info->grow_on_demand = grow_on_demand;
  handle_info->zero_based = zero_based;
  handle_info->new_allocator = bf_id_allocator_new(size, zero_based);

  status = SWITCH_ARRAY_INSERT(
      &device_ctx->handle_info_array, type, (void *)handle_info);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s init failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    switch_api_id_allocator_destroy(device, handle_info->allocator);
    bf_id_allocator_destroy(handle_info->new_allocator);
    SWITCH_FREE(device, handle_info);
    return status;
  }

  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_handle_type_free(switch_device_t device,
                                        switch_handle_type_t type) {
  switch_device_context_t *device_ctx = NULL;
  switch_handle_info_t *handle_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (device > SWITCH_MAX_DEVICE) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle free failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle free failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  if (type >= SWITCH_HANDLE_TYPE_MAX) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle free failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  status = SWITCH_ARRAY_GET(
      &device_ctx->handle_info_array, type, (void *)&handle_info);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s free failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }

  switch_api_id_allocator_destroy(device, handle_info->allocator);
  bf_id_allocator_destroy(handle_info->new_allocator);
  status = SWITCH_ARRAY_DELETE(&device_ctx->handle_info_array, type);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s free failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }
  SWITCH_FREE(device, handle_info);
  return status;
}

static switch_handle_t __switch_handle_create(switch_device_t device,
                                       switch_handle_type_t type,
                                       unsigned int count) {
  switch_device_context_t *device_ctx = NULL;
  switch_handle_info_t *handle_info = NULL;
  switch_handle_t handle = SWITCH_API_INVALID_HANDLE;
  switch_uint32_t id = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (device > SWITCH_MAX_DEVICE) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  if (type >= SWITCH_HANDLE_TYPE_MAX) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle allocate failed: %s\n",
                     switch_error_to_string(status));
    return SWITCH_API_INVALID_HANDLE;
  }

  status = SWITCH_ARRAY_GET(
      &device_ctx->handle_info_array, type, (void **)&handle_info);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s allocate failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return SWITCH_API_INVALID_HANDLE;
  }

  if (((handle_info->num_in_use + count - 1) < handle_info->num_handles) ||
      handle_info->grow_on_demand) {
    if (count == 1)
      status =
          switch_api_id_allocator_allocate(device, handle_info->allocator, &id);
    else
      status = switch_api_id_allocator_allocate_contiguous(
          device, handle_info->allocator, count, &id);
    if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR("handle %s allocate failed: %s\n",
                       switch_handle_type_to_string(type),
                       switch_error_to_string(status));
      return SWITCH_API_INVALID_HANDLE;
    }
    handle_info->num_in_use++;
    handle = id_to_handle(type, id);
  }

  return handle;
}

static switch_status_t _switch_handle_delete_contiguous(switch_device_t device,
                                                 switch_handle_t handle,
                                                 uint32_t count) {
  switch_device_context_t *device_ctx = NULL;
  switch_handle_info_t *handle_info = NULL;
  switch_uint32_t id = 0;
  switch_handle_type_t type = SWITCH_HANDLE_TYPE_NONE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (device > SWITCH_MAX_DEVICE) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle init failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  type = switch_handle_type_get(handle);
  status = SWITCH_ARRAY_GET(
      &device_ctx->handle_info_array, type, (void *)&handle_info);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s free failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }

  id = handle_to_id(handle);
  for (unsigned int i = 0; i < count; i++)
    switch_api_id_allocator_release(device, handle_info->allocator, id + i);
  handle_info->num_in_use -= count;
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t _switch_handle_delete(switch_device_t device,
                                      switch_handle_t handle) {
  return _switch_handle_delete_contiguous(device, handle, 1);
}

static switch_handle_t _switch_handle_create(switch_device_t device,
                                      switch_handle_type_t type,
                                      switch_uint32_t size,
                                      unsigned int count) {
  switch_device_context_t *device_ctx = NULL;
  void *i_info = NULL;
  void *handle_array = NULL;
  switch_handle_t handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s create and set failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return SWITCH_API_INVALID_HANDLE;
  }

  handle_array = &device_ctx->handle_array[type];
  handle = __switch_handle_create(device, type, count);

  if (handle == SWITCH_API_INVALID_HANDLE) {
    status = SWITCH_STATUS_FAILURE;
    VLOG_ERR("handle %s create failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return SWITCH_API_INVALID_HANDLE;
  }

  i_info = SWITCH_MALLOC(device, size, 1);
  if (!i_info) {
    status = SWITCH_STATUS_NO_MEMORY;
    VLOG_ERR("handle %s create failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    _switch_handle_delete(device, handle);
    return SWITCH_API_INVALID_HANDLE;
  }

  SWITCH_MEMSET(i_info, 0, size);

  status = SWITCH_ARRAY_INSERT(handle_array, handle, (void *)i_info);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s create failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    SWITCH_FREE(device, i_info);
    _switch_handle_delete(device, handle);
    return SWITCH_API_INVALID_HANDLE;
  }
  return handle;
}

switch_handle_t switch_handle_create(switch_device_t device,
                                     switch_handle_type_t type,
                                     switch_uint32_t size) {
  return _switch_handle_create(device, type, size, 1);
}

switch_handle_t switch_handle_create_contiguous(switch_device_t device,
                                                switch_handle_type_t type,
                                                switch_uint32_t size,
                                                unsigned int count) {
  return _switch_handle_create(device, type, size, count);
}

switch_status_t switch_handle_get(switch_device_t device,
                                  switch_handle_type_t type,
                                  switch_handle_t handle,
                                  void **i_info) {
  switch_device_context_t *device_ctx = NULL;
  void *handle_array = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_HANDLE_VALID(handle, type)) {
    VLOG_ERR("handle type not %s: handle: %lx\n",
                     switch_handle_type_to_string(type),
                     handle);
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s create and set failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }
  handle_array = &device_ctx->handle_array[type];

  status = SWITCH_ARRAY_GET(handle_array, handle, (void **)i_info);

  type = switch_handle_type_get(handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s get failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_handle_delete_contiguous(switch_device_t device,
                                                switch_handle_type_t type,
                                                switch_handle_t handle,
                                                uint32_t count) {
  switch_device_context_t *device_ctx = NULL;
  void *i_info = NULL;
  void *handle_array = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s create and set failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }
  handle_array = &device_ctx->handle_array[type];

  status = SWITCH_ARRAY_GET(handle_array, handle, (void **)&i_info);

  type = switch_handle_type_get(handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s delete failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }

  status = SWITCH_ARRAY_DELETE(handle_array, handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s delete failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }

  status = _switch_handle_delete_contiguous(device, handle, count);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle %s delete failed: %s\n",
                     switch_handle_type_to_string(type),
                     switch_error_to_string(status));
    return status;
  }
  SWITCH_FREE(device, i_info);
  return status;
}

switch_status_t switch_handle_delete(switch_device_t device,
                                     switch_handle_type_t type,
                                     switch_handle_t handle) {
  return switch_handle_delete_contiguous(device, type, handle, 1);
}

switch_status_t switch_api_handle_count_get(switch_device_t device,
                                            switch_handle_type_t type,
                                            switch_size_t *num_entries) {
  switch_device_context_t *device_ctx = NULL;
  switch_handle_info_t *handle_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  SWITCH_ASSERT(type < SWITCH_HANDLE_TYPE_MAX);
  SWITCH_ASSERT(num_entries != NULL);
  *num_entries = 0;

  status = switch_device_context_get(device, &device_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle count get failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  status = SWITCH_ARRAY_GET(
      &device_ctx->handle_info_array, type, (void *)&handle_info);

  if (status != SWITCH_STATUS_SUCCESS) {
    VLOG_ERR("handle count get failed: %s\n",
                     switch_error_to_string(status));
    return status;
  }

  *num_entries = handle_info->num_in_use;

  return status;
}

#ifdef __cplusplus
}
#endif
