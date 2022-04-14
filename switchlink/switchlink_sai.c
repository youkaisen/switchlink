/*
Copyright 2013-present Barefoot Networks, Inc.

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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sai.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_db.h"
#include <linux/if_ether.h>
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(switchlink_sai);

extern sai_status_t sai_initialize();

static sai_port_api_t *port_api = NULL;
static sai_virtual_router_api_t *vrf_api = NULL;
static sai_fdb_api_t *fdb_api = NULL;
static sai_router_interface_api_t *rintf_api = NULL;
static sai_neighbor_api_t *neigh_api = NULL;
static sai_next_hop_api_t *nhop_api = NULL;
static sai_next_hop_group_api_t *nhop_group_api = NULL;
static sai_route_api_t *route_api = NULL;
static sai_l2mc_api_t *l2mc_api = NULL;
static sai_hostif_api_t *host_intf_api = NULL;
static sai_tunnel_api_t *tunnel_api = NULL;


// This object ID is not used.
// Introduced this variable to be inline with submodules/SAI declarations
static sai_object_id_t obj_id = 0;

static inline uint32_t ipv4_prefix_len_to_mask(uint32_t prefix_len) {
  return (prefix_len ? (((uint32_t)0xFFFFFFFF) << (32 - prefix_len)) : 0);
}

static inline struct in6_addr ipv6_prefix_len_to_mask(uint32_t prefix_len) {
  struct in6_addr mask;
  memset(&mask, 0, sizeof(mask));
  ovs_assert(prefix_len <= 128);

  int i;
  for (i = 0; i < 4; i++) {
    if (prefix_len > 32) {
      mask.s6_addr32[i] = 0xFFFFFFFF;
    } else {
      mask.s6_addr32[i] = htonl(ipv4_prefix_len_to_mask(prefix_len));
      break;
    }
    prefix_len -= 32;
  }
  return mask;
}

int switchlink_vrf_create(uint16_t vrf_id, switchlink_handle_t *vrf_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  sai_attribute_t attr_list[2];

  memset(attr_list, 0, sizeof(attr_list));
  attr_list[0].id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE;
  attr_list[0].value.booldata = true;
  attr_list[1].id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE;
  attr_list[1].value.booldata = true;

  VLOG_DBG("Create VRF is requested");
  status = vrf_api->create_virtual_router(vrf_h, 0, 2, attr_list);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_tuntap_create(switchlink_db_tuntap_info_t *tunp,
                                switchlink_handle_t *tunp_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  sai_attribute_t attr_list[2];
  int ac = 0;
  memset(attr_list, 0, sizeof(attr_list));
  attr_list[ac].id = SAI_PORT_ATTR_HW_LANE_LIST;
  attr_list[ac].value.oid = tunp->ifindex;
  ac++;
  attr_list[ac].id = SAI_PORT_ATTR_MTU;
  attr_list[ac].value.u32 = 1500; // Hard Coded Value for now
  ac++;

  status =
      port_api->create_port(tunp_h, 0, ac++, attr_list);

  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_interface_create(switchlink_db_interface_info_t *intf,
                                switchlink_handle_t *intf_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  if (intf->intf_type == SWITCHLINK_INTF_TYPE_L3) {
    sai_attribute_t attr_list[10];
    int ac = 0;
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[ac].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr_list[ac].value.oid = intf->vrf_h;
    ac++;
    attr_list[ac].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr_list[ac].value.oid = 0;
    if (intf_h) {
        attr_list[ac].value.oid = *intf_h;
    }
    ac++;
    attr_list[ac].id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
    memcpy(attr_list[ac].value.mac, intf->mac_addr, sizeof(sai_mac_t));
    ac++;
    attr_list[ac].id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
    attr_list[ac].value.u32 = intf->ifindex;
    ac++;

    status =
        rintf_api->create_router_interface(intf_h, 0, ac++, attr_list);
  }
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_interface_delete(switchlink_db_interface_info_t *intf,
                                switchlink_handle_t intf_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  if (intf->intf_type == SWITCHLINK_INTF_TYPE_L3) {
    status = rintf_api->remove_router_interface(intf_h);
  }
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

sai_status_t switchlink_create_tunnel(
                            switchlink_db_tunnel_interface_info_t *tnl_intf,
          switchlink_handle_t *tnl_intf_h) {
    sai_attribute_t attr_list[10];
    int ac = 0;
    memset(attr_list, 0, sizeof(attr_list));


    // TODO looks like remote is valid only for PEER_MODE = P2P
    if (tnl_intf->src_ip.family == AF_INET) {
        attr_list[ac].id = SAI_TUNNEL_ATTR_ENCAP_SRC_IP;
        attr_list[ac].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        attr_list[ac].value.ipaddr.addr.ip4 =
                        htonl(tnl_intf->src_ip.ip.v4addr.s_addr);
        ac++;
    }

    // TODO looks like remote is valid only for PEER_MODE = P2P
    if (tnl_intf->dst_ip.family == AF_INET) {
        attr_list[ac].id = SAI_TUNNEL_ATTR_ENCAP_DST_IP;
        attr_list[ac].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        attr_list[ac].value.ipaddr.addr.ip4 =
                        htonl(tnl_intf->dst_ip.ip.v4addr.s_addr);
        ac++;
    }

    attr_list[ac].id = SAI_TUNNEL_ATTR_VXLAN_UDP_SPORT;
    attr_list[ac].value.u16 = tnl_intf->dst_port;
    ac++;

    return tunnel_api->create_tunnel(tnl_intf_h, 0, ac, attr_list);
}

sai_status_t switchlink_create_term_table_entry(
                            switchlink_db_tunnel_interface_info_t *tnl_intf,
                            switchlink_handle_t *tnl_term_intf_h) {
    sai_attribute_t attr_list[10];
    memset(attr_list, 0, sizeof(attr_list));
    int ac = 0;

    if (tnl_intf->dst_ip.family == AF_INET) {
        attr_list[ac].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP;
        attr_list[ac].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        attr_list[ac].value.ipaddr.addr.ip4 =
                        htonl(tnl_intf->dst_ip.ip.v4addr.s_addr);
        ac++;
    }

    if (tnl_intf->src_ip.family == AF_INET) {
        attr_list[ac].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP;
        attr_list[ac].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        attr_list[ac].value.ipaddr.addr.ip4 =
                        htonl(tnl_intf->src_ip.ip.v4addr.s_addr);
        ac++;
    }

    attr_list[ac].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID;
    attr_list[ac].value.u32 = tnl_intf->vni_id;
    ac++;

    return tunnel_api->create_tunnel_term_table_entry(tnl_term_intf_h, 0, ac,
                                                      attr_list);
}

int switchlink_tunnel_interface_create(
                                switchlink_db_tunnel_interface_info_t *tnl_intf,
                                switchlink_handle_t *tnl_intf_h,
                                switchlink_handle_t *tnl_term_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    status = switchlink_create_tunnel(tnl_intf, tnl_intf_h);
    if (status != SAI_STATUS_SUCCESS) {
        VLOG_ERR("Cannot create tunnel for interface: %s", tnl_intf->ifname);
        return -1;
    }
    VLOG_INFO("Created tunnel interface: %s", tnl_intf->ifname);

    status = switchlink_create_term_table_entry(tnl_intf, tnl_term_h);
    if (status != SAI_STATUS_SUCCESS) {
        VLOG_ERR("Cannot create tunnel termination table entry for "
                 "interface: %s", tnl_intf->ifname);
        return -1;
    }
    VLOG_INFO("Created tunnel termination entry for "
              "interface: %s", tnl_intf->ifname);

    return 0;
}

sai_status_t switchlink_remove_tunnel_term_table_entry(
                        switchlink_db_tunnel_interface_info_t *tnl_intf) {
    return tunnel_api->remove_tunnel_term_table_entry(tnl_intf->tnl_term_h);
}

sai_status_t switchlink_remove_tunnel(
                        switchlink_db_tunnel_interface_info_t *tnl_intf) {

  return tunnel_api->remove_tunnel(tnl_intf->orif_h);
}

int switchlink_tunnel_interface_delete(switchlink_db_tunnel_interface_info_t
                                       *tnl_intf) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  status = switchlink_remove_tunnel_term_table_entry(tnl_intf);
  if (status != SAI_STATUS_SUCCESS) {
      VLOG_ERR("Cannot remove tunnel termination entry for "
               "interface: %s", tnl_intf->ifname);
      return -1;
  }
  VLOG_INFO("Removed tunnel termination entry for "
            "interface: %s", tnl_intf->ifname);

  status = switchlink_remove_tunnel(tnl_intf);
  if (status != SAI_STATUS_SUCCESS) {
      VLOG_ERR("Cannot remove tunnel entry for "
               "interface: %s", tnl_intf->ifname);
      return -1;
  }

  VLOG_INFO("Removed tunnel entry for interface: %s", tnl_intf->ifname);
  // Add further code to remove tunnel dependent params here.

  return 0;
}


int switchlink_mac_create(switchlink_mac_addr_t mac_addr,
                          switchlink_handle_t bridge_h,
                          switchlink_handle_t intf_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  sai_fdb_entry_t fdb_entry;
  memset(&fdb_entry, 0, sizeof(fdb_entry));
  memcpy(fdb_entry.mac_address, mac_addr, sizeof(sai_mac_t));

  sai_attribute_t attr_list[3];
  memset(&attr_list, 0, sizeof(attr_list));
  attr_list[0].id = SAI_FDB_ENTRY_ATTR_TYPE;
  attr_list[0].value.s32 = SAI_FDB_ENTRY_TYPE_STATIC;
  attr_list[1].id = SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID;
  attr_list[1].value.oid = intf_h;

  status = fdb_api->create_fdb_entry(&fdb_entry, 3, attr_list);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_mac_delete(switchlink_mac_addr_t mac_addr,
                          switchlink_handle_t bridge_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  sai_fdb_entry_t fdb_entry;
  memset(&fdb_entry, 0, sizeof(fdb_entry));
  memcpy(fdb_entry.mac_address, mac_addr, sizeof(sai_mac_t));
  fdb_entry.bv_id = bridge_h;

  status = fdb_api->remove_fdb_entry(&fdb_entry);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_nexthop_create(switchlink_db_neigh_info_t *neigh_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_attribute_t attr_list[3];
  memset(attr_list, 0, sizeof(attr_list));
  attr_list[0].id = SAI_NEXT_HOP_ATTR_TYPE;
  attr_list[0].value.s32 = SAI_NEXT_HOP_TYPE_IP;
  attr_list[1].id = SAI_NEXT_HOP_ATTR_IP;
  if (neigh_info->ip_addr.family == AF_INET) {
    attr_list[1].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    attr_list[1].value.ipaddr.addr.ip4 =
        htonl(neigh_info->ip_addr.ip.v4addr.s_addr);
  } else {
    attr_list[1].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    memcpy(attr_list[1].value.ipaddr.addr.ip6,
           &(neigh_info->ip_addr.ip.v6addr),
           sizeof(sai_ip6_t));
  }
  attr_list[2].id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
  attr_list[2].value.oid = neigh_info->intf_h;
  status =
      nhop_api->create_next_hop(&(neigh_info->nhop_h), 0, 3, attr_list);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_nexthop_delete(switchlink_db_neigh_info_t *neigh_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  status = nhop_api->remove_next_hop(neigh_info->nhop_h);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_neighbor_create(switchlink_db_neigh_info_t *neigh_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_attribute_t attr_list[1];
  memset(attr_list, 0, sizeof(attr_list));
  attr_list[0].id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
  memcpy(attr_list[0].value.mac, neigh_info->mac_addr, sizeof(sai_mac_t));

  sai_neighbor_entry_t neighbor_entry;
  memset(&neighbor_entry, 0, sizeof(neighbor_entry));
  neighbor_entry.rif_id = neigh_info->intf_h;
  if (neigh_info->ip_addr.family == AF_INET) {
    neighbor_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    neighbor_entry.ip_address.addr.ip4 =
        htonl(neigh_info->ip_addr.ip.v4addr.s_addr);
  } else {
    ovs_assert(neigh_info->ip_addr.family == AF_INET6);
    neighbor_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    memcpy(neighbor_entry.ip_address.addr.ip6,
           &(neigh_info->ip_addr.ip.v6addr),
           sizeof(sai_ip6_t));
  }

  status = neigh_api->create_neighbor_entry(&neighbor_entry, 1, attr_list);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_neighbor_delete(switchlink_db_neigh_info_t *neigh_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_neighbor_entry_t neighbor_entry;
  memset(&neighbor_entry, 0, sizeof(neighbor_entry));
  neighbor_entry.rif_id = neigh_info->intf_h;
  neighbor_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  neighbor_entry.ip_address.addr.ip4 =
      htonl(neigh_info->ip_addr.ip.v4addr.s_addr);

  status = neigh_api->remove_neighbor_entry(&neighbor_entry);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}


int switchlink_route_create(switchlink_db_route_info_t *route_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_route_entry_t route_entry;
  memset(&route_entry, 0, sizeof(route_entry));
  route_entry.vr_id = route_info->vrf_h;
  if (route_info->ip_addr.family == AF_INET) {
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    route_entry.destination.addr.ip4 =
        htonl(route_info->ip_addr.ip.v4addr.s_addr);
    route_entry.destination.mask.ip4 =
        htonl(ipv4_prefix_len_to_mask(route_info->ip_addr.prefix_len));
  } else {
    ovs_assert(route_info->ip_addr.family == AF_INET6);
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    memcpy(route_entry.destination.addr.ip6,
           &(route_info->ip_addr.ip.v6addr),
           sizeof(sai_ip6_t));
    struct in6_addr mask =
        ipv6_prefix_len_to_mask(route_info->ip_addr.prefix_len);
    memcpy(route_entry.destination.mask.ip6, &mask, sizeof(sai_ip6_t));
  }

  sai_attribute_t attr_list[1];
  memset(attr_list, 0, sizeof(attr_list));
  if (route_info->nhop_h == g_cpu_rx_nhop_h) {
    attr_list[0].id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
    attr_list[0].value.s32 = SAI_PACKET_ACTION_TRAP;
  } else {
    attr_list[0].id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    attr_list[0].value.oid = route_info->nhop_h;
  }

  VLOG_INFO("Switch SAI route create API is triggered");
  status = route_api->create_route_entry(&route_entry, 1, attr_list);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_route_delete(switchlink_db_route_info_t *route_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_route_entry_t route_entry;
  memset(&route_entry, 0, sizeof(route_entry));
  route_entry.vr_id = route_info->vrf_h;
  if (route_info->ip_addr.family == AF_INET) {
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    route_entry.destination.addr.ip4 =
        htonl(route_info->ip_addr.ip.v4addr.s_addr);
    route_entry.destination.mask.ip4 =
        htonl(ipv4_prefix_len_to_mask(route_info->ip_addr.prefix_len));
  } else {
    ovs_assert(route_info->ip_addr.family == AF_INET6);
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    memcpy(route_entry.destination.addr.ip6,
           &(route_info->ip_addr.ip.v6addr),
           sizeof(sai_ip6_t));
    struct in6_addr mask =
        ipv6_prefix_len_to_mask(route_info->ip_addr.prefix_len);
    memcpy(route_entry.destination.mask.ip6, &mask, sizeof(sai_ip6_t));
  }

  VLOG_INFO("Switch SAI route delete API is triggered");
  status = route_api->remove_route_entry(&route_entry);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_ecmp_create(switchlink_db_ecmp_info_t *ecmp_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  uint8_t index = 0;
  sai_attribute_t attr_list[1];
  sai_attribute_t attr_member_list[2];

  memset(attr_list, 0, sizeof(attr_list));
  attr_list[0].id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
  attr_list[0].value.s32 = SAI_NEXT_HOP_GROUP_TYPE_ECMP;

  status = nhop_group_api->create_next_hop_group(
      &(ecmp_info->ecmp_h), 0, 0x1, attr_list);
  ovs_assert(status == SAI_STATUS_SUCCESS);

  for (index = 0; index < ecmp_info->num_nhops; index++) {
    memset(attr_member_list, 0x0, sizeof(attr_member_list));
    attr_member_list[0].id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
    attr_member_list[0].value.oid = ecmp_info->ecmp_h;
    attr_member_list[1].id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
    attr_member_list[1].value.oid = ecmp_info->nhops[index];
    status = nhop_group_api->create_next_hop_group_member(
        &ecmp_info->nhop_member_handles[index], 0, 0x2, attr_member_list);
    ovs_assert(status == SAI_STATUS_SUCCESS);
  }

  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int switchlink_ecmp_delete(switchlink_db_ecmp_info_t *ecmp_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  uint8_t index = 0;
  for (index = 0; index < ecmp_info->num_nhops; index++) {
    status = nhop_group_api->remove_next_hop_group_member(
        ecmp_info->nhop_member_handles[index]);
  }
  status = nhop_group_api->remove_next_hop_group(ecmp_info->ecmp_h);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

void switchlink_api_init(void) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  status = sai_initialize();
  ovs_assert(status == SAI_STATUS_SUCCESS);

  status = sai_api_query(SAI_API_PORT, (void **)&port_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_VIRTUAL_ROUTER, (void **)&vrf_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_FDB, (void **)&fdb_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_ROUTER_INTERFACE, (void **)&rintf_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_NEIGHBOR, (void **)&neigh_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_NEXT_HOP, (void **)&nhop_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_ROUTE, (void **)&route_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_HOSTIF, (void **)&host_intf_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_TUNNEL, (void **)&tunnel_api);
  ovs_assert(status == SAI_STATUS_SUCCESS);

  return;
}
