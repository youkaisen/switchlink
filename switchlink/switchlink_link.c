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

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/route/nexthop.h>
#include <linux/if_bridge.h>
#include <linux/if.h>
#include <linux/version.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_int.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"
#include "openvswitch/vlog.h"
#include "openvswitch/dynamic-string.h"
#include "unixctl.h"

static unixctl_cb_func vxlan_dump_cache;

switchlink_handle_t g_default_vrf_h = 0;
switchlink_handle_t g_default_bridge_h = 0;
switchlink_handle_t g_default_stp_h = 0;
switchlink_handle_t g_cpu_rx_nhop_h = 0;

VLOG_DEFINE_THIS_MODULE(switchlink_link);

// TODO get a better API to find an IDPF netdev
int validate_interface_name(char *name) {
    if (strncmp(name, "eno", 3) && strncmp(name, "lo", 2))
       return 1;
    return 0;
}

static void tuntap_create(switchlink_db_tuntap_info_t *tunp) {
  switchlink_db_status_t status;
  switchlink_db_tuntap_info_t tunpinfo;

  status = switchlink_db_tuntap_get_info(tunp->ifindex, &tunpinfo);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // create the tuntap port
    status = switchlink_tuntap_create(tunp, &(tunp->tunp_h));
    if (status != 0) {
        VLOG_ERR("newlink: switchlink_tuntap_create failed\n");
        return;
    }
    // add the mapping to the db
    switchlink_db_tuntap_add(tunp->ifindex, tunp);
    memcpy(&tunpinfo, tunp, sizeof(switchlink_db_tuntap_info_t));
  } else {
    // tuntap interface has already been created
    // Update mac addr, if needed?
  }
  // update bridge and other domain for the tuntap port, as needed
}

static void interface_create(switchlink_db_interface_info_t *intf) {
  switchlink_db_status_t status;
  switchlink_db_interface_info_t ifinfo;

  status = switchlink_db_interface_get_info(intf->ifindex, &ifinfo);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // create the interface
    VLOG_DBG("Switchlink Interface Create: %s", intf->ifname);
    status = switchlink_interface_create(intf, &(intf->intf_h));
    if (status != 0) {
      NL_LOG_ERROR(("newlink: switchlink_interface_create failed\n"));
      return;
    }

    // add the mapping to the db
    switchlink_db_interface_add(intf->ifindex, intf);
    // CR: remove this copy memcpy(&ifinfo, intf, sizeof(switchlink_db_interface_info_t));
  } else {
    // interface has already been created
    // update mac address if it has changed
    if (memcmp(&(ifinfo.mac_addr),
               &(intf->mac_addr),
               sizeof(switchlink_mac_addr_t))) {
      switchlink_db_interface_update(intf->ifindex, &ifinfo);
    }
    intf->intf_h = ifinfo.intf_h;
  }
}

static void interface_delete(uint32_t ifindex) {
  switchlink_db_interface_info_t intf;
  if (switchlink_db_interface_get_info(ifindex, &intf) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    return;
  }

  VLOG_DBG("Switchlink Interface Delete: %s", intf.ifname);
  // delete the interface
  switchlink_interface_delete(&intf, intf.intf_h);
  switchlink_db_interface_delete(intf.ifindex);
}

static void tunnel_interface_create(
                             switchlink_db_tunnel_interface_info_t *tnl_intf) {
  switchlink_db_status_t status;
  switchlink_db_tunnel_interface_info_t tnl_ifinfo;

  status = switchlink_db_tunnel_interface_get_info(tnl_intf->ifindex, &tnl_ifinfo);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // create the interface

    VLOG_INFO("Switchlink tunnel interface: %s", tnl_intf->ifname);
    status = switchlink_tunnel_interface_create(tnl_intf, &(tnl_intf->orif_h), &(tnl_intf->tnl_term_h));
    if (status != 0) {
      NL_LOG_ERROR(("newlink: switchlink_tunnel_interface_create failed\n"));
      return;
    }

    // add the mapping to the db
    switchlink_db_tunnel_interface_add(tnl_intf->ifindex, tnl_intf);
    return;
  }
  //VLOG_DBG("Switchlink DB already has tunnel config for "
  //         "interface: %s", tnl_intf->ifname);
  return;
}

static void tunnel_interface_delete(uint32_t ifindex) {
  switchlink_db_tunnel_interface_info_t tnl_intf;
  if (switchlink_db_tunnel_interface_get_info(ifindex, &tnl_intf) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
      //VLOG_INFO("Trying to delete a tunnel %s which is not "
      //          "available", tnl_intf.ifname);
      VLOG_INFO("Trying to delete a tunnel %s which is not "
                "available");
    return;
  }

  VLOG_INFO("Switchlink tunnel interface: %s", tnl_intf.ifname);
  // delete the interface
  switchlink_tunnel_interface_delete(&tnl_intf);
  switchlink_db_tunnel_interface_delete(ifindex);

  return;
}

// Recevied an IP add notification for an interface.
// By default all port are considered as L2 ports, when an IP address
// is configured it converts to an L3 port.
void interface_change_type(uint32_t ifindex, switchlink_intf_type_t type) {
  switchlink_db_interface_info_t ifinfo;
  switchlink_db_interface_info_t intf;
  if (switchlink_db_interface_get_info(ifindex, &ifinfo) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    return;
  }

  if (type == ifinfo.intf_type) {
    return;
  }

  memset(&intf, 0, sizeof(switchlink_db_interface_info_t));
  strncpy(intf.ifname, ifinfo.ifname, SWITCHLINK_INTERFACE_NAME_LEN_MAX);
  intf.ifindex = ifinfo.ifindex;
  intf.intf_type = SWITCHLINK_INTF_TYPE_L3;
  intf.vrf_h = ifinfo.vrf_h;
  intf.flags.ipv4_unicast_enabled = true;
  intf.flags.ipv6_unicast_enabled = true;
  memcpy(&(intf.mac_addr), &ifinfo.mac_addr, sizeof(switchlink_mac_addr_t));

  interface_delete(ifinfo.ifindex);
  if (type == SWITCHLINK_INTF_TYPE_L3) {
    interface_create(&intf);
  }
}

static switchlink_link_type_t get_link_type(char *info_kind) {
  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_ETH;

  if (!strcmp(info_kind, "bridge")) {
    link_type = SWITCHLINK_LINK_TYPE_BRIDGE;
  } else if (!strcmp(info_kind, "vxlan")) {
    link_type = SWITCHLINK_LINK_TYPE_VXLAN;
  } else if (!strcmp(info_kind, "bond")) {
    link_type = SWITCHLINK_LINK_TYPE_BOND;
  } else if (!strcmp(info_kind, "tun")) {
    link_type = SWITCHLINK_LINK_TYPE_TUN;
  }

  return link_type;
}

/*
TODO: P4-OVS: Process Received Netlink messages here
*/

// Support Port(tuntap), Routing and Vxlan features
void process_link_msg(struct nlmsghdr *nlmsg, int type) {
  int hdrlen, attrlen;
  struct nlattr *attr, *nest_attr, *nest_attr_new;
  struct ifinfomsg *ifmsg;
  uint32_t master = 0;
  bool mac_addr_valid = false;
  bool prot_info_valid = false;
  char *linkname = NULL;
  int nest_attr_type;

  struct rtattr *tb[IFLA_MAX + 1];

  switchlink_db_interface_info_t intf_info;
  switchlink_db_tuntap_info_t tunp;
  switchlink_db_tunnel_interface_info_t tnl_intf_info;
  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_NONE;
  switchlink_stp_state_t stp_state = SWITCHLINK_STP_STATE_NONE;
  switchlink_handle_t bridge_h = 0;
  switchlink_handle_t stp_h = 0;

  uint32_t vni_id = 0;
  switchlink_ip_addr_t remote_ip_addr;
  switchlink_ip_addr_t src_ip_addr;
  uint32_t vxlan_dst_port = 0;
  uint32_t underlay_intf_ifindex = 0;
  uint8_t ttl = 0;

  ovs_assert((type == RTM_NEWLINK) || (type == RTM_DELLINK));
  ifmsg = nlmsg_data(nlmsg);
  hdrlen = sizeof(struct ifinfomsg);

/*
  if ((type == RTM_NEWLINK) && ((ifmsg->ifi_flags & IFF_UP) == 0)) {
      char intf_name[16] = {0};
      if_indextoname(ifmsg->ifi_index, intf_name);
      VLOG_INFO("Link is down, ignoring kernel notification for port: %s",
                 intf_name);
      return;
  }
*/

  VLOG_DBG("%slink: family = %d, type = %d, ifindex = %d, flags = 0x%x,"\
           "change = 0x%x\n", ((type == RTM_NEWLINK) ? "new" : "del"),
           ifmsg->ifi_family, ifmsg->ifi_type, ifmsg->ifi_index,
           ifmsg->ifi_flags, ifmsg->ifi_change);

  memset(&intf_info, 0, sizeof(switchlink_db_interface_info_t));
  memset(&tnl_intf_info, 0, sizeof(switchlink_db_tunnel_interface_info_t));
  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);
  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case IFLA_IFNAME:
        ovs_strzcpy(intf_info.ifname,
                nla_get_string(attr),
                SWITCHLINK_INTERFACE_NAME_LEN_MAX);
        VLOG_DBG("Interface name is %s\n", intf_info.ifname);
        break;
      case IFLA_LINKINFO:
        nla_for_each_nested(nest_attr, attr, attrlen) {
          nest_attr_type = nla_type(nest_attr);
          switch (nest_attr_type) {
            case IFLA_INFO_KIND:
              link_type = get_link_type(nla_get_string(nest_attr));
              linkname = nla_get_string(nest_attr);
              VLOG_DBG("LINK INFO KIND: %s\n", linkname);
              break;
            case IFLA_INFO_DATA:
              nla_for_each_nested(nest_attr_new, nest_attr, attrlen) {
                  int nest_attr_type_new = nla_type(nest_attr_new);
                  switch (nest_attr_type_new) {
                      case IFLA_VXLAN_ID:
                        vni_id = *(uint32_t *) nla_data(nest_attr_new);
                        VLOG_DBG("Interface VNI ID: %d\n", vni_id);
                        break;
                      case IFLA_VXLAN_PORT:
                        vxlan_dst_port =
                            htons(*(uint16_t *) nla_data(nest_attr_new));
                        VLOG_DBG("Interface Dst port: %d\n", vxlan_dst_port);
                        break;
                      case IFLA_VXLAN_GROUP:
                        memset(&remote_ip_addr, 0,
                               sizeof(switchlink_ip_addr_t));
                        remote_ip_addr.family = AF_INET;
                        remote_ip_addr.ip.v4addr.s_addr =
                            ntohl(nla_get_u32(nest_attr_new));
                        remote_ip_addr.prefix_len = 32;
                        VLOG_DBG("Remote Ipv4 address: 0x%x\n",
                                   remote_ip_addr.ip.v4addr.s_addr);
                        break;
                      case IFLA_VXLAN_LOCAL:
                        memset(&src_ip_addr, 0, sizeof(switchlink_ip_addr_t));
                        src_ip_addr.family = AF_INET;
                        src_ip_addr.ip.v4addr.s_addr =
                            ntohl(nla_get_u32(nest_attr_new));
                        src_ip_addr.prefix_len = 32;
                        VLOG_DBG("Src Ipv4 address: 0x%x\n",
                                   src_ip_addr.ip.v4addr.s_addr);
                        break;
                      case IFLA_VXLAN_TTL:
                        ttl = nla_get_u8(nest_attr_new);
                        VLOG_DBG("TTL: %d\n", ttl);
                        break;
                    default:
                      break;
                  }
              }
              break;
            default:
              break;
          }
        }
        break;
      case IFLA_ADDRESS: {
        mac_addr_valid = true;
        ovs_assert(nla_len(attr) == sizeof(switchlink_mac_addr_t));
        memcpy(&(intf_info.mac_addr), nla_data(attr), nla_len(attr));

        VLOG_DBG("Interface Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned char) intf_info.mac_addr[0],
               (unsigned char) intf_info.mac_addr[1],
               (unsigned char) intf_info.mac_addr[2],
               (unsigned char) intf_info.mac_addr[3],
               (unsigned char) intf_info.mac_addr[4],
               (unsigned char) intf_info.mac_addr[5]
               );

        break;
      }
      case IFLA_MASTER:
        master = nla_get_u32(attr);
        break;
      case IFLA_PROTINFO:
      case IFLA_AF_SPEC:
        break;
      default:
        break;
    }
    attr = nla_next(attr, &attrlen);
  }

  if (type == RTM_NEWLINK) {
    switch (link_type) {
      case SWITCHLINK_LINK_TYPE_TUN:
        if(strstr(intf_info.ifname, "swp") != NULL) {
          memset(&tunp, 0, sizeof(switchlink_db_tuntap_info_t));
          ovs_strzcpy(tunp.ifname, intf_info.ifname,
                          SWITCHLINK_INTERFACE_NAME_LEN_MAX);
          tunp.ifindex = ifmsg->ifi_index;
          memcpy(&(tunp.mac_addr), intf_info.mac_addr,
                          sizeof(switchlink_mac_addr_t));
          tunp.link_type = link_type;
          tuntap_create(&tunp);
        }
        break;

      case SWITCHLINK_LINK_TYPE_BRIDGE:
      case SWITCHLINK_LINK_TYPE_BOND:
      case SWITCHLINK_LINK_TYPE_ETH:
        break;

      case SWITCHLINK_LINK_TYPE_NONE: {
        if (validate_interface_name(intf_info.ifname)) {
          // Physical ports netdev in kernel doesnt have any LINK TYPE.
          // We handle such cases here.
          intf_info.ifindex = ifmsg->ifi_index;
          intf_info.vrf_h = g_default_vrf_h;
          intf_info.intf_type = SWITCHLINK_INTF_TYPE_L3;
          intf_info.flags.ipv4_unicast_enabled = true;
          intf_info.flags.ipv6_unicast_enabled = true;
          intf_info.flags.ipv4_multicast_enabled = false;
          intf_info.flags.ipv6_multicast_enabled = false;
          intf_info.flags.ipv4_urpf_mode = SWITCHLINK_URPF_MODE_NONE;
          intf_info.flags.ipv6_urpf_mode = SWITCHLINK_URPF_MODE_NONE;

          interface_create(&intf_info);
        }}
        break;

      case SWITCHLINK_LINK_TYPE_VXLAN: {
        switchlink_db_status_t status;
        ovs_strzcpy(tnl_intf_info.ifname, intf_info.ifname,
                    SWITCHLINK_INTERFACE_NAME_LEN_MAX);
        tnl_intf_info.dst_ip = remote_ip_addr;
        tnl_intf_info.src_ip = src_ip_addr;
        tnl_intf_info.link_type = link_type;
        tnl_intf_info.ifindex = ifmsg->ifi_index;
        tnl_intf_info.vni_id = vni_id;
        tnl_intf_info.dst_port = vxlan_dst_port;
        tnl_intf_info.ttl = ttl;

        if (underlay_intf_ifindex != 0) {
            VLOG_DBG("Underlay intf is not empty: %d\n", underlay_intf_ifindex);
            // TODO : Update underlay RIF handler information
            // Check if nhop_h is only to be added.
            status = switchlink_db_interface_get_info(underlay_intf_ifindex,
                                                      &intf_info);
            if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
                tnl_intf_info.urif_h = intf_info.intf_h;
            }
        } else {
            // TODO Check if this works as route lookup gives a route entry
            // Not checking any patricia tree for LPM
            // get the route from the db (if it already exists)
            // Extra logic should be added for route lookup with subnet
            switchlink_db_route_info_t route_info;
            memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
            route_info.vrf_h = g_default_vrf_h;
            memcpy(&(route_info.ip_addr), &remote_ip_addr,
                   sizeof(switchlink_ip_addr_t));
            switchlink_db_status_t status =
                switchlink_db_route_get_info(&route_info);
            if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
                tnl_intf_info.urif_h = route_info.nhop_h;
            }
        }
        tunnel_interface_create(&tnl_intf_info);
      }
      break;
      default:
        break;
    }
  } else {
    ovs_assert(type == RTM_DELLINK);
    if (link_type == SWITCHLINK_LINK_TYPE_VXLAN) {
        tunnel_interface_delete(ifmsg->ifi_index);
    } else if (tunnel_interface_delete == SWITCHLINK_LINK_TYPE_NONE) {
      interface_delete(ifmsg->ifi_index);
    }
  }
}

#if 0
/* Loop through all p4 devices and print particular p4 device's
 * local data or print for all available p4 devices */
static void
vxlan_dump_cache(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[], void *aux OVS_UNUSED)
{

  // TODO, dump cache crashes after dumping the context. Fix
  // the issue and then remove this return.
  return;
#if 0
  struct ds results;
  ds_init(&results);
  unixctl_command_reply(conn, ds_cstr(&results));
  ds_destroy(&results);
#endif
  switchlink_db_tunnel_interface_info_t tnl_ifinfo;
  struct ds results = DS_EMPTY_INITIALIZER;
  int if_index = if_nametoindex(argv[1]);
  switchlink_db_status_t status;

  if (if_index == 0) {
    return;
  }

  status = switchlink_db_tunnel_interface_get_info(if_index, &tnl_ifinfo);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    ds_put_format(&results, "\nCannot find config for interface %s", argv[1]);
  } else {
//    ds_put_format(&results, "\nConfig for VxLAN port %s is:", argv[1]);
    ds_put_format(&results, "\n\tDestination port ID: %d", tnl_ifinfo.dst_port);
    ds_put_format(&results, "\n\tDestination IP: %x", tnl_ifinfo.dst_ip.ip.v4addr.s_addr);
    ds_put_format(&results, "\n\tSource IP: %x", tnl_ifinfo.src_ip.ip.v4addr.s_addr);
    ds_put_format(&results, "\n\tIfindex: %d", tnl_ifinfo.ifindex);
    ds_put_format(&results, "\n\tVNI ID: %d", tnl_ifinfo.vni_id);
    ds_put_format(&results, "\n\tTTL : %d", tnl_ifinfo.ttl);
  }

  unixctl_command_reply(conn, ds_cstr(&results));
  ds_destroy(&results);
}
#endif

void switchlink_link_init() {
  /* P4OVS: create default vrf*/
  switchlink_vrf_create(SWITCHLINK_DEFAULT_VRF_ID, &g_default_vrf_h);

  /* P4OVS: Placeholder dummy value for now to bypass real vrf_create
   * Proper assignement need to happen once SAI layer is integrated
   * Will store VRF handle returned via create_virtual_router API
   */

  /* P4OVS: create default bridge */
  switchlink_db_bridge_info_t bridge_db_info;
  memset(&bridge_db_info, 0, sizeof(switchlink_db_bridge_info_t));
  bridge_db_info.vrf_h = g_default_vrf_h;

  /* P4OVS: Placeholder dummy values for now to bypass real lbridge_create
   * SAI API need to implement vlan and stp as well?
   */
  bridge_db_info.bridge_h = 0;
  bridge_db_info.stp_h = 0;

  g_default_bridge_h = bridge_db_info.bridge_h;
  g_default_stp_h = bridge_db_info.stp_h;

  //unixctl_command_register("p4vxlan/dump-cache", "[kernel-intf-name/all]", 1, 1,
  //                           vxlan_dump_cache, NULL);
}
