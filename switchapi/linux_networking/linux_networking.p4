#ifndef LINUX_NETWORKING_P4_
#define LINUX_NETWORKING_P4_

#include <core.p4>
#include "pna.p4"

// TODO Andy: There should be some form of this in pna.p4 include file.
extern void recirculate();

/* TODO: Add Control plane and exception packet flows */
/* TODO: Receive flows taht we didn't finish last time */

const PortId_t DEFAULT_MGMT_VPORT = (PortId_t) 0;   // IMC

// These are the initial values only.  Runtime can change these later.
const PortId_t INITIAL_DEFAULT_P0_VPORT = (PortId_t) 0;
const PortId_t INITIAL_DEFAULT_P1_VPORT = (PortId_t) 0;
const PortId_t DEFAULT_EXCEPTION_VPORT  = (PortId_t) 0;
const PortId_t DEFAULT_DEBUG_VPORT      = (PortId_t) 0;


/*  
 * Network-to-host traffic - Traffic coming in from Tunnel port
 * Host-to-network traffic - Traffic coming in from Local Pod or Gateway
 */

bool RxPkt (in pna_main_input_metadata_t istd) {
    return (istd.direction == PNA_Direction_t.NET_TO_HOST);
}

bool TxPkt (in pna_main_input_metadata_t istd) {
    return (istd.direction == PNA_Direction_t.HOST_TO_NET);
}

// Usha moved the include statements before - The above definitions are used in other p4 files as well.
#include "routing.p4"
#include "headers.p4"
#include "metadata.p4"
#include "parser.p4"
#include "tunnel.p4"

#define TUNNEL_ENABLE

void copy_header_vlan(inout vlan_t[2] hdr, in vlan_t[2] outer_hdr) {
    if (hdr[0].isValid()) {
        hdr[0].pcp_cfi_vid = outer_hdr[0].pcp_cfi_vid;
        hdr[0].ether_type = outer_hdr[0].ether_type;
    }
}

void copy_header_arp(inout arp_t hdr, in arp_t outer_hdr) {
    hdr.hw_type = outer_hdr.hw_type;
    hdr.proto_type = outer_hdr.proto_type;
    hdr.hw_addr_len = outer_hdr.hw_addr_len;
    hdr.proto_addr_len = outer_hdr.proto_addr_len;
    hdr.opcode = outer_hdr.opcode;
    hdr.sender_hw_addr = outer_hdr.sender_hw_addr;
    hdr.sender_proto_addr = outer_hdr.sender_proto_addr;
    hdr.target_hw_addr = outer_hdr.target_hw_addr;
    hdr.target_proto_addr = outer_hdr.target_proto_addr;
}



control PreControlImpl(
        in    headers_t  hdr,
        inout local_metadata_t meta,
        in    pna_pre_input_metadata_t  istd,
        inout pna_pre_output_metadata_t ostd)
{
    apply { }
}

control linux_networking_control(inout headers_t hdr,
        inout local_metadata_t local_metadata,
        in pna_main_input_metadata_t istd,
        inout pna_main_output_metadata_t ostd)
{
    ActionRef_t vendormeta_mod_action_ref = (16w1 << NO_MODIFY);
    ModDataPtr_t vendormeta_mod_data_ptr = 0xFFFF;
    ModDataPtr_t vendormeta_neighbor_mod_data_ptr = 0xFFFF;

    action do_recirculate() {
        //    recirculate();
    }

    action set_exception(PortId_t vport) {
        send_to_port(vport);
        local_metadata.exception_packet = 1;
    }

    action set_control(PortId_t vport) {
        send_to_port(vport);
        local_metadata.control_packet = 1;
    }

    action send_to_managemnt() {
        send_to_port(DEFAULT_MGMT_VPORT);
    }

    table always_recirculate_table {
        key = {
        }
        actions = {
            do_recirculate;
        }
        const default_action = do_recirculate;
        size = 0;
    }

    // ************ Add outer IP encapsulation **************************

    InternetChecksum() ck;
    Hash<bit<16>>(PNA_HashAlgorithm_t.TARGET_DEFAULT) src_port_hash_fn;

    action add_udp_header(bit<16> dst_port) {
        //    hdr.outer_udp.src_port = istd.common.hash;
        hdr.outer_udp.src_port = 32000;
        hdr.outer_udp.dst_port = dst_port;
        hdr.outer_udp.checksum = 0;
#ifdef UDP_CHECKSUM_ENABLE
        ck.clear();
        ck.add(hdr.outer_udp);
        ck.add(hdr.outer_ipv4.src_addr);
        ck.add(hdr.outer_ipv4.dst_addr);
        ck.add(hdr.outer_ipv4.total_len);

        hdr.outer_udp.checksum = ck.get();
#endif
    }

    action add_vxlan_header(vni_id_t vni) {
        hdr.vxlan.setValid();
        hdr.vxlan.flags = 0x08;
        hdr.vxlan.reserved = 0;
        hdr.vxlan.vni = vni;
        hdr.vxlan.reserved2 = 0;
    }

    action add_ipv4_header(bit<32> src_addr, bit<32> dst_addr, bit<8> proto) {
        hdr.outer_ipv4.version_ihl = 0x45;
        hdr.outer_ipv4.dscp_ecn = 0;
        hdr.outer_ipv4.identification = 0;
        hdr.outer_ipv4.flags_frag_offset = 0x4000;
        hdr.outer_ipv4.ttl = 0x40;
        hdr.outer_ipv4.protocol = proto;
        hdr.outer_ipv4.header_checksum = 0;
        hdr.outer_ipv4.src_addr = src_addr;
        hdr.outer_ipv4.dst_addr = dst_addr;

        // Outer IP Header Checksum Calculation
        ck.clear();
        ck.add(hdr.outer_ipv4);
        hdr.outer_ipv4.header_checksum = ck.get();
    }

    action add_outer_ipv4_vxlan(bit<32> src_addr, bit<32> dst_addr,
            bit<16> vxlan_port, vni_id_t vni) {
        /* Outer IPv4 total_len field is
         * Outer Packet
         * Ethernet (14) | IPv4 (20) | UDP (8) | VXLAN (8) |
         * Inner Packet
         * Ethernet (14) | IPv4 (total_len)
         */
        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.total_len = hdr.ipv4.total_len + 50;
        add_ipv4_header(src_addr, dst_addr, IP_PROTOCOL_UDP);

        /* TODO: Suresh - Inner Packet With VLAN And ARP Packets */
        /* Outer UDP Header Length
         * Outer Packet
         * UDP (8) | VXLAN (8)
         * Inner Packet
         * Ethernet (14) | IPv4 (total_len)
         */
        hdr.outer_udp.setValid();
        hdr.outer_udp.hdr_length = hdr.ipv4.total_len + 30;
        add_udp_header(vxlan_port);

        add_vxlan_header(vni);
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.ether_type = ETHERTYPE_IPV4;
    }

    action vxlan_encap(ipv4_addr_t src_addr,
            ipv4_addr_t dst_addr,
            bit<16> dst_port,
            vni_id_t vni) {

        hdr.ethernet.dst_addr = hdr.outer_ethernet.dst_addr;
        hdr.ethernet.src_addr = hdr.outer_ethernet.src_addr;
        hdr.ethernet.ether_type = hdr.outer_ethernet.ether_type;
        hdr.ethernet.setValid();
        hdr.outer_ethernet.setInvalid();

#ifdef COPY_HEADER
        if (hdr.outer_vlan[0].isValid() || hdr.outer_vlan[1].isValid()) {
            copy_header_vlan(hdr.vlan, hdr.outer_vlan);
            hdr.outer_vlan[0].setInvalid();
            hdr.outer_vlan[1].setInvalid();
        }

        if (hdr.outer_vlan[1].isValid()) {
            copy_header_vlan(hdr.vlan[1], hdr.outer_vlan[1]);
            hdr.outer_vlan[1].setInvalid();
        }

        if (hdr.outer_arp.isValid()) {
            copy_header_arp(hdr.arp, hdr.outer_arp);
            hdr.outer_arp.setInvalid();
        }

#endif //COPY_HEADER

        if (hdr.outer_ipv4.isValid()) {
            hdr.ipv4.version_ihl = hdr.outer_ipv4.version_ihl;
            hdr.ipv4.dscp_ecn = hdr.outer_ipv4.dscp_ecn;
            hdr.ipv4.total_len = hdr.outer_ipv4.total_len;
            hdr.ipv4.identification = hdr.outer_ipv4.identification;
            hdr.ipv4.flags_frag_offset = hdr.outer_ipv4.flags_frag_offset;
            hdr.ipv4.ttl = hdr.outer_ipv4.ttl;
            hdr.ipv4.protocol = hdr.outer_ipv4.protocol;
            hdr.ipv4.header_checksum = hdr.outer_ipv4.header_checksum;
            hdr.ipv4.src_addr = hdr.outer_ipv4.src_addr;
            hdr.ipv4.dst_addr = hdr.outer_ipv4.dst_addr;
            hdr.ipv4.setValid();
            hdr.outer_ipv4.setInvalid();
        }

        if (hdr.outer_icmp.isValid()) {
            hdr.icmp.type = hdr.outer_icmp.type;
            hdr.icmp.code = hdr.outer_icmp.code;
            hdr.icmp.checksum = hdr.outer_icmp.checksum;
            hdr.icmp.setValid();

            hdr.outer_icmp.setInvalid();
        }

        if (hdr.outer_udp.isValid()) {
            hdr.udp.src_port = hdr.outer_udp.src_port;
            hdr.udp.dst_port = hdr.outer_udp.dst_port;
            hdr.udp.hdr_length = hdr.outer_udp.hdr_length;
            hdr.udp.checksum = hdr.outer_udp.checksum;
            hdr.udp.setValid();

            hdr.outer_udp.setInvalid();
        }

        if (hdr.outer_tcp.isValid()) {
            hdr.tcp.src_port = hdr.outer_tcp.src_port;
            hdr.tcp.dst_port = hdr.outer_tcp.dst_port;
            hdr.tcp.seq_no = hdr.outer_tcp.seq_no;
            hdr.tcp.ack_no = hdr.outer_tcp.ack_no;
            hdr.tcp.data_offset_res = hdr.outer_tcp.data_offset_res;
            hdr.tcp.flags = hdr.outer_tcp.flags;
            hdr.tcp.window = hdr.outer_tcp.window;
            hdr.tcp.checksum = hdr.outer_tcp.checksum;
            hdr.tcp.urgent_ptr = hdr.outer_tcp.urgent_ptr;
            hdr.tcp.setValid();

            hdr.outer_tcp.setInvalid();
        }

        add_outer_ipv4_vxlan(src_addr, dst_addr, dst_port, vni);
    }

    // SAI API: sai_create_tunnel
    table vxlan_encap_mod_table {
        key = {
            vendormeta_mod_data_ptr: exact;
        }
        actions = {
            vxlan_encap;
            NoAction;
        }
        const default_action = NoAction;
    }

    action no_modify () {
        // This is simply a packet modification action that makes no
        // header modifications.
    }

    action vxlan_decap_outer_ipv4 () {
        hdr.outer_ethernet.setInvalid();
        hdr.outer_ipv4.setInvalid();
        hdr.outer_udp.setInvalid();
        hdr.vxlan.setInvalid();
    }

    action vxlan_decap_outer_ipv6 () {
        hdr.outer_ethernet.setInvalid();
        hdr.outer_ipv6.setInvalid();
        hdr.outer_udp.setInvalid();
        hdr.vxlan.setInvalid();
    }

    action set_src_mac_start(bit<16> src_mac_addr_first) {
        hdr.outer_ethernet.src_addr[47:32] = src_mac_addr_first;
    }

    // SAI API: sai_create_neighbor_entry
    table rif_mod_table_start {
        key = {
            local_metadata.rif_mod_map_id : exact; /* index is mod map table */
        }
        actions = {
            set_src_mac_start; /* 2 bytes for port, 6 bytes for mac addr */
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 512;
    }

    action set_src_mac_mid(bit<16> src_mac_addr_mid) {
        /* src_mac_mid */
        hdr.outer_ethernet.src_addr[31:16] = src_mac_addr_mid;
    }

    // SAI API: sai_create_neighbor_entry
    table rif_mod_table_mid {
        key = {
            local_metadata.rif_mod_map_id : exact; /* index is mod map table */
        }
        actions = {
            set_src_mac_mid; /* 2 bytes for port, 6 bytes for mac addr */
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 512;
    }

    action set_src_mac_last(bit<16> src_mac_addr_last) {
        /* last 2 bytes */
        hdr.outer_ethernet.src_addr[15:0] = src_mac_addr_last;
    }

    // SAI API: sai_create_neighbor_entry
    table rif_mod_table_last {
        key = {
            local_metadata.rif_mod_map_id : exact; /* index is mod map table */
        }
        actions = {
            set_src_mac_last; /* 2 bytes for port, 6 bytes for mac addr */
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 512;
    }

#undef P4_COMPILER_SUPPORTS_TABLE_APPLY_INSIDE_OF_ACTION
    action set_outer_mac(ethernet_addr_t dst_mac_addr) {
        hdr.outer_ethernet.dst_addr = dst_mac_addr;
#ifdef P4_COMPILER_SUPPORTS_TABLE_APPLY_INSIDE_OF_ACTION
        // TODO: The P4_16 language specification, and open source p4test
        // front-end compiler, do not support making table.apply() calls
        // from inside of an action.  The #ifdef here is to make it quick
        // to switch between the version of this code that includes these
        // apply() calls, and one that does not, for different P4
        // compilers we want to pass this code through.
        rif_mod_table_start.apply();
        rif_mod_table_mid.apply();
        rif_mod_table_last.apply();
#endif  // P4_COMPILER_SUPPORTS_TABLE_APPLY_INSIDE_OF_ACTION
    }

    // SAI API: sai_create_neighbor_entry
    table neighbor_mod_table {
        key = {
            vendormeta_mod_data_ptr : exact;
        }
        actions = {
            set_outer_mac;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 65536;
    }

    action decap_outer_ipv4(tunnel_id_t tunnel_id) {
        local_metadata.tunnel.id = tunnel_id;
        vendormeta_mod_action_ref = vendormeta_mod_action_ref | (16w1 << VXLAN_DECAP_OUTER_IPV4);
        vendormeta_mod_data_ptr = tunnel_id;
    }

    action decap_outer_ipv6(tunnel_id_t tunnel_id) {
        local_metadata.tunnel.id = tunnel_id;
        vendormeta_mod_action_ref = vendormeta_mod_action_ref | (16w1 << VXLAN_DECAP_OUTER_IPV6);
    }

    // SAI API: sai_create_tunnel_term_table_entry
    table ipv4_tunnel_term_table {
        key = {
            local_metadata.tunnel.tun_type : exact @name("tunnel_type");
            hdr.outer_ipv4.src_addr : exact @name("ipv4_src");
            hdr.outer_ipv4.dst_addr : exact @name("ipv4_dst");
        }
        actions = {
            @tableonly decap_outer_ipv4;
            @defaultonly NoAction;
            //      @defaultonly set_exception;
        }
        default_action = NoAction;
        //    default_action = set_exception(DEFAULT_EXCEPTION_VPORT);  // The runtime sets default vPort per external port and per host port
    }

    action set_tunnel(ModDataPtr_t tunnel_id, ipv4_addr_t dst_addr) {
        vendormeta_mod_action_ref = vendormeta_mod_action_ref | (16w1 << VXLAN_ENCAP);
        vendormeta_mod_data_ptr = tunnel_id; /* ptr can be tunnel_id */
        local_metadata.ipv4_dst_match = dst_addr;
        local_metadata.is_tunnel = 1;
    }

    action l2_fwd(PortId_t port) {
        send_to_port(port);
        vendormeta_mod_action_ref = vendormeta_mod_action_ref | (16w1 << NO_MODIFY);
    }

    // Rx: do set_exception on miss
    // Tx: NoAction
    action l2_fwd_miss_action (PortId_t port) {
        // Proposal from Anjali: Compile-time error if the 'if'
        // expression is anything except RxPkt(istd) or TxPkt(istd).
        // We might generalize this in the future.
        // If default miss action has such an if expression, it is a
        // compile-time error to apply the table anywhere except that
        // there is an 'if' condition that implies RxPkt(istd), or
        // implies TxPkt(istd).
        if (RxPkt(istd)) {
            set_exception(port);
        } else {
            // Nothing for Tx packets
        }
    }

    // SAI API: sai_create_neighbor_entry
    table l2_fwd_rx_table {
        key = {
            hdr.outer_ethernet.dst_addr : exact @name("dst_mac") @id(1)
                @format(MAC_ADDRESS);
        }
        actions = {
            l2_fwd;
            @defaultonly NoAction;
            @defaultonly l2_fwd_miss_action;
        }
        const default_action = NoAction;
        //    const default_action = l2_fwd_miss_action(DEFAULT_MGMT_VPORT);
        size = 65536;
    }

    // SAI API: sai_create_fdb_entry
    table l2_fwd_rx_with_tunnel_table {
        key = {
            hdr.ethernet.dst_addr : exact @name("dst_mac") @id(1)
                @format(MAC_ADDRESS);
        }
        actions = {
            l2_fwd;
            @defaultonly NoAction;
            @defaultonly l2_fwd_miss_action;
        }
        const default_action = NoAction;
        //    const default_action = l2_fwd_miss_action(DEFAULT_MGMT_VPORT);
        size = 65536;
    }

    // SAI API: sai_create_fdb_entry
    table l2_fwd_tx_table {
        key = {
            hdr.outer_ethernet.dst_addr : exact @name("dst_mac") @id(1)
                @format(MAC_ADDRESS);
        }
        actions = {
            l2_fwd;
            set_tunnel;
            @defaultonly NoAction;
            @defaultonly l2_fwd_miss_action;
        }
        const default_action = NoAction;
        //    const default_action = l2_fwd_miss_action(DEFAULT_MGMT_VPORT);
        size = 65536;
    }

    Hash<bit<16>>(PNA_HashAlgorithm_t.TARGET_DEFAULT) ecmp_hash_fn;

    bool ecmp_group_id_valid = false;

    action drop() {
        drop_packet();
    }

    /* get egress port from rif_mod in control plane */
    action set_nexthop(router_interface_id_t router_interface_id,
            neighbor_id_t neighbor_id, PortId_t egress_port) {
        vendormeta_mod_action_ref = vendormeta_mod_action_ref | (16w1 << NEIGHBOR);
        vendormeta_neighbor_mod_data_ptr = (ModDataPtr_t) neighbor_id;
        local_metadata.rif_mod_map_id = router_interface_id;
        send_to_port(egress_port);
    }

    // SAI API: sai_create_next_hop_entry && sai_create_neighbor_entry
    table nexthop_table {
        key = {
            local_metadata.nexthop_id : exact;
        }
        actions = {
            set_nexthop;
        }
        size = 65536;
        //    const default_action = set_exception(DEFAULT_DEBUG_VPORT);
    }

    action set_nexthop_id (bit<16> nexthop_id) {
        local_metadata.nexthop_id = nexthop_id;
    }

    // SAI API: sai_create_next_hop_entry && sai_create_neighbor_entry
    table ecmp_hash_table {
        key = {
            local_metadata.host_info_tx_extended_flex_0 :exact;
            //  istd.common.hash : exact;
        }
        actions = {
            set_nexthop_id;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 65536;
    }

    action ecmp_hash_action(bit<16> ecmp_group_id) {
        ecmp_group_id_valid = true;
        local_metadata.host_info_tx_extended_flex_0 = ecmp_group_id;
    }

    // SAI API: sai_create_next_hop_entry & sai_create_route_entry
    table ipv4_table {
        key = {
            //      local_metadata.32_bit_zeros : ternary;
            local_metadata.ipv4_dst_match : lpm;
        }

        actions = {
            set_nexthop_id;
            ecmp_hash_action; /* not used in RX direction */
            @defaultonly NoAction;
        }

        const default_action = NoAction;
        size = 65536;
    }

    action set_control_dest(PortId_t port_id) {
        send_to_port(port_id);
    }

    action push_vlan_fwd(PortId_t port, bit<16> vlan_tag) {
        hdr.outer_vlan[0].ether_type = hdr.outer_ethernet.ether_type;
        hdr.outer_vlan[0].pcp_cfi_vid = vlan_tag;
        hdr.outer_vlan[0].setValid();
        hdr.outer_ethernet.ether_type = ETHERTYPE_VLAN;
        send_to_port(port);
    }

    action pop_vlan_fwd(PortId_t port) {
        hdr.outer_ethernet.ether_type = hdr.outer_vlan[0].ether_type;
        hdr.outer_vlan[0].setInvalid();
        send_to_port(port);
    }

    table handle_rx_control_pkts_table {
        key = {
            istd.input_port: exact;
        }

        actions = {
            NoAction;
            set_control_dest;
        }

        const default_action = NoAction;
        //        const default_action = set_exception(DEFAULT_DEBUG_VPORT);
    }

    table handle_rx_exception_pkts {
        key = {
            istd.input_port: exact;
        }

        actions = {
            NoAction;
            set_exception;
        }

        const default_action = NoAction;
        //const default_action = set_exception(DEFAULT_DEBUG_VPORT);
    }

    table handle_tx_control_vlan_pkts_table {
        key = {
            istd.input_port: exact;
            local_metadata.vlan_id: exact;
        }

        actions = {
            NoAction;
            pop_vlan_fwd;
        }

        const default_action = NoAction;
        //const default_action = set_exception(DEFAULT_DEBUG_VPORT);
    }

    table handle_tx_control_pkts_table {
        key = {
            istd.input_port: exact;
        }

        actions = {
            NoAction;
            push_vlan_fwd;
            set_control_dest;
        }

        const default_action = NoAction;
        //const default_action = set_exception(DEFAULT_DEBUG_VPORT);
    }

    table handle_tx_exception_pkts {
        key = {
            istd.input_port: exact;
        }

        actions = {
            NoAction;
            set_exception;
        }

        const default_action = NoAction;
        //        const default_action = set_exception(DEFAULT_DEBUG_VPORT);
    }

#ifdef ECMP
    const PNA_HashAlgorithm_t ECMP_HASH_ALGO = PNA_HashAlgorithm_t.TARGET_DEFAULT;
    ActionSelector(ECMP_HASH_ALGO, 128, 10) as1;

    // SAI API: sai_create_next_hop_entry && sai_create_neighbor_entry
    table ecmp_udp_hash {
        key = {
            hdr.ipv4.src_addr:selector;
            hdr.ipv4.dst_addr:selector;
            hdr.ipv4.protocol:selector;
            hdr.udp.src_port:selector;
            hdr.udp.dst_port:selector;
        }
        actions = {NoAction;}
        pna_implementation = as1;
    }
#endif //ECMP

    apply {
        if (RxPkt(istd)) {
            if (local_metadata.control_packet == 1) {
                handle_rx_control_pkts_table.apply();
            } else if (hdr.outer_ipv4.isValid() && hdr.ethernet.isValid()) {
                ipv4_tunnel_term_table.apply();
                l2_fwd_rx_with_tunnel_table.apply();
            } else {
                l2_fwd_rx_table.apply();
            }
        } else if (TxPkt(istd)) {
            if (local_metadata.control_packet == 1 && hdr.outer_vlan[0].isValid()) {
                handle_tx_control_vlan_pkts_table.apply();
            } else if (local_metadata.control_packet == 1) {
                handle_tx_control_pkts_table.apply();
            } else {
                l2_fwd_tx_table.apply();
            }
            switch (l2_fwd_tx_table.apply().action_run) {
                set_tunnel: {
                    ipv4_table.apply();
                    nexthop_table.apply();
                }
            }
        }


        if ((vendormeta_mod_action_ref & (16w1 << VXLAN_ENCAP)) != 0) {
            vxlan_encap_mod_table.apply();
        }

        if ((vendormeta_mod_action_ref & (16w1 << VXLAN_DECAP_OUTER_IPV4)) != 0) {
            vxlan_decap_outer_ipv4();
        }

        if ((vendormeta_mod_action_ref & (16w1 << VXLAN_DECAP_OUTER_IPV6)) != 0) {
            vxlan_decap_outer_ipv6();
        }

        if ((vendormeta_mod_action_ref & (16w1 << NEIGHBOR)) != 0) {
            vendormeta_mod_data_ptr = vendormeta_neighbor_mod_data_ptr;
            neighbor_mod_table.apply();
            switch (neighbor_mod_table.apply().action_run) {
                set_outer_mac: {
                    rif_mod_table_start.apply();
                    rif_mod_table_mid.apply();
                    rif_mod_table_last.apply();
                }
            }
        }

        if ((vendormeta_mod_action_ref & (16w1 << NO_MODIFY)) != 0) {
            no_modify();
        }


#ifdef MODIFY_SWITCH_BLOCK
        switch (vendormeta_mod_action_ref) {
            VXLAN_ENCAP: { vxlan_encap_mod_table.apply(); }
            VXLAN_DECAP_OUTER_IPV4: { vxlan_decap_outer_ipv4(); }
            VXLAN_DECAP_OUTER_IPV6: { vxlan_decap_outer_ipv6(); }

            NEIGHBOR: {
                switch (neighbor_mod_table.apply().action_run) {
                    set_outer_mac: {
                        rif_mod_table_start.apply();
                        rif_mod_table_mid.apply();
                        rif_mod_table_last.apply();
                    }
                    default: { /* body omitted */ }
                }
            }
            //neighbor_mod_table.apply(); }
            NO_MODIFY: { no_modify(); }
        }
#endif //MODIFY_SWITCH_BLOCK
    }
}  // control main

PNA_NIC(packet_parser(), PreControlImpl(), linux_networking_control(), packet_deparser()) main;

#endif // LINUX_NETWORKING_P4_
