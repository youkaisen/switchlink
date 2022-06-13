"""
DPDK Tap and Link Port counter feature
"""

# in-built module imports
import time
import sys

# Unittest related imports
import unittest

# ptf related imports
import ptf
import ptf.dataplane as dataplane
from ptf.base_tests import BaseTest
from ptf.testutils import *
from ptf import config

# framework related imports
import common.utils.ovsp4ctl_utils as ovs_p4ctl
import common.utils.test_utils as test_utils
from common.utils.config_file_utils import get_config_dict, get_gnmi_params_simple, get_interface_ipv4_dict
from common.utils.gnmi_cli_utils import gnmi_cli_set_and_verify, gnmi_set_params, ip_set_ipv4,gnmi_get_params_elemt_value,gnmi_get_params_counter

class Tap_Link_PortCounter(BaseTest):

    def setUp(self):
        BaseTest.setUp(self)
        self.result = unittest.TestResult()
        config["relax"] = True # for verify_packets to ignore other packets received at the interface
        
        test_params = test_params_get()
        config_json = test_params['config_json']
        self.dataplane = ptf.dataplane_instance
        ptf.dataplane_instance = ptf.dataplane.DataPlane(config)

        self.capture_port = test_params['pci_bdf'][:-1] + "1"
        self.config_data = get_config_dict(config_json, test_params['pci_bdf'])
        self.gnmicli_params = get_gnmi_params_simple(self.config_data)
        self.interface_ip_list = get_interface_ipv4_dict(self.config_data)

    def runTest(self):
        if not test_utils.gen_dep_files_p4c_ovs_pipeline_builder(self.config_data):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to generate P4C artifacts or pb.bin")

        if not gnmi_cli_set_and_verify(self.gnmicli_params):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to configure gnmi cli ports")

        ip_set_ipv4(self.interface_ip_list)
       
        # get port list and add to dataplane
        port_list = self.config_data['port_list']
        port_list[0] = test_utils.get_port_name_from_pci_bdf(self.capture_port)
        port_ids = test_utils.add_port_to_dataplane(port_list)
     
        for port_id, ifname in config["port_map"].items():
            device, port = port_id
            self.dataplane.port_add(ifname, device, port)

        if not ovs_p4ctl.ovs_p4ctl_set_pipe(self.config_data['switch'], self.config_data['pb_bin'], self.config_data['p4_info']):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to set pipe")

        for table in self.config_data['table']:
            print(f"Scenario : wcm link port : {table['description']}")
            print(f"Adding {table['description']} rules")
            ##for match_action in table['match_action']:
            # The last match action is not addedd here and skip it for next time 
            for match_action in table['match_action'][:-1]:
                if not ovs_p4ctl.ovs_p4ctl_add_entry(table['switch'],table['name'], match_action):
                    self.result.addFailure(self, sys.exc_info())
                    self.fail(f"Failed to add table entry {match_action}")
        
        ###########################
        #  Unicast Counter Case
        ###########################
        num = self.config_data['traffic']['in_pkt_header']['number_pkts'][3]
        pktlen = self.config_data['traffic']['in_pkt_header']['payload_size'][1]
        total_octets_send = pktlen*num
        print (f"Test {num} Unitcast packet from link to TAP")
        print (f"Record in-octets and in-unicast-pkts counter of PORT0 before sending traffic")
        lnk_cont_1 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_cont_1:
            lnk_in_octs_1, lnk_in_uni_pkts_1 = lnk_cont_1['in-octets'], lnk_cont_1['in-unicast-pkts'] 
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")
        print("Recording out-octets and out-unicast-pkts of counter of TAP1 before sending traffic")
        tap_cont_1 = gnmi_get_params_counter(self.gnmicli_params[2]) 
        if tap_cont_1 :
            tap_out_octs_1, tap_out_uni_pkts_1 = tap_cont_1['out-octets'], tap_cont_1['out-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP1")
    
        pkt = simple_tcp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][0], pktlen=pktlen)
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][0]], pkt, count=num)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][2]][1]])
            print(f"PASS: Verification of {num} packets passed per rule 2")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")
        
        print (f"Record in-octets and in-unicast-pkts counter of Link Port PORT0 after sending traffic")
        lnk_cont_2 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_cont_2:
            lnk_in_octs_2, lnk_in_uni_pkts_2 = lnk_cont_2['in-octets'], lnk_cont_2['in-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")
       
        print(f"Recording out-octets and out-unicast-pkts of counter of TAP1 after sending traffic ")
        tap_cont_2 = gnmi_get_params_counter(self.gnmicli_params[2])
        if tap_cont_2:
            tap_out_octs_2, tap_out_uni_pkts_2 = tap_cont_2['out-octets'], tap_cont_2['out-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP1")

        #Idealy we expect counter update is equal to expected num but sometimes the port
        #also receive other unpredicatable brackgroud traffic noise such IPv6 which cause more count.
        #Thus we have to implement the counter update must be equal or larger then num
        #This note apply to all other counter verification
        lnk_pks_update = lnk_in_uni_pkts_2 - lnk_in_uni_pkts_1
        lnk_octs_update = lnk_in_octs_2 - lnk_in_octs_1
        if  lnk_pks_update >= num:
            print(f"PASS: {num} packets expected and {lnk_pks_update} verified on PORT0 in-unicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {lnk_pks_update} verified on PORT0 in-unicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())
        
        if lnk_octs_update >= total_octets_send:
            print(f"PASS: {total_octets_send} octets expected and {lnk_octs_update} verified on PORT0 in-octets counter")
        else:
            print(f"FAIL: {total_octets_send} octets expected but {lnk_octs_update} verified on PORT0 in-octets counter")
            self.result.addFailure(self, sys.exc_info())

        tap_pkt_update = tap_out_uni_pkts_2 - tap_out_uni_pkts_1
        tap_oct_upate = tap_out_octs_2 - tap_out_octs_1
        if tap_pkt_update >= num:
            print(f"PASS: {num} packets expected and {tap_pkt_update} verified on TAP1 out-unicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {tap_pkt_update} verified on TAP1 out-unicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        if tap_oct_upate >= total_octets_send:
            print(f"PASS: {total_octets_send} octets expected and {tap_oct_upate} verified on TAP1 out-octets counter")
        else:
            print(f"FAIL: {total_octets_send} octets expected but {tap_oct_upate} verified on TAP1 out-octets counter")
            self.result.addFailure(self, sys.exc_info())

        ##another direction
        num = self.config_data['traffic']['in_pkt_header']['number_pkts'][2]
        pktlen = self.config_data['traffic']['in_pkt_header']['payload_size'][0]
        total_octets_send = pktlen*num  
        print (f"Test {num} Unitcast packet from TAP to Link")
        print (f"Record in-octets and in-unicast-pkts counter of TAP0 before sending traffic")
        tap_cont_1 = gnmi_get_params_counter(self.gnmicli_params[1])
        if tap_cont_1:
            tap_in_octs_1, tap_in_uni_pkts_1 = tap_cont_1['in-octets'],tap_cont_1['in-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP0")
     
        print("Recording out-octets and out-unicast-pkts of counter of PORT0 before sending traffic")
        lnk_cont_1 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_cont_1:
            lnk_out_octs_1,lnk_out_uni_pkts_1 = tap_cont_1['out-octets'],tap_cont_1['out-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")
       
        pkt = simple_tcp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][1], pktlen=pktlen)
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][1]], pkt, count=num)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][0]][1]])
            print(f"PASS: Verification of {num} packets passed per rule 4")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")

        print (f"Record in-octets and in-unicast-pkts counter of TAP0 after sending traffic")
        tap_cont_2 = gnmi_get_params_counter(self.gnmicli_params[1])
        if tap_cont_2:
            tap_in_octs_2,tap_in_uni_pkts_2 = tap_cont_2['in-octets'],tap_cont_2['in-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP0")
        
        print(f"Recording out-octets and out-unicast-pkts of counter of Link port PROT0 after sending traffic")
        lnk_cont_2 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_cont_2:
            lnk_out_octs_2,lnk_out_uni_pkts_2 = lnk_cont_2['out-octets'], lnk_cont_2['out-unicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        lnk_pks_update = lnk_out_uni_pkts_2 - lnk_out_uni_pkts_1
        lnk_octs_update = lnk_out_octs_2 - lnk_out_octs_1
        if lnk_pks_update >= num:
            print(f"PASS: {num} packets expected and {lnk_pks_update} verified on PORT0 out-unicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {lnk_pks_update} verified on PORT0 out-unicast-pkts counter")

        if lnk_octs_update >= total_octets_send:
            print(f"PASS: {total_octets_send} octets expected and {lnk_octs_update} verified on PORT0 out-octets counter")
        else:
            print(f"FAIL: {total_octets_send} octets expected but {lnk_octs_update} verified on PORT0 out-octets counter")
         
        tap_pkt_update=tap_in_uni_pkts_2 - tap_in_uni_pkts_1
        tap_oct_update=tap_in_octs_2 - tap_in_octs_1
        if tap_pkt_update >= num:
            print(f"PASS: {num} packets expected and {tap_pkt_update} verified on TAP0 in-unicast-pkts counter")
        else:
            print(f"FAIL: {num} octets expected but {tap_pkt_update} verified on TAP0 in-unicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())
        
        if  tap_oct_upate>= total_octets_send:
            print(f"PASS:{total_octets_send} octets expected and {tap_oct_update} verified on TAP0 in-octets counter")
        else:
            print(f"FAIL:{total_octets_send} octets expected but {tap_oct_update} verified on TAP0 in-octets counter")
            self.result.addFailure(self, sys.exc_info())

        ###########################
        #  Multicast Counter Case
        ###########################
        num = self.config_data['traffic']['in_pkt_header']['number_pkts'][0]
        print(f"Sending {num} MultiCast packet from Link to TAP")
        print (f"Record in-multicast-pkts of PORT0  before sending traffic")
        lnk_in_1 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_in_1:  
            lnk_in_mul_pkts_1 = lnk_in_1['in-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record out-multicast-pkts of TAP0 before sending traffic")
        tap_out_1 = gnmi_get_params_counter(self.gnmicli_params[1])
        if tap_out_1:
            tap_out_mul_pkts_1 = tap_out_1['out-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP0")

        pkt = simple_udp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][2],ip_src=self.config_data['traffic']['in_pkt_header']["ip_src"][0])
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][0]], pkt, count=num)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][1]][1]])
            print(f"PASS: Verification of packets passed per rule 1")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")  
        
        print (f"Record in-multicast-pkts of PORT0 after sending traffic")   
        lnk_in_2 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_in_2:
             lnk_in_mul_pkts_2 = lnk_in_2['in-multicast-pkts'] 
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record out-multicast-pkts of TAP0 after sending traffic")
        tap_out_2 = gnmi_get_params_counter(self.gnmicli_params[1])
        if tap_out_2:
             tap_out_mul_pkts_2 = tap_out_2['out-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP0")
        
        lnk_in_mul_update = lnk_in_mul_pkts_2 - lnk_in_mul_pkts_1
        if lnk_in_mul_update >= num:
            print(f"PASS: {num} packets expected and {lnk_in_mul_update} verified on PORT0 in-multicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {lnk_in_mul_update} verified on PORT0 in-multicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        tap_out_mul_update = tap_out_mul_pkts_2 - tap_out_mul_pkts_1
        if tap_out_mul_update >= num:
            print(f"PASS: {num} packets expected and {tap_out_mul_update} verified on TAP0 out-multicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but { tap_out_mul_update} verified on TAP0 out-multicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())
        
        num = self.config_data['traffic']['in_pkt_header']['number_pkts'][1]
        print(f"Sending {num} MultiCast packet from TAP to Link")

        print (f"Record out-multicast-pkts of PORT0 before sending traffic")
        lnk_out_1 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_out_1:
            lnk_out_mul_pkts_1 = lnk_out_1['out-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record in-multicast-pkts of TAP0 before sending traffic")
        tap_in_1 = gnmi_get_params_counter(self.gnmicli_params[1])
        if tap_in_1:
            tap_in_mul_pkts_1 = tap_in_1['in-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP0")

        pkt = simple_udp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][4],ip_src=self.config_data['traffic']['in_pkt_header']["ip_src"][0])
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][1]], pkt, count=num)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][0]][1]])
            print(f"PASS: Verification of packets passed per rule 5")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")  
        
        print (f"Record out-multicast-pkts of PORT0 after sending traffic")   
        lnk_out_2 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_out_2:
            lnk_out_mul_pkts_2 = lnk_out_2['out-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record in-multicast-pktsof TAP0 after sending traffic")
        tap_in_2 = gnmi_get_params_counter(self.gnmicli_params[1])
        if tap_in_2:
            tap_in_mul_pkts_2 = tap_in_2['in-multicast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP0")
        
        lnk_out_mul_update =  lnk_out_mul_pkts_2 -  lnk_out_mul_pkts_1
        if  lnk_out_mul_update >= num:
            print(f"PASS: {num} packets expected and {lnk_out_mul_update } verified on PORT0 out-multicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {lnk_out_mul_update} verified on PORT0 out-multicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        tap_in_mul_update = tap_in_mul_pkts_2 - tap_in_mul_pkts_1
        if tap_in_mul_update >= num:
            print(f"PASS: {num} packets expected and {tap_in_mul_update} verified on TAP0 in-multicast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {tap_in_mul_update} verified on TAP0 in-multicast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        ###########################
        #  BroadCast Counter Case
        ########################### 
        num = self.config_data['traffic']['in_pkt_header']['number_pkts'][1]
        print(f"Sending {num} broadcast packet from Link to TAP")
        print (f"Record in-broadcast-pkts of PORT0  before sending traffic")
        lnk_in_1 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_in_1:
            lnk_in_brd_pkts_1 = lnk_in_1['in-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record out-broadcast-pkts of TAP2 before sending traffic")
        tap_out_1 = gnmi_get_params_counter(self.gnmicli_params[3])
        if tap_out_1:
             tap_out_brd_pkts_1 = tap_out_1['out-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP2")

        pkt = simple_udp_packet( eth_dst="FF:FF:FF:FF:FF:FF",ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][3],ip_src=self.config_data['traffic']['in_pkt_header']["ip_src"][0])
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][0]], pkt, count=num)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][3]][1]])
            print(f"PASS: Verification of packets passed per rule 3")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")  
        
        print (f"Record in-broadcast-pkts of PORT0 after sending traffic")   
        lnk_in_2 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_in_2:
            lnk_in_brd_pkts_2 = lnk_in_2['in-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record out-broadcast-pkts of TAP2 after sending traffic")
        tap_out_2 = gnmi_get_params_counter(self.gnmicli_params[3])
        if tap_out_2:
             tap_out_brd_pkts_2 = tap_out_2['out-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP2")
        
        lnk_in_update = lnk_in_brd_pkts_2 - lnk_in_brd_pkts_1
        if lnk_in_update >= num:
            print(f"PASS: {num} packets expected and {lnk_in_update} verified on PORT0 in-broadcast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {lnk_in_update} verified on PORT0 in-broadcast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        tap_out_update = tap_out_brd_pkts_2 - tap_out_brd_pkts_1
        if tap_out_update >= num:
            print(f"PASS: {num} packets expected and {tap_out_update} verified on TAP2 out-broadcast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {tap_out_update} verified on TAP2 out-broadcast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        print(f"Sending {num} broadcast packet from TAP to Link")
        print (f"delete existing boradcast match action from current direction")
        del_action = self.config_data['table'][0]['del_action'][2]
        ovs_p4ctl.ovs_p4ctl_del_entry(table['switch'], table['name'], del_action)
        #As this action is no longer exist, below is to remove it from del_action list
        self.config_data['table'][0]['del_action'].pop(2)

        print (f"Add boradcast match action for another direction")
        match_action = table['match_action'][-1]
        if not ovs_p4ctl.ovs_p4ctl_add_entry(table['switch'],table['name'], match_action):
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"Failed to add table entry {match_action}")

        print (f"Record out-broadcast-pkts of PORT0 before sending traffic")
        lnk_out_1 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_out_1:
            lnk_out_brd_pkts_1 = lnk_out_1['out-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of PORT0")

        print (f"Record in-broadcast-pkts of TAP1 before sending traffic")
        tap_in_1 = gnmi_get_params_counter(self.gnmicli_params[3])
        if tap_in_1:
            tap_in_brd_pkts_1 = tap_in_1['in-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP2")

        pkt = simple_udp_packet( eth_dst="FF:FF:FF:FF:FF:FF",ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][3])
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][3]], pkt, count=num)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][0]][1]])
            print(f"PASS: Verification of packets passed per rule 6")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")  
        
        print (f"Record out-broadcast-pkts of PORT0 after sending traffic")   
        lnk_out_2 = gnmi_get_params_counter(self.gnmicli_params[0])
        if lnk_out_2:
            lnk_out_brd_pkts_2 = lnk_out_2['out-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP2 ")

        print (f"Record in-broadcast-pkts of TAP2 after sending traffic")
        tap_in_2 = gnmi_get_params_counter(self.gnmicli_params[3])
        if tap_in_2:
            tap_in_brd_pkts_2 = tap_in_2['in-broadcast-pkts']
        else:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: unable to get counetr of TAP1")
        
        link_out_update = lnk_out_brd_pkts_2 - lnk_out_brd_pkts_1
        if link_out_update >= num:
            print(f"PASS: {num} packets expected and {link_out_update} verified on PORT0 out-broadcast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {link_out_update} verified on PORT0 out-broadcast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        tap_in_update = tap_in_brd_pkts_2 - tap_in_brd_pkts_1
        if tap_in_update >= num:
            print(f"PASS: {num} packets expected and {tap_out_update} verified on TAP2 in-broadcast-pkts counter")
        else:
            print(f"FAIL: {num} packets expected but {tap_out_update} verified on TAP2 in-broadcast-pkts counter")
            self.result.addFailure(self, sys.exc_info())

        self.dataplane.kill()

    def tearDown(self):
        for table in self.config_data['table']:
            print(f"Deleting {table['description']} rules")
            for del_action in table['del_action']:
                ovs_p4ctl.ovs_p4ctl_del_entry(table['switch'], table['name'], del_action)
 
        if self.result.wasSuccessful():
            print("Test has PASSED")
        else:
            print("Test has FAILED")
