"""
DPDK L3 Verify traffic with Action Profile
"""

# in-built module imports
import time

# ptf related imports
import ptf
import ptf.dataplane as dataplane
from ptf.base_tests import BaseTest
from ptf.testutils import *
from ptf import config

# scapy related imports
from scapy.packet import *
from scapy.fields import *
from scapy.all import *

# framework related imports
import common.utils.ovsp4ctl_utils as ovs_p4ctl
import common.utils.test_utils as test_utils
from common.utils.config_file_utils import get_config_dict, get_params_tap_port_simple, get_interface_ipv4_dict
from common.utils.gnmi_cli_utils import gnmi_cli_set_and_verify, gnmi_set_params, ip_set_ipv4

class L3_Verify_Traffic_with_Action_Profile(BaseTest):

    def setUp(self):
        BaseTest.setUp(self)
        config["relax"] = True # for verify_packets to ignore other packets received at the interface
        
        test_params = test_params_get()
        config_json = test_params['config_json']
        self.dataplane = ptf.dataplane_instance
        ptf.dataplane_instance = ptf.dataplane.DataPlane(config)

        self.config_data = get_config_dict(config_json)

        if not test_utils.gen_dep_files_p4c_ovs_pipeline_builder(self.config_data):
            self.fail("Failed to generate P4C artifacts or pb.bin")

        self.gnmicli_params = get_params_tap_port_simple(self.config_data)
        self.interface_ip_list = get_interface_ipv4_dict(self.config_data)

        self.PASSED = True
        

    def runTest(self):
        gnmi_set_params(self.gnmicli_params)
        ip_set_ipv4(self.interface_ip_list)

        port_list = self.config_data['port_list']
        port_ids = test_utils.add_port_to_dataplane(port_list)

        for port_id, ifname in config["port_map"].items():
            device, port = port_id
            self.dataplane.port_add(ifname, device, port)

        ovs_p4ctl.ovs_p4ctl_set_pipe(self.config_data['switch'], self.config_data['pb_bin'], self.config_data['p4_info'])
        
        function_dict = {
                'table_for_configure_member' : ovs_p4ctl.ovs_p4ctl_add_member_and_verify,
                'table_for_ipv4' : ovs_p4ctl.ovs_p4ctl_add_entry
                }
        table_entry_dict = {
                'table_for_configure_member' : 'member_details',
                'table_for_ipv4' : 'match_action'
                }

        for table in self.config_data['table']:
            print(f"Scenario : l3 verify traffic with action profile : {table['description']}")
            print(f"Adding {table['description']} rules")
            for match_action in table[table_entry_dict[table['description']]]:
                function_dict[table['description']](table['switch'],table['name'], match_action)

        # forming UDP packet
        print(f"Sending UDP packet from {port_ids[0]} to {self.config_data['traffic']['in_pkt_header']['ip_dst_1']}")
        pkt = simple_udp_packet(ip_dst = self.config_data['traffic']['in_pkt_header']['ip_dst_1'])
        send_packet(self, port_ids[0], pkt)

        # Verify pkt recvd
        print(f"Verifying UDP packet received on {port_ids[1]}")
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[1][1]])
            print(f"PASS: Verification of UDP packets passed, packet received as per rule 1")
        except Exception as err:
            print(f"FAIL: Verification of UDP packets sent failed with exception {err}")
            self.PASSED = False

        # forming TCP packet
        print(f"Sending TCP packet from {port_ids[0]} to {self.config_data['traffic']['in_pkt_header']['ip_dst_1']}")
        pkt = simple_tcp_packet(ip_dst = self.config_data['traffic']['in_pkt_header']['ip_dst_1'])
        send_packet(self, port_ids[0], pkt)

        # Verify pkt recvd
        print(f"Verifying TCP packet received on {port_ids[1]}")
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[1][1]])
            print(f"PASS: Verification of TCP packets passed, packet received as per rule 1")
        except Exception as err:
            print(f"FAIL: Verification of TCP packets sent failed with exception {err}")
            self.PASSED = False

        # forming UDP Multicast packet
        print(f"Sending UDP Multicast packet from {port_ids[0]} to {self.config_data['traffic']['in_pkt_header']['ip_dst_2']}")
        pkt = simple_udp_packet(ip_dst = self.config_data['traffic']['in_pkt_header']['ip_dst_2'])
        send_packet(self, port_ids[0], pkt)

        # Verify pkt recvd
        print(f"Verifying UDP Multicast packet received on {port_ids[2]}")
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[2][1]])
            print(f"PASS: Verification of UDP Multicast packets passed, packet received as per rule 2")
        except Exception as err:
            print(f"FAIL: Verification of UDP Multicast sent failed with exception {err}")
            self.PASSED = False


        # forming UDP Broadcast packet
        print(f"Sending UDP Broadcast packet from {port_ids[0]} to {self.config_data['traffic']['in_pkt_header']['ip_dst_3']}")
        pkt = simple_udp_packet(ip_dst = self.config_data['traffic']['in_pkt_header']['ip_dst_3'])
        send_packet(self, port_ids[0], pkt)

        # Verify pkt recvd
        print(f"Verifying UDP Broadcast packet received on {port_ids[3]}")
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[3][1]])
            print(f"PASS: Verification of UDP Broadcast packets passed, packet received as per rule 3")
        except Exception as err:
            print(f"FAIL: Verification of UDP Broadcast sent failed with exception {err}")
            self.PASSED = False

        self.dataplane.kill()


    def tearDown(self):
        function_dict = {
                'table_for_configure_member' : ovs_p4ctl.ovs_p4ctl_del_member,
                'table_for_ipv4' : ovs_p4ctl.ovs_p4ctl_del_entry
                }
        table_entry_dict = {
                'table_for_configure_member' : 'del_member',
                'table_for_ipv4' : 'del_action'
                }
        for table in self.config_data['table']:
            print(f"Deleting {table['description']} rules")
            for del_action in table[table_entry_dict[table['description']]]:
                function_dict[table['description']](table['switch'], table['name'], del_action)
        
        if self.PASSED:
            print("Test has PASSED")
        else:
            print("Test has FAILED")

 

