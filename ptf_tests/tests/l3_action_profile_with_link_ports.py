"""

DPDK Action Selector Traffic Test with TAP Port
TC1 : 2 members with action send (to 2 different ports) associated to 1 group with match field dst IP

"""

# in-built module imports
import time
import sys

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
from common.lib.telnet_connection import connectionManager
import common.utils.ovsp4ctl_utils as ovs_p4ctl
import common.utils.test_utils as test_utils
from common.utils.config_file_utils import get_config_dict, get_gnmi_params_simple, get_interface_ipv4_dict
from common.utils.gnmi_cli_utils import gnmi_cli_set_and_verify, gnmi_set_params, ip_set_ipv4


class L3_Action_Profile_Link(BaseTest):

    def setUp(self):
        BaseTest.setUp(self)
        config["relax"] = True # for verify_packets to ignore other packets received at the interface
        
        test_params = test_params_get()
        config_json = test_params['config_json']
        self.dataplane = ptf.dataplane_instance
        ptf.dataplane_instance = ptf.dataplane.DataPlane(config)

        iface = test_params['iface']
        pci_bdf = test_params['pci_bdf']
        self.config_data = get_config_dict(config_json, pci_bdf=pci_bdf,iface=iface )

        if not test_utils.gen_dep_files_p4c_ovs_pipeline_builder(self.config_data):
            self.fail("Failed to generate P4C artifacts or pb.bin")

        self.gnmicli_params = get_gnmi_params_simple(self.config_data)
        self.interface_ip_list = get_interface_ipv4_dict(self.config_data)

        self.PASSED = True

    def runTest(self):
        if not test_utils.gen_dep_files_p4c_ovs_pipeline_builder(self.config_data):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to generate P4C artifacts or pb.bin")

        if not gnmi_cli_set_and_verify(self.gnmicli_params):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to configure gnmi cli ports")

        ip_set_ipv4(self.interface_ip_list)

        port_list = self.config_data['port_list']
        port_ids = test_utils.add_port_to_dataplane(port_list)


        for port_id, ifname in config["port_map"].items():
            device, port = port_id
            self.dataplane.port_add(ifname, device, port)

        # set pipe line
        if not ovs_p4ctl.ovs_p4ctl_set_pipe(self.config_data['switch'], self.config_data['pb_bin'], self.config_data['p4_info']):

            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to set pipe")
        

        print(f"Table 0 settings")
        table = self.config_data['table'][0]

        print(f"##########  Scenario : {table['description']} ##########")

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


        # Verify whether packet is dropped as per rule 1
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][1]], pkt)
        try:
            verify_no_packet_any(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][0]][1]])
            print(f"PASS: Verification of packets passed, packet dropped as per rule 1")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")
        
 
        # verify whether traffic hits group-2
        pkt = simple_tcp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][1])
        # Verify whether packet is dropped as per rule 1
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][1]], pkt)
        try:
            verify_no_packet_any(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][0]][1]])
            print(f"PASS: Verification of packets passed, packet dropped as per rule 1")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")

        
        print ("sending packet from Link port to TAP")

        print("sending packet to check if rule3 drop")
        pkt = simple_tcp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][2])
        # Verify whether packet is dropped as per rule 3
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][0]], pkt)
        try:
            verify_no_packet_any(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][1]][1]])
            print(f"PASS: Verification of packets passed, packet dropped as per rule 3")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")
        
        pkt = simple_tcp_packet(ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][2])
        # Verify whether packet is received as per rule 4
        send_packet(self, port_ids[self.config_data['traffic']['send_port'][0]], pkt)
        try:
            verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][2]][1]])
            print(f"PASS: Verification of packets passed, packet received as per rule 4")
        except Exception as err:
            self.result.addFailure(self, sys.exc_info())
            self.fail(f"FAIL: Verification of packets sent failed with exception {err}")
        
        self.dataplane.kill()


    def tearDown(self):

        table = self.config_data['table'][1]
        
        print(f"Deleting rules")
        for del_action in table['del_action']:
            ovs_p4ctl.ovs_p4ctl_del_entry(table['switch'], table['name'], del_action)
       
        table = self.config_data['table'][0]
        print("Deleting groups")
        for del_group in table['del_group']:
            ovs_p4ctl.ovs_p4ctl_del_group(table['switch'],table['name'],del_group)
                 
        print("Deleting members")    
        for del_member in table['del_member']:
            ovs_p4ctl.ovs_p4ctl_del_member(table['switch'],table['name'],del_member)

        if self.PASSED:
            print("Test has PASSED")
        else:
            print("Test has FAILED")

 
