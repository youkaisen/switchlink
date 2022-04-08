"""

DPDK Action Selector Traffic Test with TAP Port
TC1 : 2 members with action send (to 2 different ports) associated to 1 group with match field dst IP
TC2 : 5 members with action send (to 5 different ports) associated to 3 groups with match field dst IP 

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
from common.utils.config_file_utils import get_config_dict, get_gnmi_params_simple, get_interface_ipv4_dict
from common.utils.gnmi_cli_utils import gnmi_cli_set_and_verify, gnmi_set_params, ip_set_ipv4


class L3_Action_Selector(BaseTest):

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

        self.gnmicli_params = get_gnmi_params_simple(self.config_data)
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
        # set pipe line
        ovs_p4ctl.ovs_p4ctl_set_pipe(self.config_data['switch'], self.config_data['pb_bin'], self.config_data['p4_info'])
        
        table = self.config_data['table'][0]
        
        print(f"##########  Scenario : {table['description']} ##########")

        print("Add action profile members")
        for member in table['member_details']:
            ovs_p4ctl.ovs_p4ctl_add_member_and_verify(table['switch'],table['name'],member)

        print("Adding action selector groups")
        group_count = 0
        for group in table['group_details']:
            ovs_p4ctl.ovs_p4ctl_add_group_and_verify(table['switch'],table['name'],group)
            group_count+=1
        
        print(f"Setting up rule for : {table['description']}")
        table = self.config_data['table'][1]
        for match_action in table['match_action']:
            ovs_p4ctl.ovs_p4ctl_add_entry(table['switch'],table['name'], match_action)

        # verify whether traffic hits group-1
        for src in self.config_data['traffic']['in_pkt_header']['ip_src']:
            print("sending packet to check if it hit group 1")
            pkt = simple_tcp_packet(ip_src=src, ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][0])
            
            send_packet(self, port_ids[self.config_data['traffic']['send_port'][0]], pkt)
            try:
                verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][0]][1]])
                print(f"PASS: Verification of packets passed, packets received as per group 1: member 1")
            except Exception as err:
                print(f"FAIL: Verification of packets sent failed with exception {err}")
                self.PASSED = False
        
 
        # verify whether traffic hits group-2
        iteration = 1 
        for src in self.config_data['traffic']['in_pkt_header']['ip_src']:
            print("sending packet to check if it hit group 2")
            pkt = simple_tcp_packet(ip_src=src, ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][1])
            send_packet(self, port_ids[self.config_data['traffic']['send_port'][1]], pkt)
            if iteration == 1:
                try:
                    verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][1]][1]])
                    print(f"PASS: Verification of packets passed, packets received as per group 2 : member 2")
                except Exception as err:
                    print(f"FAIL: Verification of packets sent failed with exception {err}")
                    self.PASSED = False
            elif iteration  == 2 :
                try:
                    verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][2]][1]])
                    print(f"PASS: Verification of packets passed, packets received as per group 2 : member 3")
                except Exception as err:
                    print(f"FAIL: Verification of packets sent failed with exception {err}")
            else:
                print("FAIL: wrong number of ip_src list provided")
                self.PASSED = False

            iteration+=1

        # verify whether traffic hits group-3
        if group_count == 3:
            iteration = 1
            for src in self.config_data['traffic']['in_pkt_header']['ip_src']:
                print("sending packet to check if it hit group 3")
                pkt = simple_tcp_packet(ip_src=src, ip_dst=self.config_data['traffic']['in_pkt_header']['ip_dst'][2])
                send_packet(self, port_ids[self.config_data['traffic']['send_port'][1]], pkt)
                if iteration == 1:
                    try:
                        verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][3]][1]])
                        print(f"PASS: Verification of packets passed, packets received as per group 3 : member 4")
                    except Exception as err:
                        print(f"FAIL: Verification of packets sent failed with exception {err}")
                        self.PASSED = False
                elif iteration  == 2 :
                    try:
                        verify_packets(self, pkt, device_number=0, ports=[port_ids[self.config_data['traffic']['receive_port'][4]][1]])
                        print(f"PASS: Verification of packets passed, packets received as per group 3 : member 5")
                    except Exception as err:
                        print(f"FAIL: Verification of packets sent failed with exception {err}")
                        self.PASSED = False
                else:
                    print("FAIL: wrong number of ip_src list provided")
                    self.PASSED = False

                iteration+=1
      
            

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

 
