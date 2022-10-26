# Copyright (c) 2022 Intel Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Generic utility scripts for P4OVS PTF scripts.
"""

from ptf import *
from ptf.testutils import *
import common.lib.local_connection as local_connection

import json
import os
import subprocess
import re
import pexpect
import time

from common.lib.local_connection import Local
from common.lib.telnet_connection import connectionManager
from common.lib.ovs import Ovs
from common.utils.ovs_utils import get_connection_object
import common.utils.gnmi_cli_utils as gnmi_cli_utis
from common.lib.ssh import Ssh


def add_port_to_dataplane(port_list):
    """
    To add device ports to dataplane database for ptf usage
    """
    local = Local()
    r,_,_ = local.execute_command("ip -j link show")
    result = json.loads(r)
    for name in port_list:
        for iface in result:
            if (iface["ifname"] == name):
                config["port_map"].update({(0,iface["ifindex"]):name})
                continue
    
    return ptf_ports() 

def get_port_name_from_pci_bdf(pci_bdf):
    """
    To return port name from pci_bdf
    """
    local = Local()
    r,_,_ = local.execute_command(f"ls -la /sys/class/net/ |grep -i {pci_bdf}")
    port_name = r.split()[8]
    
    return port_name


def gen_dep_files_p4c_ovs_pipeline_builder(config_data):
    """
    util function to generate p4 artifacts
    :params: config_data --> dict --> dictionary with all config data loaded from json
    :returns: Boolean True/False
    """
    local = Local()
    
    p4file = config_data['p4file']
    conf_file = p4file + ".conf"
    output_dir = os.sep.join(["common", "p4c_artifacts", p4file])
    pb_bin_file = config_data['p4file']+'.pb.bin'
    config_data['pb_bin'] = output_dir + "/" + pb_bin_file
    config_data['p4_info'] = output_dir + "/p4Info.txt"
    p4file = p4file + ".p4"
    cmd = f'''p4c --arch psa --target dpdk --output {output_dir}/pipe --p4runtime-files \
            {output_dir}/p4Info.txt --bf-rt-schema {output_dir}/bf-rt.json --context \
            {output_dir}/pipe/context.json {output_dir}/{p4file}'''

    out, returncode, err = local.execute_command(cmd)
    if returncode:
        print(f"Failed to run p4c: {out} {err}")
        return False

    print(f"PASS: {cmd}")

    cmd = f'''cd {output_dir}; ovs_pipeline_builder --p4c_conf_file={conf_file} \
            --bf_pipeline_config_binary_file={pb_bin_file}'''

    out, returncode, err = local.execute_command(cmd)
    if returncode:
        print(f"Failed to run ovs_pipeline_builder: {out} {err}")
        return False

    cmd = f'''ovs_pipeline_builder --p4c_conf_file={conf_file} \
            --bf_pipeline_config_binary_file={pb_bin_file}'''

    print(f"PASS: {cmd}")

    return True

def gen_dep_files_p4c_dpdk_pna_ovs_pipeline_builder(config_data):
    """
    util function to generate p4 artifacts for dpdk pna architecture
    :params: config_data --> dict --> dictionary with all config data loaded from json
    :returns: Boolean True/False
    """
    local = Local()

    p4file = config_data['p4file']
    conf_file = p4file + ".conf"
    output_dir = os.sep.join(["common", "p4c_artifacts", p4file])
    pb_bin_file = config_data['p4file']+'.pb.bin'
    config_data['pb_bin'] = output_dir + "/" + pb_bin_file
    config_data['p4_info'] = output_dir + "/p4Info.txt"
    spec_file = p4file + ".spec"
    p4file = p4file + ".p4"
    cmd = f'''p4c-dpdk -I p4include -I p4include/dpdk --p4v=16 --p4runtime-files \
            {output_dir}/p4Info.txt -o {output_dir}/pipe/{spec_file} --arch pna --bf-rt-schema {output_dir}/bf-rt.json --context \
            {output_dir}/pipe/context.json {output_dir}/{p4file}'''
    print (cmd)
    out, returncode, err = local.execute_command(cmd)
    if returncode:
        print(f"Failed to run p4c: {out} {err}")
        return False

    print(f"PASS: {cmd}")
    
    cmd = f'''cd {output_dir}; ovs_pipeline_builder --p4c_conf_file={conf_file} \
            --bf_pipeline_config_binary_file={pb_bin_file}'''

    out, returncode, err = local.execute_command(cmd)
    if returncode:
        print(f"Failed to run ovs_pipeline_builder: {out} {err}")
        return False

    cmd = f'''ovs_pipeline_builder --p4c_conf_file={conf_file} \
            --bf_pipeline_config_binary_file={pb_bin_file}'''

    print(f"PASS: {cmd}")

    return True

def gen_dep_files_p4c_dpdk_pna_ovs_pipeline_builder_ct_timer(config_data):
    """
    util function to generate p4 artifacts for dpdk pna architecture
    :params: config_data --> dict --> dictionary with all config data loaded from json
    :needs to update spec file for time usage
    :returns: Boolean True/False
    """
    local = Local()
    p4file = config_data['p4file']
    conf_file = p4file + ".conf"
    output_dir = os.sep.join(["common", "p4c_artifacts", p4file])
    pb_bin_file = config_data['p4file']+'.pb.bin'
    config_data['pb_bin'] = output_dir + "/" + pb_bin_file
    config_data['p4_info'] = output_dir + "/p4Info.txt"
    spec_file = p4file + ".spec"
    p4file = p4file + ".p4"
    cmd = f'''p4c-dpdk -I p4include -I p4include/dpdk --p4v=16 --p4runtime-files \
            {output_dir}/p4Info.txt -o {output_dir}/pipe/{spec_file} --arch pna --bf-rt-schema {output_dir}/bf-rt.json --context \
            {output_dir}/pipe/context.json {output_dir}/{p4file}'''
    print (cmd)
    out, returncode, err = local.execute_command(cmd)
    if returncode:
        print(f"Failed to run p4c: {out} {err}")
        return False

    print(f"PASS: {cmd}")

    with open(f'{output_dir}/pipe/{spec_file}', 'r', encoding='utf-8') as file:
         data = file.readlines()

    data[155] = "\t\t60\n"
    data[157] = "\t\t180\n"

    with open(f'{output_dir}/pipe/{spec_file}', 'w', encoding='utf-8') as file:
         file.writelines(data)

    cmd = f'''cd {output_dir}; ovs_pipeline_builder --p4c_conf_file={conf_file} \
            --bf_pipeline_config_binary_file={pb_bin_file}'''

    out, returncode, err = local.execute_command(cmd)
    if returncode:
        print(f"Failed to run ovs_pipeline_builder: {out} {err}")
        return False

    cmd = f'''ovs_pipeline_builder --p4c_conf_file={conf_file} \
            --bf_pipeline_config_binary_file={pb_bin_file}'''

    print(f"PASS: {cmd}")

    return True

def qemu_version(ver="6.1.0"):
    """
    To Add/Del same Hotplug mutiple times need to check qemu version >= 6.1.0.
    Below 6.1.0  version functionality will fail.
    """
    local = Local()
    cmd = f'''qemu-system-x86_64 --version | head -1 | cut -d" " -f4'''
    print(cmd)

    out, returncode, err = local.execute_command(cmd)
    result = out.strip() >= ver
    if result:
        print(f"PASS: {cmd}")
        return out.strip()

    return False 

def vm_create(vm_location_list, memory="512M"):
    """
    To create VMs. Will stop the execution if anyone of VM creation gets failed.
    Usage eg : result, vm_name = vm_create(vm_location_list)

    """
    num_of_vms = len(vm_location_list)
    vm_list = []
    for i in range(num_of_vms):
        vm_name = f"VM{i}"
        vm_list.append(vm_name)

        cmd = f"(qemu-kvm -smp 2 -m {memory} \
-boot c -cpu host -enable-kvm -nographic \
-L /root/pc-bios -name VM{i} \
-hda {vm_location_list[i]} \
-object memory-backend-file,id=mem,size={memory},mem-path=/dev/hugepages,share=on \
-mem-prealloc \
-numa node,memdev=mem \
-chardev socket,id=char{i},path=/tmp/vhost-user-{i} \
-netdev type=vhost-user,id=netdev{i},chardev=char{i},vhostforce \
-device virtio-net-pci,netdev=netdev{i} \
-serial telnet::655{i},server,nowait &)"

        p  = subprocess.Popen([cmd], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        time.sleep(5)
        try:
            out, err = p.communicate(timeout=5)
            return False, f"VM{i}"

        except Exception as err:
            print(f"VM creation successful : VM{i}")

    return True,vm_list

def configure_vm(conn, command_list):
    """
    To login to VM instance and configure the VMs.
    """
    for cmd in command_list:
        status = conn.sendCmd(cmd)
        if status:
            print(f"Command: {cmd} executed ")
        else:
            print("Failed to execute command {cmd}")


def vm_to_vm_ping_test(conn, dst_ip, count="4"):
    """
    To test if ping to a destination works without any drop
    """
    cmd = f"ping {dst_ip} -c {count}"
    dummy_ping(conn, cmd)
 
    conn.sendCmd(cmd)
    result = conn.readResult()
    pkt_loss = 100
    if result:
        match = re.search('(\d*)% packet loss', result)
        if match:
            pkt_loss = int(match.group(1))
  
    if f"{count} received, 0% packet loss" in result:
        print(f"PASS: Ping successful to destination {dst_ip}")
        return True
    else:
        print(f"FAIL: Ping Failed to destination {dst_ip} with {pkt_loss}% loss")
        return False

def vm_ping_less_than_100_loss(conn, dst_ip, count="4"):
    """
    Sometimes when expecting some ping packet loss, we can use this function
    """
    cmd = f"ping {dst_ip} -c {count}"
    dummy_ping(conn, cmd)

    conn.sendCmd(cmd)
    result = conn.readResult()
    pkt_loss = 100
    if result:
        match = re.search('(\d*)% packet loss', result)
        if match:
            pkt_loss = int(match.group(1))
    
    if pkt_loss < 100:
        if f"{count} received, {pkt_loss}% packet loss" in result:
            print(f"PASS: Ping successful to destination {dst_ip}")
            return True
    else:
        print(f"FAIL: Ping Failed to destination {dst_ip} with {pkt_loss}% loss")
        return False

def dummy_ping(conn, cmd):
    """
    Dummy traffic to ignore traffic drops dueto ARP learning etc
    """
    conn.sendCmd(cmd)
    conn.readResult()

def vm_to_vm_ping_drop_test(conn, dst_ip, count="4"):
    """
    To test if ping to a destination is getting failed.
    i.e, 100% drop expected.
    """
    cmd = f"ping {dst_ip} -c {count}"
    dummy_ping(conn, cmd)

    conn.sendCmd(cmd)
    result = conn.readResult()
    pkt_loss = 100
    if result:
        match = re.search('(\d*)% packet loss', result)
        if match:
            pkt_loss = int(match.group(1))

    if pkt_loss == 100:
        print(f"PASS: 100% packet loss to destination {dst_ip}")
        return True
    else:
        print(f"FAIL: Ping to destination {dst_ip} works with {pkt_loss}% loss")
        return False


def vm_port_flapping(conn, config_data, result):
    """ Read live data from telnet connection
    :param conn: VM1 telnet instance
    :type conn: 'obj' type
    :param config_data: input configuration dictionary
    :type config_data: dict
    :param result: instance of unittest.TestResult() for test result logging
    :type result: 'obj' type
    :return: True or False
    :rtype: boolean
    """
    ping_cmd = f"ping -w 30 {config_data['vm'][0]['remote_ip']}"
    print(ping_cmd)
    res = conn.sendCmd(ping_cmd)
    if res:
        print('Traffic started from VM1 -> VM2')
    else:
        result.addFailure(sys.exc_info())
        print('failed to start ping')
        return False
    try:
        down_cmd = f"ip link set {config_data['port'][1]['interface']} " \
                   f"down"
        up_cmd = f"ip link set {config_data['port'][1]['interface']} up"
        lookup_string1 = f"64 bytes from {config_data['vm'][0]['remote_ip']}"
        while True:
            line = conn.tn.read_until(b"ms", 30).decode('utf-8')
            print(f'{line}')
            if lookup_string1 in line:
                print(f'Traffic is running successfully. '
                      f'Now bring VM2 interface down')
                if not conn.sendCmd(down_cmd):
                    result.addFailure(sys.exc_info())
                    print(f'Failed to bring VM2 interface down')
                lookup_string1 = "None"
                sys.stdout.flush()
                print(f'VM2 interface is down')
            elif down_cmd in line:
                print('No traffic is running, '
                      'bring VM2 interface up')
                if not conn.sendCmd(up_cmd):
                    result.addFailure(sys.exc_info())
                    print(f'Failed to bring VM2 interface up')
                lookup_string1 = f"64 bytes from {config_data['vm'][0]['remote_ip']}"
                down_cmd = "None"
                sys.stdout.flush()
            if lookup_string1 in line:
                print('traffic is resumed as expected, Port flapping is '
                      'successful')
                return True
    except Exception as err:
        print(f"Read CLI output failed with error: {err}")
        return False


def get_port_status(interface_ip_list):
    """Get port status using ethtool utility
    :param interface_ip_list: list of dict; An pair of interface with IP
    :type interface_ip_list: list [{},{}]
    :return: True or False
    :rtype: boolean
    """
    local = local_connection.Local()
    for interface_ipv4_dict in interface_ip_list:
        for interface, ip in interface_ipv4_dict.items():
            cmd = f'ethtool {interface} |grep "Link detected:" |cut -d " ' \
                  f'" -f3 '
            out, _, err = local.execute_command(cmd)
            out = str(out).rstrip('\n')
            if out == "yes":
                print(f'{interface} link detected')
            else:
                print(f'Failed to detect {interface}')
                return False
    return True

def vm_create_with_hotplug(config_data, memory="512M"):
    """
    To create VMs. Will stop the execution if anyone of VM creation gets failed.
    Usage eg : result, vm_name = vm_create(vm_location_list)

    """
    vm_list = []
    for vm in config_data['vm']:
        vm_name = vm['vm_name']
        vm_list.append(vm_name)

        cmd = f"(qemu-system-x86_64 -enable-kvm -smp 4 -m {memory} \
 -boot c -cpu host -enable-kvm -nographic \
 -L /root/pc-bios -name {vm_name} \
 -hda {vm['vm_image_location']} \
 -object memory-backend-file,id=mem,size={memory},mem-path=/dev/hugepages,share=on \
 -mem-prealloc \
 -numa node,memdev=mem \
 -monitor telnet::{vm['hotplug']['qemu-socket-port']},server,nowait \
 -serial telnet::{vm['hotplug']['serial-telnet-port']},server &)"
        
        print(cmd)

        p  = subprocess.Popen([cmd], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        try:
            out, err = p.communicate(timeout=5)
            return False, f"VM{i}"

        except Exception as err:
            print(f"VM creation successful : {vm_name}")

    return True,vm_list

def sendCmd_and_recvResult(conn, command_list):
    """
    Sends Command and returns output
    """
    result=[]
    for cmd in command_list:
        status = conn.sendCmd(cmd)
        if status:
            print(f"Command: {cmd} executed ")
        else:
            print("Failed to execute command {cmd}")
        result.append(conn.readResult())

    return result

def vm_interface_up(conn, interface_ip_list, status="up"):
    command_list=[]
    for interface_ipv4_dict in interface_ip_list:
        for interface, ip in interface_ipv4_dict.items():
            command_list.append(f"ip link set {interface} {status}")
    
    return sendCmd_and_recvResult(conn, command_list)

def vm_interface_configuration(conn, interface_ip_list):
    command_list=[]
    for interface_ipv4_dict in interface_ip_list:
        for interface, ip in interface_ipv4_dict.items():
            command_list.append(f"ip addr add {ip} dev {interface}")

    return sendCmd_and_recvResult(conn, command_list)

def vm_route_configuration(conn, interface, local_ip, remote_ip):
    local_ip = local_ip.split("/")[0] #stripping it of any /24 if any
    remote_ip = remote_ip.split("/")[0]

    cmd = f"ip route add {remote_ip}/24 via {local_ip} dev {interface}"
    return sendCmd_and_recvResult(conn, [cmd])

def vm_ip_neigh_configuration(conn, interface, remote_ip, remote_mac):
    remote_ip = remote_ip.split("/")[0] #stripping it of any /24 if any

    cmd = f"ip neigh add dev {interface} {remote_ip} lladdr {remote_mac}"
    return sendCmd_and_recvResult(conn, [cmd])

def vm_ethtool_offload(conn, interface):
    """
    :Function to offload interface
    :Example: ethtool --offload ens3 rx off tx off
    """
    cmd = f"ethtool --offload {interface} rx off tx off"
    return sendCmd_and_recvResult(conn, [cmd])

def vm_change_mtu(conn, interface, mtu):
    """
    :Function to change interface mtu
    :Example: ip link set ens3 mtu 1450 up
    """
    cmd = f"ip link set {interface} mtu {mtu} up"
    return sendCmd_and_recvResult(conn, [cmd])

def vm_change_port_status(conn, interface, status):
    """
    :Function to change interface status
    :Example: ip link set ens3 up or down
    """
    cmd = f"ip link set {interface} {status}"
    return sendCmd_and_recvResult(conn, [cmd])

def set_telnet_conn_timeout(conn, timeout=10):
    conn.timeout=timeout

def compare_counter(counter2, counter1):
    delta =dict()
    for key in counter2.keys():
        delta[key] = counter2[key] -counter1[key]
    return delta

def ovs_add_ctrl_port_to_bridge(bridge, port_list, p4_device_id):
    """
    ovs-vsctl add-port BRIDGE CONTROL_PORT
    Example:
        ovs-vsctl add-p4-device 1
        ovs-vsctl add-br br1
        ovs-vsctl add-br-p4 br1 1
        ovs-vsctl add-port br1 TAP0
    """
    ovs = Ovs(get_connection_object())
    
    out, returncode, err = ovs.vsctl.add_p4_device(p4_device_id)
    if returncode:
        print(f"Failed to add p4_device {p4_device_id} in bridge {bridge} due to {out} {err}")
        return False
    out, returncode, err = ovs.vsctl.add_br(bridge)
    if returncode:
        print(f"Failed to add bridge {bridge} due to {out} {err}")
        return False
    out, returncode, err = ovs.vsctl.add_br_p4(bridge, 1)
    if returncode:
        print(f"Failed to add bridge {bridge} in p4 device due to {out} {err}")
        return False
    # adding port into ovs bridge
    for port in port_list:
        out, returncode, err = ovs.vsctl.add_port(bridge,port)
        if returncode:
            print(f"Failed to port {port} in bridge {bridge} {out} {err}")
            return False

    return True

def get_ovs_port_dump(bridge, ctrl_port_list):
    """
    ovs-ofctl dump-ports BRIDGE
    Example:
        ovs-ofctl dump-ports br1
    output example
        port LOCAL: rx pkts=22, bytes=1860, drop=0, errs=0, frame=0, over=0, crc=0
                tx pkts=8, bytes=656, drop=0, errs=0, coll=0
        port  1: rx pkts=0, bytes=0, drop=0, errs=0, frame=0, over=0, crc=0
                tx pkts=14, bytes=1204, drop=0, errs=0, coll=0
    """
    counter_dict = dict()
    out, returncode, err = Ovs(get_connection_object()).ofctl.dump_port(bridge)
 
    if not returncode and ("port" in out):
        out = out.split("\n")
        #skip headline, local port rx and local port tx
        out.pop(0); out.pop(0);out.pop(0)
    else:
        print (f"FAIL: unable to ovs-ofctl dump-ports {bridge} due to {err}")
        return False
   
    # Build control port counter dict
    for each in out:
        each = each.strip()
        if each.isspace() or len(each)==0:
            continue
        if "port" in each:
            port_id = int(each.split()[1].replace(":",""))
            rx = each.split()[2]
            ctrl_port_name = ctrl_port_list[port_id-1]
            counter_dict[ctrl_port_name] = dict()
            counter_dict[ctrl_port_name][rx]=dict()
            items=  each.split()[3:]
            #Build remaining counter
            for item in items:
                count_name = item.split("=")[0].strip()
                counter_dict[ctrl_port_name][rx][count_name] = dict()
                counter_dict[ctrl_port_name][rx][count_name] = int(item.split("=")[1].replace(",",""))
        else:
            tx = each.split(", ")[0].split()[0]
            counter_dict[ctrl_port_name][tx] = dict()
            # remmove prefix tx
            items = each.replace("tx", "").split()
            for item in items:
                count_name = item.split("=")[0].strip()
                counter_dict[ctrl_port_name][tx][count_name] = dict()
                counter_dict[ctrl_port_name][tx][count_name] = int(item.split("=")[1].replace(",",""))

    if counter_dict:
        return counter_dict
    else:
        return False

def get_control_port(config_data):
    ctrl_port = []
    for data in config_data['port']:
        if data["control-port"]:
            ctrl_port.append(data["control-port"])
    if ctrl_port:
        return ctrl_port
    else:
        return False

def local_ping(*args):
    local = Local()
    cmd = " ".join(args)
    result,_,_  = local.execute_command(cmd)
  
    pkt_loss = 100
    if result:
        match = re.search('(\d*)% packet loss', result)
        if match:
            pkt_loss = int(match.group(1))

    if pkt_loss == 100:
        return False
    else:
        return True

def check_and_clear_vhost(directory="/tmp/"):
    """
    :Function to check and clear vhost socket file from /tmp (default) directory
    :returns False if socket file is found and could not be deleted, else True
    """
    _, vhost_list = check_vhost_socket_count(directory)
    if vhost_list:
        for file in vhost_list:
                file_path = directory + file
                print(f"Deleting vhost-user socket file " + file_path)
                local = Local()
                _, returncode, _ = local.execute_command(f"rm -f "  + file_path)
                if returncode:
                    print(f"Cannot delete file " + file_path)
                    return False
                else:
                    return True
    else:            
        print(f"No vhost-user socket file found in " + directory)
        return True

def check_vhost_socket_count(directory="/tmp/"):
    """
    :Function to check vhost socket files count from /tmp (default) directory
    :returns length of vhost_list in integer and vhost_list 
    """
    vhost_list = []
    for file in os.listdir(directory):
        if file.startswith("vhost-user"):
            vhost_list.append(file)
    return len(vhost_list), vhost_list  

def create_ipnetns_vm(ns_data, remote=False, hostname="",username="",password=""):
    """
    :Function to create Namesapce, VM and IP
    :returns boolean True or False
    """
    namespace = ns_data['name']
    veth_if = ns_data['veth_if']
    veth_peer =  ns_data['peer_name']
    ip_add_cmd =f"ip addr add {ns_data['ip']} dev {ns_data['veth_if']}"
    ip_link_set_cmd = f"ip link set dev {ns_data['veth_if']} up"

    if not gnmi_cli_utis.ip_netns_add(namespace,remote=remote,hostname=hostname, username=username, password=password):
        print (f"FAILED: Failed to configure namespace {namespace}")
        return False
    elif not gnmi_cli_utis.ip_link_add_veth_and_peer(veth_if,veth_peer, remote=remote,hostname=hostname, username=username, password=password):
        print (f"FAILED: Failed to configure namespace {veth_peer}")
        return False
    elif not gnmi_cli_utis.ip_link_set_veth_to_ns(namespace, veth_if,remote=remote,hostname=hostname, username=username, password=password):
        print (f"FAILED: Failed to configure {veth_if} to namespace {namespace}")
        return False
    elif not gnmi_cli_utis.ip_link_netns_exec(namespace, ip_add_cmd,remote=remote,hostname=hostname, username=username, password=password)[0]:
        print (f"FAILED: Failed to execute cmd {ip_add_cmd} on namespace {namespace}")
        return False
    elif not gnmi_cli_utis.ip_link_netns_exec(namespace, ip_link_set_cmd,remote=remote,hostname=hostname, username=username, password=password)[0]:
        print (f"FAILED: Failed to execute cmd {ip_link_set_cmd} on namespace {namespace}")
        return False
    elif not gnmi_cli_utis.ip_set_dev_up(veth_peer, remote=remote,hostname=hostname, username=username, password=password):
        print (f"FAILED: unable to configure {veth_peer} up")
        return False
    else:
        return True

def del_ipnetns_vm(ns_data, remote=False, hostname="",username="",password=""):
    """
    :Function to delete Namesapce
    :returns boolean True or False
    """
    namespace = ns_data['name']
    if not gnmi_cli_utis.del_ip_netns(namespace,remote=remote,hostname=hostname, username=username, passwd=password):
        print (f"Failed to delete namesapce {namespace} ")
        return False
    print(f"PASS: delete {namespace} on {hostname}")
    
    return True

def ip_ntns_exec_ping_test(nsname, dst_ip, count="4", remote=False, hostname="",username="",password=""):
    """
    :To test if ping to a destination works without any drop
    :E.g. ip netns exec VM1 ping 99.0.0.1
    """
    cmd = f"ping {dst_ip} -c {count}"
    results = gnmi_cli_utis.ip_link_netns_exec(nsname, cmd,remote=remote,hostname=hostname, username=username, password=password)
   
    pkt_loss = 100
    if results[0]:
        match = re.search('(\d*)% packet loss', results[1])
        if match:
            pkt_loss = match.group(1)

    if f"{count} received, 0% packet loss" in results[1]:
        print(f"PASS: Ping successful to destination {dst_ip}")
        return True
    else:
        print(f"FAIL: Ping Failed to destination {dst_ip} with {pkt_loss}% loss")
        return False

def get_ovs_p4ctl_help(option):
    """
    :Function to get output of command "ovs-p4ctl --help"
    :returns output or False
    """
    connection = Local()
    cmd =f"ovs-p4ctl {option}"
    output, _, _ = connection.execute_command(cmd)
    connection.tear_down()
    if output:
        print (f"PASS: The command \"{cmd}\" return below message \n {output}")
        return output 
    else:
        return False

def ipnetns_eth_offload(nsname, interface, remote=False, hostname="",username="",password=""):
    """
    :Function to offload interface
    :Example: ethtool --offload ens3 rx off tx off
    :returns boolean True or False
    """
    cmd=f"ethtool --offload {interface} rx off tx off"
    if not gnmi_cli_utis.ip_link_netns_exec(nsname, cmd,remote=remote,hostname=hostname, username=username, password=password)[0]:
        print (f"FAILED: Failed to execute cmd {cmd} on namespace {nsname}")
        return False
    return True

def ipnetns_change_mtu(nsname,  interface, mtu=1500, remote=False, hostname="",username="",password=""):
    """
    :Function to change mtu of interface on linux name space       
    :returns boolean True or False
    """
    cmd=f"ip link set {interface} mtu {mtu} up"
    if not gnmi_cli_utis.ip_link_netns_exec(nsname, cmd,remote=remote,hostname=hostname, username=username, password=password)[0]:
        print (f"FAILED: Failed to execute cmd {cmd} on namespace {nsname}")
        return False
    return True

def ipnetns_netserver(nsname, remote=False, hostname="",username="",password=""):
    """
    :Function to start netserver on linux name space
    :returns boolean True or False
    """
    cmd = "netserver"
    result = gnmi_cli_utis.ip_link_netns_exec(nsname, cmd,remote=remote,hostname=hostname, username=username, password=password)[1]
    if "Starting netserver" not in result:
        print (f"FAILED: Failed to execute cmd {cmd} on namespace {nsname}")
        return False
        
    print (f"PASS: netserver is running on namespace {nsname}") 
    return True

def ipnetns_netperf_client(nsname, host, testlen, testname, option="", remote=False, hostname="",username="",password=""):
    """
    :Function to start netperf on linux name space
    :returns boolean True or False
    """
    max = 5
    found = False
    err_list,data, counter =[],[], {}
 
    if testname == "UDP_STREAM":
        cnt_name=['sckt_byte','msg_byte','elapsed','msg_ok','msg_erro','throput']
        n, data_len = 1, 6
    elif testname == "TCP_STREAM":
        found = False
        cnt_name=['recv_sckt_byte','send_sckt_byte','sned_msg_byte','elapsed','throput']
        n, data_len =1, 5
    else:
        print(f"FAIL: the stream {testname} is not defined. Please correct it")
        return False
  
    cmd = f"netperf -H {host} -l {testlen} -t {testname} {option}".replace(u'\xa0', u' ')
    while n < max:
        output = gnmi_cli_utis.ip_link_netns_exec(nsname, cmd,remote=remote,hostname=hostname, username=username, password=password)[1]
        for each in output.strip().split("\n"):
            data=each.strip().split()
            if len(data) == data_len:
                try:
                    if all(isinstance(float(item),float) for item in data):
                        found=True
                        for i in range(len(data)):
                            counter[cnt_name[i]] = float(data[i])
                        break
                except:
                    #checking netperf output data having all float number that indicate sucess
                    # of netperf.do nothing and continue to check
                    pass
        if found:
            break
        else:
            err_list.append(f"The {n} failure and its output {output}")          
    
        n +=1 
    if found == False:
        print(f"FAIL: unable to collect netperf execution data after {n} tries due output\n{err_list}")
        return False
    
    print (f"PASS: successfully executed \"{cmd}\" with below output \n {output}")
    return counter

def vm_check_netperf(conn, vmname):
    """
    :Function to check of netperf is installed or not
    :returns boolean True or False
    """
    conn.readResult()
    cmd= "netperf -V"
    conn.sendCmd(cmd)
    output = conn.readResult().split("\n")[1]
    
    if "Netperf version" not in output:
        print (f"FAILED: netperf is not installed on {vmname}")
        return False
    
    print (f"PASS: verify netperf is installed on {vmname}")
    return True

def vm_start_netserver(conn):
    """
    To check if a netserver is running or not. If not running, try to start netperf
    """
    # kill existing process and restart it 
    conn.sendCmd("pkill -9 netserver")
    conn.sendCmd("netserver")
    output = conn.readResult()
    if "Starting netserver" not in output:
        print(f"FAIL: Unable to start netserver")
        return False
    
    print ("PASS: netserver is running on VM") 
    return True

def vm_netperf_client(conn, host, testlen, testname, option=""):
    """
    A function to determine if sending netperf succeed or fail.
    As netperf doesn't provide explict status of success or failure, 
    this function is to serach if a line of netperf output has a float number
    in all fiels. If yes, sending netperf succeed and a counter
    
      Example 1:  Netperf UDP_STRAM output 
        root@TRAFFICGEN:~# netperf -H 99.0.0.3 -l 10 -t UDP_STREAM -- -m 64
        ....omitted .....
        212992           10.00     1938991             99.27
    
      Example 2 :  Netperf TCP_STRAM output 
        root@TRAFFICGEN:~# netperf -H 99.0.0.3 -l 10 -t TCP_STREAM -- -m 64
        .... omitted ....
        131072  16384     64    10.00     610.03
    """
    max = 5
    found = False
    err_list,data, counter =[],[],{}
    conn.readResult() # read to clear previous buffer
    if testname == "UDP_STREAM":
        cnt_name=['sckt_byte','msg_byte','elapsed','msg_ok','msg_erro','throput']
        n, data_len = 1, 6
    elif testname == "TCP_STREAM":
        found = False
        cnt_name=['recv_sckt_byte','send_sckt_byte','sned_msg_byte','elapsed','throput']
        n, data_len =1, 5
    else:
        print(f"FAIL: the stream {testname} is not defined. Please correct it")
        return False
    
    cmd = f"netperf -H {host} -l {testlen} -t {testname} {option}".replace(u'\xa0', u' ')
    conn.sendCmd(cmd)
    while n < max:
        output = conn.readResult()
        for each in output.strip().split("\n"):
            data=each.strip().split()
            if len(data) == data_len:
                try:
                    if all(isinstance(float(item),float) for item in data):
                        found=True
                        for i in range(len(data)):
                            counter[cnt_name[i]] = float(data[i])
                        break
                except:
                    #checking netperf output data having all float number that indicate sucess
                    # of netperf.do nothing and continue to check
                    pass
        if found:
            break
        else:
            err_list.append(f"The {n} failure and its output {output}")          
    
        n +=1 
    if found == False:
        print(f"FAIL: Unable to collect netperf execution data after {n} tries due output\n{err_list}")
        return False
    
    print (f"PASS: successfully executed \"{cmd}\" with below output \n {output}")
    return counter

def vm_netperf_client_fail(conn, host, testlen, testname, option=""):
    """
    To test netserver is not listening and expect netperf failure
    
      Example 1: 
        root@TRAFFICGEN:~# netperf -H 99.0.0.3 -l 5 -t TCP_STREAM -- -m 64
        stablish control: are you sure there is a netserver listening on 99.0.0.3 at port 12865?
        establish_control could not establish the control connection from 0.0.0.0 port 0 address family AF_UNSPEC to 99.0.0.3 port 12865 address family AF_INET

    """
    conn.readResult()
    cmd = f"netperf -H {host} -l {testlen} -t {testname} {option}".replace(u'\xa0', u' ')
    conn.sendCmd(cmd)
    output = conn.readResult().split("\n")
    if "are you sure there is a netserver listening" in output[-3]:
        print(f"PASS: \"{cmd}\" not established as netserver is not expected reachable")
        return True  
   
    print (f"FAIL: netserver is expected not reachable but it's reached") 
    return False

def host_check_netperf(remote=False, hostname="",username="",password=""):
    """
    :Function to check if netperf is installed and pkill running porcess
    :and prepare to restart it.
    :returns boolean True or False
    """
    if remote:
        connection = Ssh(hostname=hostname, username=username, passwrd=password)
        connection.setup_ssh_connection()
    else:
        hostname="local host"
        connection = Local()
    result, _, _ = connection.execute_command("netperf -V")
    
    if "Netperf version" not in result:
        print (f"FAILED: netperf is not installed on namespace {hostname}")
        connection.tear_down()
        return False
    print (f"PASS: verify netperf is installed on {hostname}")
 
    _, _, err= connection.execute_command("pkill -9 netserver")
    if err:
        print (f"FAILED: faild to pkill -9 netserver")
        connection.tear_down()
        return False
    print (f"PASS: \"pkill -9 netserver\" and ready to restart netserver on {hostname}")
    
    connection.tear_down()
    return True

def get_vm_interface_counter(conn, interface):
    """
    A function to build a counter directory for a VM interface statistics
    """
    counter ={}
    cmd= f"ip -s -s link show dev {interface}"
    print (f"Execute cmd \"{cmd}\"")
    
    j=1
    while j<3:
        if j>2: print (f"{j} try to execute cmd \"{cmd}\"")
        conn.sendCmd(cmd)
        output = conn.readResult()
        if len(output.split("\n")) <8:
            j +=1
        else:
            break
    if j>3:
        print (f"FAIL: failed to execue \"{cmd}\" after {j} times")
        return False
   
    iter_rslt = iter(output.split("\n"))
    # Build  port counter dict
    for each in iter_rslt:
        each = each.strip()
        if each.isspace() or len(each)==0:
            continue
        if "RX:" in each:
            key="RX"
            counter[key]=dict()
            name_list = each.split(":")[1].strip().split()
            val_list = next(iter_rslt, None).split()
            for i in range(len(name_list)):
                counter[key][name_list[i]]=int(val_list[i])
        elif "RX errors" in each:
            key="RX errors"
            counter[key]=dict()
            name_list = each.split(":")[1].strip().split()
            val_list = next(iter_rslt, None).split()
            for i in range(len(name_list)):
                counter[key][name_list[i]]=int(val_list[i])
        elif "TX:" in each:
            key="TX"
            counter[key]=dict()
            name_list = each.split(":")[1].strip().split()
            val_list = next(iter_rslt, None).split()
            for i in range(len(name_list)):
                counter[key][name_list[i]]=int(val_list[i])
        elif "TX errors" in each:
            key="TX errors"
            counter[key]=dict()
            name_list = each.split(":")[1].strip().split()
            val_list = next(iter_rslt, None).split()
            for i in range(len(name_list)):
                counter[key][name_list[i]]=int(val_list[i])
    if counter:        
        return counter
   
    return False

def vtysh_config_frr_bgp_attr(asnumber, neighbor="",addr_family="",
                router_id="", network="",hostname="",username="",password=""):
    """
    A funtion to configure frr BGP attributes
    """
    print (f"Configure BGP attributes")
    if hostname and username and password:
        remote=f"{username}@{hostname}"
        config = pexpect.spawn("ssh " + remote) 
        config.expect("password:")
        config.sendline(password)
        i = config.expect (['Permission denied', '[~#\]\$]'])
        if i == 0:
            print(f"Permission denied by {hostname}. Unable to login")
            config.kill(0)
        elif i == 1:
            print('Connected Successfully.')
            config.sendline("vtysh")
            config.expect("#")
    else:
        config= pexpect.spawn("vtysh")
        config.expect("#")
    try:
        if asnumber not in range(1,4294967296):
            print ("FAIL: a as-number must be in range of 1 ~ 4294967295")
            config.close()
            return False
        config.sendline("config t")
        config.expect("config\)#")
        config.sendline(f"router bgp {asnumber}")
        config.expect("#")
        if neighbor:
            config.sendline(f"neighbor {neighbor} remote-as {asnumber}")
            config.expect("#")
        if addr_family: 
            config.sendline(f"address-family {addr_family}")
            config.expect("router-af\)#")
            if router_id:
                config.sendline(f"bgp router-id {router_id}")
                config.expect("config-router\)#")
            if network:
                config.sendline(f"network {network}")
                config.expect("\)#")
                
        config.sendline(f"end")
        config.expect("#")             
    except pexpect.ExceptionPexpect as e:
        print (f"FAIL: unable to configure bgp due to {e}")
        config.close()
        return False
  
    print (f"PSSS: successfuly configure BGP attributes with below configuration")
    config.sendline("show run")
    config.expect("end")
    print (config.before.decode("utf-8"))
    print ("\n")
    config.close()
    
    return True

def vtysh_config_frr_delete_bgp(asnumber, hostname="",username="",password=""):
    """
    A funtion to delete frr BGP configuration
    Returns: boolean True or False
    """
    print (f"Delete router interface")
    if hostname and username and password:
        remote=f"{username}@{hostname}"
        config = pexpect.spawn("ssh " + remote) 
        config.expect("password:")
        config.sendline(password)
        i = config.expect (['Permission denied', '[~#\]\$]'])
        if i == 0:
            print(f"Permission denied by {hostname}. Unable to login")
            config.kill(0)
        elif i == 1:
            print(f'Connected Successfully to {hostname}')
            config.sendline("vtysh")
            config.expect("#")
    else:
        config= pexpect.spawn("vtysh")
        config.expect("#")
    try:
        cmd=f"no router bgp {asnumber}"
        config.sendline("config t")
        config.expect("config\)#")
        config.sendline(cmd)
        config.expect("config\)#")
        config.sendline(f"end")
        config.expect("#")
    except pexpect.ExceptionPexpect as e:
        print (f"FAIL: unable to execute {cmd} due to {e}")
        config.close()
        return False
    
    print (f"PSSS: successfuly execute\"{cmd}\"with below configuration")
    config.sendline("show run")
    config.expect("end")
    print (config.before.decode("utf-8"))
    print ("\n")
    config.close()
    
    return True

def vtysh_config_frr_router_interface(interface, action="",ip="", hostname="",username="",password=""):
    """
    A funtion to configure frr router interface
    Returns: boolean True or False
    """
    print (f"configure router interface")
    if hostname and username and password:
        remote=f"{username}@{hostname}"
        config = pexpect.spawn("ssh " + remote) 
        config.expect("password:")
        config.sendline(password)
        i = config.expect (['Permission denied', '[~#\]\$]'])
        if i == 0:
            print(f"Permission denied by {hostname}. Unable to login")
            config.kill(0)
        elif i == 1:
            print(f'Connected Successfully to {hostname}')
            config.sendline("vtysh")
            config.expect("#")
    else:
        config= pexpect.spawn("vtysh")
        config.expect("#")
    try:
        if not interface:
            print ("FAIL: an interface must be provided")
            config.close()
            return False
        config.sendline("config t")
        config.expect("config\)#")
        config.sendline(f"interface {interface}")
        config.expect("config-if\)#")
        if ip:
            config.sendline(f"{action} ip address {ip}")
            config.expect("config-if\)#")
        
        config.sendline(f"end")
        config.expect("#")
    except pexpect.ExceptionPexpect as e:
        print (f"FAIL: unable to configure frr router interface due to {e}")
        config.close()
        return False
    
    print (f"PSSS: successfuly configure frr router interface with below configuration")
    config.sendline("show run")
    config.expect("end")
    print (config.before.decode("utf-8"))
    print ("\n")
    config.close()
    
    return True

def restart_frr_service(remote=False, hostname="",username="",password=""):
    """
    A function to restart frr service by executing "service frr restart" 
    on local or remote host.
    Returns: boolean True or False
    """
    if remote:
        connection = Ssh(hostname=hostname, username=username, passwrd=password)
        connection.setup_ssh_connection()
    else:
        hostname="local host"
        connection = Local()
    _, _, err = connection.execute_command("service frr restart")

    if err:
        print (f"FAILED: faild to restart frr service")
        connection.tear_down()
        return False
    print (f"PASS: successfuly execute cmd \"service frr restart\" on {hostname}")
    
    connection.tear_down()
    
    return True
