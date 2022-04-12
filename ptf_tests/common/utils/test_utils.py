"""
Generic utility scripts for P4OVS PTF scripts.
"""

from ptf import *
from ptf.testutils import *

import json
import os

from common.lib.local_connection import Local
from common.lib.telnet_connection import connectionManager

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


def ping_test_using_telnet(conn, dst_ip, count="4"):
    """
    To test if ping to a destination works without any drop
    """
    cmd = f"ping {dst_ip} -c {count}"
    dummy_ping(conn, cmd)

    conn.sendCmd(cmd)
    result = conn.readResult()
    pkt_loss = 100
    if result != None:
        match = re.search('(\d*)% packet loss', result)
        if match !=None:
            pkt_loss = match.group(1)

    if f"{count} received, 0% packet loss" in result:
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


