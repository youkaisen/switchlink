from ptf import *
from ptf.testutils import *

import json

from common.lib.local_connection import Local

def add_port_to_dataplane(port_list):
    local = Local()
    r,_,_ = local.execute_command("ip -j link show")
    result = json.loads(r)
    for name in port_list:
        for iface in result:
            if (iface["ifname"] == name):
                config["port_map"].update({(0,iface["ifindex"]):name})
                continue
    
    return ptf_ports() 
