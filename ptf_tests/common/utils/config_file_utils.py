"""
util lib for parsing config json files
"""
import json
import os


def get_config_dict(config_json, pci_bdf=""):
    """
    util function to convert json config file to dictionary
    expected directory structure:
    P4OVS
    |
    |
    ---- ptf-test
        |
        ---- common
        |   |
            | ---- config (JSON files)
            | ----- lib (gnmi, p4-ovsctl)
            | ----- utils ( parse jason, send/verify traffic, port config, vm support etc)
        | -----exact-match.py
        | -----action-selector.py
        | -----port-types.py
        | -----hot-plug.py
    :param config_json: config json file name
    :return: dictionary --> 'data'
    """
    config_json = os.sep.join([os.getcwd(), 'common', 'config', config_json])

    with open(config_json) as config_json:
        data = json.load(config_json)

        port_list = []
        for port in data['port']:
            port_list.append(port['name'])
        port_list.sort()

        data['port_list'] = port_list

        if pci_bdf:
            pci_bdf = [x.strip() for x in pci_bdf.split(',')]
            if len(pci_bdf)>len(data['port_list']):
                print(f"No of pci bdf must be equal to or less than the no of ports defined in the config json file: {len(data['port_list'])}")
                return None

            for port in data['port']:
                for pci in pci_bdf:
                    if pci and \
                            str(pci_bdf.index(pci)+1) == port['id']:
                                if port['device']=='physical-device':
                                    port['pci_bdf'] = pci
                                else:
                                    print(f"Port no {port['id']} expected device type as physical-device found {port['device']} instead")
                                    return None

        for table in data['table']:
            if 'match_action' in table.keys():
                table['del_action'] = []
                for match_action in table['match_action']:
                    table['del_action'].append(match_action.split(',')[0])

        for table in data['table']:
            if 'member_details' in table.keys():
                table['del_member'] = []
                for member_detail in table['member_details']:
                    table['del_member'].append(member_detail.split(',')[1])

        for table in data['table']:
            if 'group_details' in table.keys():
                table['del_group'] = []
                for group_detail in table['group_details']:
                    table['del_group'].append(group_detail.split(',')[0])

        #######################################################
        ##### Any future data structure can be added here #####
        #######################################################

        return data


def get_interface_ipv4_dict(data):
    """
    util function to get a list of dictionary mapping interfaces with its corresponding ip
    :param data: dictionary obtained from config json file
    :return: list of dictionary --> [{"TAP0":"1.1.1.1/24"},
                                    {"TAP1":"2.2.2.2/24"},
                                    ...]
    """
    interface_ip_list = []
    for port in data['port']:
        interface_ip_list.append({port['name']: port.setdefault('ip', '0.0.0.0')})

    return interface_ip_list


def get_device_type(port):
    """
    helper function to decide the device type: tap/vhost/link
    :params: port --> dictionary containing port details from json
    :returns: string --> tap / vhost / link
    """
    if port['device'] == "physical-device":
        return "link"
    elif port['device'] == 'virtual-device' and port['port-type'] == 'LINK':
        return 'vhost'
    elif port['device'] == 'virtual-device' and port['port-type'] == 'TAP':
        return 'tap'
    else:
        print("Invalid 'device' or 'port-type' in json")
        return None


def get_gnmi_params_simple(data):
    """
    util function to parse 'data' dictionary and return list of 'params' string for gnmi-cli set/get
    :param data: dictionary obtained from config json file
    :return: list --> list of params
                --> ["device:virtual-device,name:net_vhost0,host:host1,device-type:VIRTIO_NET,queues:1,socket-path:/tmp/vhost-user-0,port-type:LINK",
                "device:virtual-device,name:net_vhost1,host:host2,device-type:VIRTIO_NET,queues:1,socket-path:/tmp/vhost-user-1,port-type:LINK",
                ...]
    """
    common = ['device', 'name']
    mandatory = {'tap': [],
                 'vhost': ['host', 'device-type', 'queues', 'socket-path'],
                 'link': ['pci-bdf']
                 }
    optional = ['pipeline-name', 'mempool-name', 'control-port', 'mtu']

    params = []

    for port in data['port']:
        param = ""
        for field in common:
            param += f"{field}:{port[field]},"

        device_type = get_device_type(port)
        if not device_type:
            return None
        for field in mandatory[device_type]:
            param += f"{field}:{port[field]},"

        for field in optional:
            if field in port.keys():
                param += f"{field}:{port[field]},"

        param += f"port-type:{port['port-type']}"

        params.append(param)

    return params
