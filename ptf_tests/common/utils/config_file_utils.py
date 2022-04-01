"""
util lib for parsing config json files
"""
import json
import os


def get_config_dict(config_json):
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

        for table in data['table']:
            if 'match_action' in table.keys():
                table['del_action']=[]
                for match_action in table['match_action']:
                    table['del_action'].append(match_action.split(',')[0])

        for table in data['table']:
            if 'member_details' in table.keys():
                table['del_member']=[]
                for member_detail in table['member_details']:
                    table['del_member'].append(member_detail.split(',')[1])

        for table in data['table']:
            if 'group_details' in table.keys():
                table['del_group']=[]
                for group_detail in table['group_details']:
                    table['del_group'].append(group_detail.split(',')[0])

        #######################################################
        ##### Any future data structure can be added here #####
        #######################################################

        return data


def get_params_tap_port_simple(data):
    """
    util function to parse 'data' dictionary and return list of 'params' string for gnmi-cli set/get
    :param data: dictionary obtained from config json file
    :return: list --> list of params
                --> ["device:virtual-device,name:TAP0,pipeline-name:pipe,mempool-name:MEMPOOL0,mtu:1500,port-type:TAP",
                     "device:virtual-device,name:TAP1,pipeline-name:pipe,mempool-name:MEMPOOL0,mtu:1500,port-type:TAP",
                     ...]
    """
    params = []
    keys = ["pipeline-name", "mempool-name", "mtu", "port-type"]

    for port in data['port']:
        param = ""
        param += f"device:{port['device']}"
        param += f",name:{port['name']}"
        param += f",pipeline-name:{port['pipeline_name']}"
        param += f",mempool-name:{port['mempool_name']}"
        param += f",mtu:{port['mtu']}"
        param += f",port-type:{port['port_type']}"

        params.append(param)

    return params


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
