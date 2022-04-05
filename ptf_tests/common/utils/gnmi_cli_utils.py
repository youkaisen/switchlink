from common.lib.port_config import PortConfig
from common.lib.local_connection import Local


def gnmi_cli_set_and_verify(set_params, get_params, host_info, pass_criteria_pattern=['pipe', 'up']):
    """
    Util function to gnmi-set and verify using gnmi-get
    :param pass_criteria_pattern: list of patterns to 'grep'
                                in gnmi-cli get output to declare test Pass/Fail
    :param set_params: 'params' string to execute gnmi-cli set
    :param get_params: 'params' string to execute gnmi-cli get
    :param host_info: type --> 'dict' : {'host':<host ip/localhost>,
                                        'username':<username>,
                                        'password':<password>
    :return: Boolean True/False
    """
    port_config = PortConfig(host_info['host'], host_info['username'], host_info['password'])

    if not port_config.GNMICLI.gnmi_cli_set(set_params):
        print(f"Failed to do gnmi-set {set_params}")
        return False

    grep = "| grep -w -i "
    grep_string = ""
    for pattern in pass_criteria_pattern:
        grep_string += f"{grep} \"{pattern}\""

    if not port_config.GNMICLI.gnmi_cli_get(get_params, grep_string=grep_string):
        print(f"Failed to do gnmi-get {set_params}")
        return False

    print("gnmi-set Successful!")
    return True

def gnmi_set_params(params):
    port_config = PortConfig()
    for param in params:
        output = port_config.GNMICLI.gnmi_cli_set(param)
    port_config.GNMICLI.tear_down()

    return output

def ip_set_ipv4(interface_ip_list):
    port_config = PortConfig()
    for interface_ipv4_dict in interface_ip_list:
        for interface, ip in interface_ipv4_dict.items():
            port_config.Ip.iplink_enable_disable_link(interface, status_to_change='up')
            port_config.Ip.ipaddr_ipv4_set(interface, ip)

    return
