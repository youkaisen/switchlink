"""
This lib should contain utility functions related to ovs commands like
ovs-vsctl, ovs-ofctl and ovs-dpctl.
This lib makes use of functions from library common/lib/ovs.py.
"""

from common.lib.local_connection import Local
from common.lib.ssh import SSHParamiko
from common.lib.ovs import Ovs


def get_connection_object(remote=False, hostname="", username="", passwd=""):
    """ Get connection object needed either for localhost or remote host
    commands execution

    :param remote: set value to True enables remote host cmd execution
    :type remote: boolean e.g. remote=True
    :param hostname: remote host IP address, not required for DUT host
    :type hostname: string e.g. 10.233.132.110
    :param username: remote host username, not required for DUT
    :type username: string e.g. root
    :param passwd: remote host password, not required for DUT
    :type passwd: string e.g. cloudsw
    :return: connection object either SSHParamiko or Local class
    :rtype: Object e.g. connection
    """
    if remote:
        connection = SSHParamiko(hostname, username, passwd)
        connection.setup_ssh_connection()
    else:
        connection = Local()
    return connection


def get_ovsctl_version(remote=False, hostname="", username="", passwd=""):
    """ Get current Ovs version
    """
    # Establish connection with local/remote host
    connection = get_connection_object(remote, hostname, username, passwd)
    ovs = Ovs(connection)
    # Execute needed ovs command
    version = ovs.vsctl.get_ver()
    if version:
        print(version)
    # Close connection
    connection.tear_down()






