#!/usr/bin/python

from common.lib.local_connection import Local
from common.lib.exceptions import ExecuteCMDException


class PortConfig(object):
    def __init__(self):
        """
        Constructor method
        """
        self.GNMICLI = self._GNMICLI()
        self.Ifconfig = self._Ifconfig()

    class _Common(object):
        cmd_prefix = None

        def form_cmd(self, cmd):
            """Combine command prefix with command
            :param cmd: command to combine with prefix
            :type cmd: str
            :return: command combined with prefix
            :rtype: str
            """
            return " ".join([self.cmd_prefix, cmd])

    class _GNMICLI(_Common):
        def __init__(self):
            """
            Constructor method
            """
            # self.ssh = SSH(host, username, password)
            self.local = Local()
            self.cmd_prefix = 'gnmi-cli'


        def gnmi_cli_set(self, params):
            """
            gnmi-cli set command
            :param params: all parameters required for gnmi-cli set
            :type params: str
            :return: stdout of the gnmi-cli set command
            :rtype: str
            """
            cmd = self.form_cmd(f"set \"{params}\"")
            output, return_code, _ = self.local.execute_command(cmd)
            if 'Set request, successful' not in output:
                print(f"FAIL: {cmd}")
                raise ExecuteCMDException(f'Failed to execute command {cmd}')
            print(f"PASS: {cmd}")
            return output

        def gnmi_cli_get(self, params, grep_string=""):
            """
            gnmi-cli get command
            :param params: all parameters required for gnmi-cli get
            :type params: str
            :return: stdout of the gnmi-cli get command
            :rtype: str
            """
            self.ssh.execute_command("echo $SDE_INSTALL")
            cmd = self.form_cmd(f"get \"{params}\" {grep_string}")
            output, return_code, _ = self.local.execute_command(cmd)
            if return_code:
                print(f"output: {output}")
                raise ExecuteCMDException(f'Failed to execute command "{cmd}"')

            return output

        def tear_down(self):
            """
            close ssh related objects.
            :return: None
            """
            pass

    class _Ifconfig(_Common):
        def __init__(self):
            """
            Constructor method
            """
            self.cmd_prefix = 'ifconfig'
            self.local = Local()

        def ifconfig_ipv4_set(self, interface, ip):
            """
            Assigns IP address 'ip' to 'interface'
            :param interface: network interface name --> str e.g. "TAP0"
            Assigns IP address 'ip' to 'interface'
            :param interface: network interface name --> str e.g. "TAP0"
            :param ip: ipv4 address --> str e.g. "1.1.1.1/24"
            :return: True/False --> boolean
            """
            cmd = self.form_cmd(f" {interface} {ip} up")
            output, return_code, _ = self.local.execute_command(cmd)
            if return_code:
                print(f"FAIL: {cmd}")
                raise ExecuteCMDException(f'Failed to execute command "{cmd}"')

            print(f"PASS: {cmd}")
            return True

        def tear_down(self):
            """
            close ssh related objects.
            :return: None
            """
            pass
