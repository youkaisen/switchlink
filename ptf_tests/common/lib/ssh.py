from socket import error
import paramiko
import select
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, \
    SSHException


class SSHParamiko:
    """
    Implements SSH functionality in python with help of paramiko
    module
    """

    def __init__(self, hostname, username, passwrd):
        """
        object instantiation method
        :param hostname: IP Address of client host
        :type hostname: string e.g. 10.223.246.66
        :param username: Username of host
        :type username: string e.g. root
        :param passwrd: Password of host
        :type passwrd: string e.g. pass
        """

        self.hostname = hostname
        self.username = username
        self.passwrd = passwrd
        self.ssh_client = None
        self.remote_cmd = None
        self.timeout = None
        self.NBYTES = 1048576
        self.string_buffer = None

    def setup_ssh_connection(self):
        """establishes connection with the remote server

        :return: ssh client object
        :rtype: 'object', of type SSHClient class
        """

        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy())
            self.ssh_client.connect(hostname=self.hostname,
                                    username=self.username,
                                    password=self.passwrd)
            # print("Established ssh session.")
            return self.ssh_client
        except BadHostKeyException as BHK:
            print("Server's host key could not be verified: %s" % BHK)
        except AuthenticationException as A:
            print("Authentication failed: %s" % A)
        except SSHException as S:
            print(
                "There was an error connecting or establishing SSH "
                "connection: %s" % S)
        except error as E:
            print("Socket error occurred while connecting: %s" % E)

    def execute_command(self, remote_cmd, timeout=10):
        """executes commands on remote server

        :param remote_cmd: command to execute
        :type remote_cmd: string e.g. ls -lh
        :param timeout: Max wait time
        :type timeout: integer
        :return: On success cmd output, on failure -1
        :rtype: string, (integer)
        """

        self.remote_cmd = remote_cmd
        self.timeout = timeout
        # Empty string buffer initialized to capture process STDOUT output
        self.string_buffer = ''
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                self.remote_cmd, timeout=timeout)
        except SSHException as S:
            print("Server fails to execute the command: %s" % S)
        except AttributeError as A:
            print("SSH connection failed: %s" % A)

        # stdin, stdout and stderr are python file like objects
        # these are objects of class paramiko.channel
        # using these objects we can poll the exit status of the running
        # command on remote

        while not stdout.channel.exit_status_ready():
            '''May not return exit status in some cases like bad servers'''
            '''Until final exit status is not received, lets read the data'''
            if stdout.channel.recv_ready():
                '''Returns true if data is buffered and ready to read from 
                this terminal'''
                rlist, wlist, xlist = select.select([stdout.channel], [], [],
                                                    0.0)
                '''Returns 3 new lists for stdout,stdin,stderr'''
                if len(rlist) > 0:
                    out = stdout.channel.recv(self.NBYTES)
                    '''On failure returns empty string'''
                    if out != '':
                        self.string_buffer += out.decode()

        # Code for handling stderr
        errors = str(stderr.read().decode('utf-8'))
        if errors == '':
            return self.string_buffer, 0, errors
        else:
            print(f"Error in running given command, {self.remote_cmd}")
            print(f"Error log:\n{errors}")
            return self.string_buffer, -1, errors

    def execute_command_get_exit_status(self, cmd):
        """ To execute remote server cmd and return on status

        :param cmd: Remote cmd to execute
        :type cmd: string
        :return: 0 on success, -1 on failure
        :rtype: integer
        """
        try:
            chan = self.ssh_client.get_transport().open_session()
            chan.exec_command(cmd)
            """
            key = True
            while key:
                if chan.exit_status_ready():
                    status = chan.recv_exit_staus()
                    print(f'Exit status:{status}')
                    return status
            return -1
            """
            """If the command hasn’t finished yet, below method will wait 
               until it does, or until the channel is closed. 
               If no exit status is provided by the server, -1 is returned"""
            return chan.recv_exit_status()
        except SSHException as E:
            print(f"Request is rejected or session ends prematurely\n"
                  f"Error logs:{E}")
            return -1

    def tear_down(self):
        """Close current SSH session with remote machine

        :return: None
        :rtype: None
        """
        self.ssh_client.close()
        # print("Closed current ssh session")
