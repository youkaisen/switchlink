import subprocess


class Local(object):
    """This class helps run commands on local server
    """
    def __init__(self):
        self.process = None

    def execute_command(self, command):
        """ To execute localhost commands and return all outputs
        :param command: command to execute locally
        :type command: string e.g. "ls -lh"
        :return: cmd output, exit code, and error logs
        :rtype: tuple e.g. out,return_code,error
        """

        self.process = subprocess.Popen('/bin/bash', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = self.process.communicate(command.encode('utf-8'))

        if err:
            err = err.decode('utf-8')
        return out.decode('utf-8'), self.process.returncode, err

    def execute_command_get_exit_status(self, command):
        """To execute localhost commands and return exit status only

        :param command: command to execute locally
        :type command: string e.g. "ls -lh"
        :return: pass or fail exit status of command
        :rtype:
        """
        self.process = subprocess.Popen('/bin/bash', stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE)
        out, err = self.process.communicate(command.encode('utf-8'))
        if err:
            err = err.decode('utf-8')
            return -1
        else:
            return 0

    def tear_down(self):
        """
        Yet to implement
        :return: None
        :rtype: None
        """
        pass
