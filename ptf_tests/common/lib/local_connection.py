from subprocess import run
import subprocess


class Local(object):
    def __init__(self):
        pass

    def execute_command(self, command):
        """
        util function to run commands locally
        :param command: command string
        :return: stdout, returncode, stderr
        """

        self.process = subprocess.Popen('/bin/bash', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = self.process.communicate(command.encode('utf-8'))

        if err:
            err = err.decode('utf-8')
        return out.decode('utf-8'), self.process.returncode, err
