import os
os.sys.path.insert(0, "{}/paramikossh".format(os.path.dirname(os.path.abspath(__file__))))  # noqa
import paramiko
import socket
import time
import re
from bs4 import UnicodeDammit
try:
    from urlparse import urlparse
except Exception:
    from urllib.parse import urlparse

ENABLE_CLUSTERMODE_COMMAND_STR = "clustermode cluster;"
LIST_DICTIONARY_COMMAND_STR = "dictionaryconfig print {dictionary_name};"
ADD_DICTIONARY_ENTRY_COMMAND_STR = "dictionaryconfig edit {dictionary_name} new \"{entry_value}\";"
REMOVE_DICTIONARY_ENTRY_COMMAND_STR = "dictionaryconfig edit {dictionary_name} delete \"{entry_value}\";"
MODIFY_DICTIONARY_COMMIT_COMMAND_STR = "commit \"{commit_message}\";"

ESA_SPECIAL_CHARACTERS = [ '.', '[', ']', '^', '?', '$', '*', '+', '(', ')', '|', '-' ]

ESA_ESCAPED_FORMAT_STR = "^{escaped}$"

class CiscoEsaHelper():
    OS_LINUX = 0
    OS_MAC = 1

    def __init__(self, connector, username, password, endpoint):
        self._connector = connector
        self._username = username
        self._password = password
        self._endpoint = urlparse(endpoint).hostname
        
    def _start_connection(self, server):

        user = self._username
        password = self._password
        

        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._ssh_client.connect(hostname=server, username=user,
                    password=password, allow_agent=False, look_for_keys=True,
                    timeout=30)
        except Exception as e:
            return (False, "SSH connection attempt failed", e)

        # Get Linux Distribution
        #cmd = "uname -a"
        #status_code, stdout, exit_status = self._send_command(cmd)

        # Couldn't send command
        #if exit_status != 0:
        #    return False, "Unable to send command", stdout

        # Some version of mac
        #if (exit_status == 0 and stdout.split()[0] == "Darwin"):
        #    self.OS_TYPE = self.OS_MAC

        return True, "SSH connection successfull", None

    def _get_output(self, timeout):
        """
            returns:
                success, data, exit_status
        """
        sendpw = True
        self._shell_channel.settimeout(2)
        self._shell_channel.set_combine_stderr(True)
        output = ""
        stime = int(time.time())
        
        try:
            while True:
                self._connector.save_progress('111')
                ctime = int(time.time())
                # data is ready to be received on the channel
                if (self._shell_channel.recv_ready()):
                    self._connector.save_progress('222')
                    recv_output = UnicodeDammit(self._shell_channel.recv(8192)).unicode_markup
                    if recv_output:
                        self._connector.save_progress('666: {}'.format(recv_output))
                        output += recv_output
                        self._connector.save_progress('hello: {}'.format(output))
                        # need to send an enter command to get more of the list
                        if '-Press Any Key For More-' in recv_output:
                            self._connector.save_progress('888')
                            try:
                                self._connector.save_progress('999')
                                self._shell_channel.send("\n")
                            except socket.error:
                                self._connector.save_progress('101010')
                                pass
                    else:
                        self._connector.save_progress('777')
                        break
                    self._connector.save_progress('4444')

                    # This is pretty messy but it's just the way it is I guess
                    if (sendpw and self._password):
                        self._connector.save_progress('1111')
                        try:
                            self._connector.save_progress('2222')
                            self._shell_channel.send("{}\n".format(self._password))
                        except socket.error:
                            self._connector.save_progress('3333')
                            pass
                        sendpw = False
                elif (timeout and ctime - stime >= timeout):
                    self._connector.save_progress('333')
                    return (False, "Error: Timeout", None)
                elif (self._shell_channel.exit_status_ready() and not self._shell_channel.recv_ready()):
                    self._connector.save_progress('444')
                    break
                self._connector.save_progress('555')
                time.sleep(1)
        except Exception as e:
            self._connector.save_progress('Error attempting to retrieve command output: {}'.format(e))
            return (False, "Error", str(e))
        
        return (True, output, self._shell_channel.recv_exit_status())
    
    def _send_command(self, command, timeout=0):
        """
           Args:
               command: command to send
               timeout: how long to wait before terminating program
        """
        # attempt to establish connection first
        status_code, msg, uname_str = self._start_connection(self._endpoint)
        if (not status_code):
            return (False, msg, uname_str)

        try:
            output = ""
            trans = self._ssh_client.get_transport()
            self._shell_channel = trans.open_session()
            self._shell_channel.get_pty()
            self._shell_channel.set_combine_stderr(True)
            self._shell_channel.exec_command(command)
            success, data, exit_status = self._get_output(timeout)
            if not success:
                return (success, "Could not send command: {}\r\nOutput: {}\r\nExit Status: {}".format(command, data, exit_status), exit_status)
            output += data
            output = self._clean_stdout(output)
        except Exception as e:
            return (False, "Error sending command:{}\r\nDetails:{}".format(command, e), exit_status)

        return (success, output, exit_status)

    def _clean_stdout(self, stdout):
        if (stdout is None):
            return None

        try:
            lines = stdout.splitlines()
            while (True):
                if (self._password and self._password in lines[0]):
                    lines.pop(0)
                    continue
                if ("[sudo] password for" in lines[0]):
                    lines.pop(0)
                    continue
                if (lines[0] == ""):
                    lines.pop(0)
                    continue
                if (lines[0] == "-Press Any Key For More-"):
                    lines.pop(0)
                    continue
                break
        except:
            return None

        return ('\n'.join(lines))

    def _escape_entry(self, entry_value):
        escaped_str = entry_value
        if '\\' in escaped_str:
            escaped_str = escaped_str.replace('\\', r'\\')
        
        for character in ESA_SPECIAL_CHARACTERS:
            escaped_str = escaped_str.replace( character, '\\\\' + character )

        return ESA_ESCAPED_FORMAT_STR.format(escaped=escaped_str)

    def list_dictionary_items(self, dictionary_name, cluster_mode=False):
        cmd = ""

        if cluster_mode:
            cmd += ENABLE_CLUSTERMODE_COMMAND_STR

        cmd += LIST_DICTIONARY_COMMAND_STR.format(dictionary_name=dictionary_name)

        return self._send_command(cmd)

    def add_dictionary_item(self, dictionary_name, entry_value, commit_message, cluster_mode=False):
        cmd = ""

        if cluster_mode:
            cmd += ENABLE_CLUSTERMODE_COMMAND_STR

        # escape special characters
        escaped_entry = self._escape_entry(entry_value)

        cmd += ADD_DICTIONARY_ENTRY_COMMAND_STR.format(dictionary_name=dictionary_name, entry_value=escaped_entry)
        cmd += MODIFY_DICTIONARY_COMMIT_COMMAND_STR.format(commit_message=commit_message)

        return self._send_command(cmd)
    
    def remove_dictionary_item(self, dictionary_name, entry_value, commit_message, cluster_mode=False):
        cmd = ""

        if cluster_mode:
            cmd += ENABLE_CLUSTERMODE_COMMAND_STR

        # escape special characters
        escaped_entry = self._escape_entry(entry_value)

        cmd += REMOVE_DICTIONARY_ENTRY_COMMAND_STR.format(dictionary_name=dictionary_name, entry_value=escaped_entry)
        cmd += MODIFY_DICTIONARY_COMMIT_COMMAND_STR.format(commit_message=commit_message)

        return self._send_command(cmd)