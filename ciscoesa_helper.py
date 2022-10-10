# File: ciscoesa_helper.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import os
import socket
import time

import paramiko
from bs4 import UnicodeDammit

os.sys.path.insert(0, "{}/paramikossh".format(os.path.dirname(os.path.abspath(__file__))))  # noqa

try:
    from urlparse import urlparse
except Exception:
    from urllib.parse import urlparse

ENABLE_CLUSTERMODE_COMMAND_STR = "clustermode cluster;"
LIST_DICTIONARY_COMMAND_STR = "dictionaryconfig print {dictionary_name};"
ADD_DICTIONARY_ENTRY_COMMAND_STR = "dictionaryconfig edit {dictionary_name} new \"{entry_value}\";"
REMOVE_DICTIONARY_ENTRY_COMMAND_STR = "dictionaryconfig edit {dictionary_name} delete \"{entry_value}\";"
MODIFY_DICTIONARY_COMMIT_COMMAND_STR = "commit \"{commit_message}\";"


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
                ctime = int(time.time())
                # data is ready to be received on the channel
                if (self._shell_channel.recv_ready()):
                    recv_output = UnicodeDammit(self._shell_channel.recv(8192)).unicode_markup
                    if recv_output:
                        output += recv_output
                        # need to send an enter command to get more of the list
                        if '-Press Any Key For More-' in recv_output:
                            try:
                                self._shell_channel.send("\n")
                            except socket.error:
                                pass
                    else:
                        break

                    # This is pretty messy but it's just the way it is I guess
                    if (sendpw and self._password):
                        try:
                            self._shell_channel.send("{}\n".format(self._password))
                        except socket.error:
                            pass
                        sendpw = False
                elif (timeout and ctime - stime >= timeout):
                    return (False, "Error: Timeout", None)
                elif (self._shell_channel.exit_status_ready() and not self._shell_channel.recv_ready()):
                    break
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
        escaped_entry = entry_value.replace('\\', '\\\\').replace('\"', '\\\"')

        cmd += ADD_DICTIONARY_ENTRY_COMMAND_STR.format(dictionary_name=dictionary_name, entry_value=escaped_entry)
        cmd += MODIFY_DICTIONARY_COMMIT_COMMAND_STR.format(commit_message=commit_message)

        return self._send_command(cmd)

    def remove_dictionary_item(self, dictionary_name, entry_value, commit_message, cluster_mode=False):
        cmd = ""

        if cluster_mode:
            cmd += ENABLE_CLUSTERMODE_COMMAND_STR

        # escape special characters
        escaped_entry = entry_value.replace('\\', '\\\\').replace('\"', '\\\"')

        cmd += REMOVE_DICTIONARY_ENTRY_COMMAND_STR.format(dictionary_name=dictionary_name, entry_value=escaped_entry)
        cmd += MODIFY_DICTIONARY_COMMIT_COMMAND_STR.format(commit_message=commit_message)

        return self._send_command(cmd)
