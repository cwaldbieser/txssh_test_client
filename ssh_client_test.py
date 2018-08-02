#! /usr/bin/env python

from __future__ import print_function
import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import random
import string
import struct
import sys
import textwrap
import time
import types
import attr
import jinja2
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname
from ldaptor.protocols.ldap import ldapclient
from ldaptor.protocols.ldap import ldapsyntax
import pem
from six.moves import configparser, cStringIO
from twisted.internet import ssl, task, defer
from twisted.internet.endpoints import (
    clientFromString,
    connectProtocol, 
    UNIXClientEndpoint,
)
from twisted.internet.protocol import Factory, Protocol
from twisted.conch.client.knownhosts import KnownHostsFile
from twisted.conch.endpoints import SSHCommandClientEndpoint
from twisted.conch.ssh.keys import EncryptedKeyError, Key
from twisted.python.filepath import FilePath
from twisted.internet import stdio
from twisted.protocols import basic


class CommandProtocol(Protocol):

    reactor = None
    is_connected = False
    encoding = 'utf-8'
    stdin_open = True
    delay_before_closing_stdin = 1
    debug = False

    def __init__(self):
        self.linebuf = cStringIO() 
        self.finished = defer.Deferred()
        self.stdin_buf = []
        self.stdout_cb = None

    def connectionMade(self):
        if self.debug:
            print("[DEBUG] Connection made.")
        self.is_connected = True
        for line in self.stdin_buf:
            if self.debug:
                print("[DEBUG] Writing line to tunnel: {0}".format(line))
            self.transport.write(line.encode(self.encoding))
            self.transport.write('\n'.encode(self.encoding))
        self.stdin_buf = []
        if not self.stdin_open:
            #self.reactor.callLater(self.delay_before_closing_stdin, self._close_stdin)
            self._close_stdin()

    def dataReceived(self, data):
        if self.debug:
            print("[DEBUG] Transport: {}".format(self.transport))
            print("[DEBUG] Data received.")
            print("[DEBUG] Server says: {0}".format(data))
        parts = data.split("\n")
        if len(parts) > 1:
            self.linebuf = cStringIO()
            self.linebuf.write(parts[-1])
        else:
            self.linebuf.write(data)
        line = self.linebuf.getvalue()
        print(data,)
        if self.stdout_cb is not None:
            self.stdout_cb(data.decode(self.encoding))

    def connectionLost(self, reason):
        if self.debug:
            print("[DEBUG] Connection lost.")
            print(reason)
        self.is_connected = False
        self.finished.callback(None)

    def write_line_to_stdin(self, line):
        """
        Write lines to the remote STDIN.
        If not yet connected, buffer the lines.
        If None is provided as the argument, STDIN to the remote side is closed.
        """
        if not self.stdin_open:
            raise Exception("STDIN to the remote end was closed!")
        if line is None:
            self.stdin_open = False
            if self.is_connected:
                self._close_stdin()
            return
        if self.is_connected:
            if self.debug:
                print("[DEBUG] Writing line to tunnel ...")
            self.transport.write(line.encode(self.encoding))
            self.transport.write('\n'.encode(self.encoding))
        else:
            self.stdin_buf.append(line)

    def _close_stdin(self):
        if self.debug:
            print("[DEBUG] Closing STDIN to tunnel ...")
        ssh_conn = self.transport.conn
        print(ssh_conn.channels)
        ssh_conn.sendEOF(self.transport)

    def register_output_callback(self, cb):
        """
        Register a callback to receive STDOUT from the remote
        end.  The callback should be synchronous and have
        the form:

            def callback(data):
                # Do something with data ...

        """
        self.stdout_cb = cb


class StdinProtocol(basic.LineReceiver):
    delimiter = '\n'   
    callback = None
 
    def __init__(self):
        self.lines = []

    def connectionMade(self):
        print("[DEBUG] StdinProtocol - Connection made!")    

    def lineReceived(self, line):
        print("[DEBUG] StdinProtocol - line received!")
        if self.callback is None:
            self.lines.append(line)
        else:
            self.callback(line)

    def set_callback(self, callback):
        """
        Register callback with signature:

            def callback(line):
                # Does something ...

        """
        self.callback = callback
        if self.lines is not None:
            for line in self.lines:
                callback(line)
            self.lines = []


def main(args):
    """
    Reset compromised accounts.
    """
    debug_flag = args.debug
    task.react(run_tasks, [args, debug_flag])

@defer.inlineCallbacks
def run_tasks(reactor, args, debug_flag):
    """
    """
    yield test_long_task_with_stdin(reactor, args, debug_flag) 


@defer.inlineCallbacks
def test_long_task_with_stdin(reactor, args, debug_flag=False):
    """
    Test delayed cat.
    """
    host = b"localhost"
    if args.host is not None:
        host = args.host.encode('utf-8')
    pth = os.path.abspath(os.path.join(os.path.dirname(__file__), "delayed_cat.py"))
    if debug_flag:
        print("[DEBUG] command: {0}".format(pth))
    command = shellquote(pth).encode('utf-8')
    if args.command is not None:
        command = shellquote(args.command).encode('utf-8')
    yield run_remote_command(reactor, command, args, host, debug_flag)

@defer.inlineCallbacks
def run_remote_command(reactor, command, args, host, debug_flag=False): 
    shell_user = getpass.getuser()
    if args.user is not None:
        shell_user = args.user
    agent = get_agent(reactor)
    if agent is None:
        raise Exception("Could not connect to SSH agent.")
    known_hosts = get_known_hosts()    
    endpoint = SSHCommandClientEndpoint.newConnection(
        reactor,
        command,
        shell_user,
        host,
        knownHosts=known_hosts,
        agentEndpoint=agent)
    proto = CommandProtocol()
    proto.debug = debug_flag
    message = textwrap.dedent("""\
        Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.

        Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live. It is altogether fitting and proper that we should do this.

        But, in a larger sense, we can not dedicate-- we can not consecrate-- we can not hallow-- this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us-- that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion-- that we here highly resolve that these dead shall not have died in vain-- that this nation, under God, shall have a new birth of freedom-- and that government of the people, by the people, for the people, shall not perish from the earth.
        """)
    lines = message.split("\n")
    for line in lines:
        proto.write_line_to_stdin(line)
    proto.write_line_to_stdin(None)
    proto.reactor = reactor
    #proto.register_output_callback(sys.stdout.write)
    proto.stdin_open = False
    proto = yield connectProtocol(endpoint, proto)
    yield proto.finished
    defer.returnValue(None)

@defer.inlineCallbacks
def delay(reactor, seconds):
    """
    A Deferred that fires after `seconds` seconds.
    """
    yield task.deferLater(reactor, seconds, lambda : None)

def get_agent(reactor):
    if "SSH_AUTH_SOCK" in os.environ:
        agent_endpoint = UNIXClientEndpoint(reactor, os.environ["SSH_AUTH_SOCK"])
    else:
        agent_endpoint = None
    return agent_endpoint

def get_known_hosts():
    knownHostsPath = FilePath(os.path.expanduser("~/.ssh/known_hosts"))
    if knownHostsPath.exists():
        knownHosts = KnownHostsFile.fromPath(knownHostsPath)
    else:
        knownHosts = None
    return knownHosts

def yesno2boolean(value):
    """
    Convert strings to boolean 
    (case insensitive):
    
    y -> True
    yes -> True
    t -> True
    true -> True
    1 -> True
    Anything else -> False
    """
    value = value.lower()
    if value in ('y', 'yes', 't', 'true', '1'):
        return True
    else:
        return False

def shellquote(s):
    """
    Quote a string so it appears as a single argument
    on the shell command line.
    """
    return "'" + s.replace("'", "'\\''") + "'"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH client test.")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable all debugging.")
    parser.add_argument(
        "--debug-ssh",
        action="store_true",
        help="Enable SSH debugging.")
    parser.add_argument(
        "-u",
        "--user",
        action="store",
        help="Remote user.")
    parser.add_argument(
        "-H",
        "--host",
        action="store",
        help="Remote host.")
    parser.add_argument(
        "-c",
        "--command",
        action="store",
        help="Remote command.")
    args = parser.parse_args()
    main(args)


