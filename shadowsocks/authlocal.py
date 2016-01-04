#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import errno
import struct
import logging
import traceback
import random
import json
import hashlib

from shadowsocks import encrypt, eventloop, shell, common
from shadowsocks.common import parse_header

BUF_SIZE = 32 * 1024


class AuthModel(object):
    def __init__(self):

        self._server_socket = None
        self._server_addr = '127.0.0.1'
        self._server_port = 3721
        self._auth_info = None

        self._online_user = {}

    def _create_remote_socket(self):
        addrs = socket.getaddrinfo(self._server_addr, self._server_port, 0, socket.SOCK_STREAM,
                                   socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]

        remote_sock = socket.socket(af, socktype, proto)
        self._server_socket = remote_sock
        #remote_sock.setblocking(False)
        #remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        remote_sock.connect(sa)

    def make_auth(self):
        if not self._server_socket:
            self._create_remote_socket()
        if self._server_socket:
            print("start to auth")

            self._server_socket.send(b'{"username":"xiaocai","passwd":"520"}')
            try:
                data = self._server_socket.recv(BUF_SIZE)

            except (OSError, IOError) as e:
                print("make_auth_err: " + e)

            if data:
                self._auth_info = json.JSONDecoder().decode(data.decode("utf-8"))
            print("code: " + self._auth_info['code'])
            print("id: " + self._auth_info['id'])
        else:
            print("can not connect to the auth server")
        self.close()
    def get_code(self):
        if self._auth_info:
            return self._auth_info['code']
        else:
            None
    def get_id(self):
        if self._auth_info:
            return self._auth_info['id'].encode()
        else:
            None

    def close(self):
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
        else:
            print("no need to close auth socket")


