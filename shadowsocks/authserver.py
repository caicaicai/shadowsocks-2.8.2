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

# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

MSG_FASTOPEN = 0x20000000

# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# for each opening port, we have a TCP Relay

# for each connection, we have a TCP Relay Handler to handle the connection

# for each handler, we have 2 sockets:
#    local:   connected to the client
#    remote:  connected to remote server

# for each handler, it could be at one of several stages:

# as sslocal:
# stage 0 SOCKS hello received from local, send hello to local
# stage 1 addr received from local, query DNS for remote
# stage 2 UDP assoc
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

# as ssserver:
# stage 0 just jump to stage 1
# stage 1 addr received from local, query DNS for remote
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024


class TCPRelayHandler(object):
    def __init__(self, server, fd_to_handlers, loop, local_sock):
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._stage = STAGE_INIT
        self._data_to_write_to_local = 'hahahaha\n'


        self._client_address = local_sock.getpeername()[:2]
        self._remote_address = None

        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR,
                 self._server)

    def __hash__(self):
        # default __hash__ is id / 16
        # we want to eliminate collisions
        return id(self)

    @property
    def remote_address(self):
        return self._remote_address

    def _make_auth(self, data):
        try:
            f_data = json.JSONDecoder().decode(data)
            if f_data['username']:

                #auth stuff
                encrypt_code = ''.join([random.choice('AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789') for i in range(40)])
                auth_info = {}
                auth_info['s'] = 1
                auth_info['code'] = encrypt_code
                auth_info['id'] = hashlib.md5(encrypt_code).hexdigest()
                auth_info['username'] = f_data['username']
                auth_info['addr'] = self._server.server_addr
                auth_info['port'] = self._server.server_port
                print('auth success: ' + auth_info['username'])
                self._server.add_online_user(auth_info)

                return json.JSONEncoder().encode(auth_info)
            else:
                return return json.JSONEncoder().encode({'s':0})
        except Exception as e:
            print(e)
        	return json.JSONEncoder().encode({'s':0})

    def _update_stream(self, stream, status):
        # update a stream to a new waiting status

        if stream == STREAM_DOWN:
            self._loop.modify(self._local_sock, eventloop.POLL_OUT)


    def _write_to_sock(self, data, sock):
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                            errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        #self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)

        return True

    def _handle_stage_connecting(self, data):
        self._data_to_write_to_remote.append(data)

    def _on_local_read(self):
        # handle all local read events and dispatch them to methods for
        # each stage
        if not self._local_sock:
            return
        data = None
        try:
            data = self._local_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._data_to_write_to_local = self._make_auth(data)
        self._on_local_write()

    def _on_local_write(self):
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            #self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)

    def _on_local_error(self):
        logging.debug('got local error')
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
        self.destroy()



    def handle_event(self, sock, event):
        # handle all events in this handler and dispatch them to methods
        # order is important

        if event & eventloop.POLL_ERR:
            self._on_local_error()

        if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
            self._on_local_read()



    def _log_error(self, e):
        logging.error('%s when handling connection from %s:%d' %
                      (e, self._client_address[0], self._client_address[1]))

    def destroy(self):
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED

        logging.debug('destroy')

        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._server.remove_handler(self)


class TCPRelay(object):
    def __init__(self, config):
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}

        self._timeout = 15
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        listen_addr = '0.0.0.0'
        listen_port = 3721
        self._listen_port = listen_port

        addrs = socket.getaddrinfo(listen_addr, listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (listen_addr, listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        server_socket.listen(1024)
        self._server_socket = server_socket
        self._online_user = {}
        self.server_addr = config['server']
        self.server_port = config['server_port']

    def add_online_user(self, auth_info):
        #同一账户多次登陆
        for _id in self._online_user:
            if self._online_user[_id]['username'] == auth_info['username']:
                print(u'relogin: ' + auth_info['username'])
                self.remove_online_user(_id)
                break
        self._online_user[auth_info['id']] = auth_info

    def remove_online_user(self, _id):
        del self._online_user[_id]

    def get_encrypt_code_by_id(self, _id):
        if self._online_user.has_key(_id):
            # delete is O(n), so we just set it to None
            return self._online_user[_id]['code']
        else:
            print("get encrypt failed for" + _id)
            return None
    
    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._eventloop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler, data_len):
        if data_len and self._stat_callback:
            self._stat_callback(self._listen_port, data_len)

        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            logging.log(shell.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler.remote_address:
                            logging.warn('timed out: %s:%d' %
                                         handler.remote_address)
                        else:
                            logging.warn('timed out')
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def handle_event(self, sock, fd, event):
        # handle events and dispatch to handlers
        if sock:
            logging.log(shell.VERBOSE_LEVEL, 'fd %d %s', fd,
                        eventloop.EVENT_NAMES.get(event, event))
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                # TODO
                raise Exception('server_socket error')
            try:
                logging.debug('accept')
                conn = self._server_socket.accept()
                TCPRelayHandler(self, self._fd_to_handlers,
                                self._eventloop, conn[0])
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, event)
            else:
                logging.warn('poll removed fd')

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._eventloop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP port %d', self._listen_port)
            if not self._fd_to_handlers:
                logging.info('stopping')
                self._eventloop.stop()
        self._sweep_timeout()

    def close(self, next_tick=False):
        logging.debug('TCP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for handler in list(self._fd_to_handlers.values()):
                handler.destroy()
