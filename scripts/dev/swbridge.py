#!/usr/bin/env python3
''' relay packets between the AP and BP interfaces'''
import selectors
import socket


def socket_copy(local, remote):
    ''' Copy content from local to remote socket '''
    rilproxy_buffer_size = 3000  # TODO 3000 is not a power of 2
    bytes_read = local.recv(rilproxy_buffer_size)
    local_name = local.getsockname()[0]
    remote_name = remote.getsockname()[0]

    if len(bytes_read) < 0:
        raise RuntimeError('[{} -> {}] error reading {} socket'.format(
            local_name, remote_name, local_name))

    bytes_written = remote.send(bytes_read)

    if bytes_written < 1:
        raise RuntimeError('[{} -> {}] socket connection broken'.format(
            local_name, remote_name))
    if bytes_written < len(bytes_read):
        raise RuntimeError('[{} -> {}] read {} bytes, wrote {} bytes'.format(
            local_name, remote_name, len(bytes_read), bytes_written))
    print('[{} -> {}] {}'.format(
        local_name, remote_name, bytes_read))


# Open sockets
# NOTE capabilities would need to be set on python binary.. or be ambient
ETH_P_ALL = 0x0003
local = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.htons(ETH_P_ALL))
remote = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(ETH_P_ALL))

local.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                 1)
local.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                 str('ril0' + '\0').encode('utf-8'))
local.bind(('ril0', 0))
remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                  1)
remote.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                  str('enp0s29u1u4' + '\0').encode('utf-8'))
remote.bind(('enp0s29u1u4', 0))

# Proxy it
sel = selectors.DefaultSelector()

sel.register(local, selectors.EVENT_READ)
sel.register(remote, selectors.EVENT_READ)
while True:
    print('...')
    events = sel.select()
    for key, mask in events:
        if key.fileobj is local:
            socket_copy(local, remote)
        else:
            socket_copy(remote, local)

# Close sockets
local.close()
remote.close()
