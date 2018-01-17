#!/usr/bin/env python3
''' relay packets between the AP and BP interfaces'''
import selectors
import socket
from .ril_h import ERRNO, REQUEST, UNSOL


REQUEST_SETUP = 0xc715
REQUEST_TEARDOWN = 0xc717
MTYPE_REPLY = 0
MTYPE_UNSOL = 1

bytes_missing = 0
cache = bytearray()
last_token = 0
request_num = 0
packet_num = 0
sub_dissector = False
requests = {}
pending_requests = {}


# TODO should token be hex?
# TODO make data mandatory

class RilMessage(object):
    def __init__(self, length):
        self.length = length


class RilRequest(RilMessage):
    def __init__(self, command, length, token):
        self.command = command
        self.token = token
        super().__init__(length)


class RilReply(RilMessage):
    ''' m_type is always 0. Command is not in message. '''
    def __init__(self, command, error, length, reply_to, token):
        self.command = command
        self.error = error
        self.token = token
        reply_to = reply_to
        super().__init__(length)


class RilUnsolicitedResponse(RilMessage):
    ''' m_type is always 1 '''
    def __init__(self, command, length):
        self.command = command
        super().__init__(length)


def disect_n_filter(bfr, source):
    # TODO remove some global variables
    global bytes_missing, cache, last_token, packet_num, request_num
    global sub_dissector, requests, pending_requests

    print("buffer length (raw):", len(bfr))
    packet_num += 1

    # Follow-up to a message where length header indicates more bytes than
    # available in the message.
    if bytes_missing > 0:
        cache = b''.join([cache, bfr])
        bytes_missing = bytes_missing - len(bfr)

        # Still fragments missing, wait for next packet
        if bytes_missing > 0:
            return

        bfr = cache
        cache.clear()

    # Advance request counter
    request_num = request_num + 1

    msg_len = len(bfr)

    # TODO is this the correct place?
    print("buffer length (reassembled)", msg_len)

    # Message must be at least 4 bytes
    if msg_len < 4:
        print("[" + packet_num + "] Dropping short buffer of length", msg_len)

        return

    header_len = int.from_bytes(bfr[0:3], byteorder='little')

    print("Header length (raw)", header_len)
    if header_len < 4:
        print("[{}] Dropping short header length of {}".format(
            packet_num, header_len))

        return

    #  FIXME: Upper limit?
    if header_len > 3000:
        print("[{}] Skipping long buffer of length {}".format(
            packet_num, header_len))
        bytes_missing = 0
        cache.clear()

        return
    print("Header length", header_len)
    if msg_len <= (header_len - 4):
        bytes_missing = header_len - msg_len + 4
        b''.join([cache, bfr])

        return
    cache.clear()

    bytes_missing = 0
    command_or_type = int.from_bytes(bfr[4:7], byteorder='little')

    if (source == 'ril0'):
        if (header_len > 4):
            token = int.from_bytes(bfr[8:11], byteorder='little')
            ril_msg = RilRequest(command_or_type, header_len, token)

            print("REQUEST(" + maybe_unknown(REQUEST[ril_msg.command]) + ")")

            requests[ril_msg.token] = {'command': ril_msg.command,
                                       'request_num': request_num}
            pending_requests[ril_msg.token] = 1

            if ril_msg.token - last_token > 0:
                print("Token delta", ril_msg.token - last_token)

            last_token = ril_msg.token
        # TODO handle data
        # if (header_len > 8):
        #    dissector:call(bfr[12, header_len - 12 + 4]:tvb(), info,
        #    subtree)
    elif source == 'enp0s29u1u4':
        m_type = int.from_bytes(bfr[4:7], 'little')

        if (m_type == MTYPE_REPLY):
            token = int.from_bytes(bfr[8:11])
            error = int.from_bytes(bfr[12:15])
            request = requests[ril_msg.token]
            request_delta = request_num - request.request_num

            del pending_requests[ril_msg.token]

            print("Debug: Packets until reply", request_delta)

            ril_msg = RilReply(error, request.command, header_len,
                               request.request_num, token)

            print("REPLY(" + maybe_unknown(REQUEST[ril_msg.command]) + ") [" +
                  ril_msg.token + "] = " + maybe_unknown(ERRNO[ril_msg.error]))
            # TODO handle data
            # if (header_len > 12):
            #   dissector:call(bfr(16, header_len - 16 + 4):tvb(), info,
            #   subtree)
        elif (ril_msg.m_type == MTYPE_UNSOL):
            command = int.from_bytes(bfr[8:13], byteorder='little')
            ril_msg = RilUnsolicitedResponse(command, header_len)

            print("UNSOL(" + maybe_unknown(UNSOL[ril_msg.command]) + ")")
            # TODO handle data
            # if (header_len > 8):
            #     dissector:call(bfr(12, header_len - 12 + 4):tvb(), info,
            #     subtree)
        else:
            print("Warning: UNKNOWN REPLY")
    else:
        print("Warning: INVALID DIRECTION")
    print("In-flight requests", len(pending_requests))

    # If data is left in buffer, run dissector on it
    if msg_len > header_len + 4:
        # TODO Handle
        print('Warning: Data left in buffer')


def maybe_unknown(value):
    if value is not None:
        return value.lower()
    return "unknown"


def socket_copy(local, remote):
    ''' Copy content from to remote socket '''
    rilproxy_buffer_size = 3000  # TODO 3000 is not a power of 2
    bytes_read = local.recv(rilproxy_buffer_size)
    local_name = local.getsockname()[0]
    remote_name = remote.getsockname()[0]

    if len(bytes_read) < 0:
        raise RuntimeError('[{} -> {}] error reading {} socket'.format(
            local_name, remote_name, local_name))

    bytes_read = disect_n_filter(bytes_read, local_name)

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
# NOTE capabilities would need to be set on python binary+ or be ambient
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
