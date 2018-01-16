#!/usr/bin/env python3
''' relay packets between the AP and BP interfaces'''
import selectors
import socket
from .ril_h import REQUEST


REQUEST_SETUP = 0xc715
REQUEST_TEARDOWN = 0xc717
bytes_missing = 0
cache = bytearray()
request_num = 0
packet_num = 0
sub_dissector = False


def disect_n_filter(bfr, direction):
    global bytes_missing, cache, packet_num, request_num, sub_dissector

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

    bfr_len = len(bfr)

    # TODO is this the correct place?
    print("bfr length (reassembled)", bfr_len)

    # Message must be at least 4 bytes
    if bfr_len < 4:
        print("[" + packet_num + "] Dropping short buffer of length", bfr_len)
        return 0

    header_len = int.from_bytes(bfr[0:3], byteorder='little')

    print("Header length (raw)", header_len)

    if header_len < 4:
        print("[" + packet_num + "] Dropping short header len of", header_len)
        return 0

    #  FIXME: Upper limit?
    if header_len > 3000:
        print("[" + packet_num + "] Skipping long bfr of length", header_len)
        bytes_missing = 0
        cache.clear()
        return 0

    print("Header length", header_len)

    if bfr_len <= (header_len - 4):
        bytes_missing = header_len - bfr_len + 4
        b''.join([cache, bfr])
        return

    cache.clear()
    bytes_missing = 0

    rid = int.from_bytes(bfr[4:7], byteorder='little')
    # TODO
    # if (rid == REQUEST_SETUP):
    #    ap_ip = tostring(src_ip_addr_f())
    #    bp_ip = tostring(dst_ip_addr_f())

    # TODO
    # if sub_dissector:
    #     info.cols.info:append (", ")
    # else:
    #     info.cols.info = DirectionLabel[direction()] + " "

    # TODO info.cols.protocol = 'RILProxy'

    if (direction == 'from AP'):
        # Request
        message = "REQUEST(" + maybe_unknown(REQUEST[rid]) + ")"
        info.cols.info:append(message)
        subtree = add_default_fields(tree, message, bfr(0,-1), header_len + 4)
        subtree:add_le(rilproxy.fields.request, bfr(4,4))
        if (header_len > 4):
            token = int.from_bytes(bfr[8:11], byteorder='little')
            info.cols.info:append(" [" + token + "]")
            frames[token] = packet_num
            requests[token] = { 'rid': rid, 'request_num': request_num }
            pending_requests[token] = 1
            subtree:add_le(rilproxy.fields.token, bfr(8,4))

            if token - last_token > 0:
                print("Token delta", token - last_token)
            last_token = token
        if (header_len > 8):
            dissector = query_dissector("rild.request." + maybe_unknown(REQUEST[rid]))
            # TODO dissector:call(bfr[12, header_len - 12 + 4]:tvb(), info, subtree)
    elif direction() == DIR_FROM_BP:
        mtype = int.from_bytes(bfr[4:7], 'little')
        if (mtype == MTYPE_REPLY):
            result = int.from_bytes(bfr[12:15])
            token = int.from_bytes(bfr[8:11])
            request = requests[token]
            request_delta = request_num - request.request_num

            pending_requests[token] = nil
            print("Packets until reply", request_delta)

            message = "REPLY(" + maybe_unknown(REQUEST[request.rid]) +") [" + token + "] = " + maybe_unknown(ERRNO[result])
            info.cols.info:append(message)
            subtree = add_default_fields(tree, message, bfr, header_len + 4)
            subtree:add_le(rilproxy.fields.mtype, bfr(4,4))
            subtree:add_le(rilproxy.fields.token, bfr(8,4))
            if frames[token] is None:
                subtree:add(rilproxy.fields.reply, frames[token])
            subtree:add_le(rilproxy.fields.result, bfr(12,4))
            if (header_len > 12):
                dissector = query_dissector("rild.reply." + maybe_unknown(REQUEST[request.rid]))
                # TODO dissector:call(bfr(16, header_len - 16 + 4):tvb(), info, subtree)
        elif (mtype == MTYPE_UNSOL):
            event = int.from_bytes(bfr[8:13], byteorder='little')
            message = "UNSOL(" + maybe_unknown(UNSOL[event]) + ")"
            info.cols.info:append(message)
            subtree = add_default_fields(tree, message, bfr, header_len + 4)
            subtree:add_le(rilproxy.fields.mtype, bfr(4,4))
            subtree:add_le(rilproxy.fields.event, bfr(8,4))
            if (header_len > 8):
                dissector = query_dissector("rild.unsol." + UNSOL[event])
                # TODO dissector:call(bfr(12, header_len - 12 + 4):tvb(), info, subtree)
        else:
            info.cols.info:append("UNKNOWN REPLY")
    else:
        info.cols.info:append("INVALID DIRECTION")

    print("In-flight requests", count_table (pending_requests))

    # If data is left in bfr, run dissector on it
    if bfr_len > header_len + 4:
        previous = sub_dissector
        sub_dissector = true
        # TODO rilproxy.dissector(bfr:range(header_len + 4, -1):tvb(), info, tree)
        sub_dissector = previous


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

    bytes_read = disect_n_filter(bytes_read)

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
