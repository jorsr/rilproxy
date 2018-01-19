#!/usr/bin/env python3
''' relay packets between the AP and BP interfaces'''
import selectors
import socket
from ril_h import ERRNO, REQUEST, UNSOL


# TODO should token be hex?
# TODO make data mandatory
ETH_P_ALL = 0x0003
RILPROXY_PORT = 18912
UDP = 17


class RilMessage(object):
    '''General RIL Message.
    All share data and length fields
    '''
    def __init__(self, length):
        self.length = length


class RilRequest(RilMessage):
    '''A RIL Request.
    The fields are:
     * Length
     * Command
     * Token
     * Data
    '''
    def __init__(self, command, length, token):
        self.command = command
        self.token = token
        super().__init__(length)


class RilReply(RilMessage):
    '''A RIL Reply.
    The fields are:
     * Length
     * M_Type (always 0)
     * Token
     * Error
     * Data
    Command is not in the actual message
    '''
    def __init__(self, command, error, length, reply_to, token):
        self.command = command
        self.error = error
        self.token = token
        reply_to = reply_to
        super().__init__(length)


class RilUnsolicitedResponse(RilMessage):
    '''A RIL Unsolicited Response.
    The fields are:
     * Length
     * M_Type (always 1)
     * Command
     * Data
    '''
    def __init__(self, command, length):
        self.command = command
        super().__init__(length)


def maybe_unknown(dictionary, value):
    '''Return "unknown" for NULL values'''
    if value in dictionary.keys():
        return dictionary[value]
    return str(value) + ' is unknown'


def validate(ril_msg):
    ''' Run through verifier '''
    pass


class Dissector(object):
    '''Dissects RIL Packets and is able to validate them.
    Based on the Lua Wireshark dissector by Componolit and merged with my own
    validator.
    '''
    # Constants
    REQUEST_SETUP = 0xc715
    REQUEST_TEARDOWN = 0xc717
    M_TYPE_REPLY = 0
    M_TYPE_UNSOL = 1

    # Globals
    bytes_missing = 0
    cache = bytearray()  # from last run (if all packets get sent in order)
    last_token = 0  # from possibly further away
    request_num = 0  # from possibly further away
    requests = {}  # from further away
    pending_requests = {}  # from further away
    packet_num = 0

    def dissect(self, bfr, source):
        '''Dissect the RIL packets and return a RIL message object.'''
        msg_len = len(bfr) * 8  # from bytes to bits
        print('DEBUG buffer length (raw):', msg_len)
        self.packet_num += 1

        # Follow-up to a message where length header indicates more bytes than
        # available in the message.
        if self.bytes_missing > 0:
            self.cache = b''.join([self.cache, bfr])
            self.bytes_missing = self.bytes_missing - msg_len

            # Still fragments missing, wait for next packet
            if self.bytes_missing > 0:
                return None

            bfr = self.cache
            self.cache = bytearray()

        # Advance request counter
        self.request_num = self.request_num + 1

        # TODO is this the correct place?
        print('DEBUG buffer length (reassembled)', msg_len)

        # Message must be at least 4 bytes
        if msg_len < 4:
            print('WARNING [' + self.packet_num +
                  '] Dropping short buffer of length', msg_len)

            return None

        header_len = int.from_bytes(bfr[0:4], byteorder='big')

        if header_len < 4:
            print('WARNING [{}] Dropping short header length of {}'.format(
                self.packet_num, header_len))

            return None

        #  FIXME: Upper limit?
        if header_len > 3000:
            print('WARNING [{}] Skipping long buffer of length {}'.format(
                self.packet_num, header_len))
            self.bytes_missing = 0
            self.cache = bytearray()

            return None
        if msg_len <= (header_len - 4):
            self.bytes_missing = header_len - msg_len + 4
            b''.join([self.cache, bfr])

            return None
        self.cache = bytearray()

        self.bytes_missing = 0
        command_or_type = int.from_bytes(bfr[4:8], byteorder='little')

        if (source == 'ril0'):
            # TODO Why are there unknown commands?
            print('DEBUG RIL REQUEST PACKET')
            print('DEBUG  length: ', header_len)
            print('DEBUG  command:', maybe_unknown(REQUEST, command_or_type))
            if (header_len > 4):
                token = int.from_bytes(bfr[8:12], byteorder='little')

                print('DEBUG  token:  ', token)

                ril_msg = RilRequest(command_or_type, header_len, token)
                self.requests[ril_msg.token] = {
                    'command': ril_msg.command,
                    'request_num': self.request_num
                }
                self.pending_requests[ril_msg.token] = 1

                if ril_msg.token - self.last_token > 0:
                    print('DEBUG token delta', ril_msg.token -
                          self.last_token)

                self.last_token = ril_msg.token

                # TODO handle data
                # if (header_len > 8):
                #    dissector:call(bfr[12, header_len - 12 + 4]:tvb(), info,
                #    subtree)

                return ril_msg
        elif source == 'enp0s29u1u4':
            # TODO Why is type sometimes 4?
            m_type = int.from_bytes(bfr[4:8], byteorder='little')

            if (m_type == self.M_TYPE_REPLY):
                print('DEBUG RIL REPLY PACKET')
                print('DEBUG  length: ', header_len)
                print('DEBUG  type:   OnRequestComplete')

                token = int.from_bytes(bfr[8:12], byteorder='little')
                print('DEBUG  token:  ', token)

                error = int.from_bytes(bfr[12:16], byteorder='little')

                print('DEBUG  error:  ', maybe_unknown(ERRNO, error))

                request = self.requests[token]
                request_delta = self.request_num - request['request_num']

                del self.pending_requests[token]

                ril_msg = RilReply(error, request['command'], header_len,
                                   request['request_num'], token)

                print('DEBUG  command:',
                      maybe_unknown(REQUEST, ril_msg.command))
                print('DEBUG packets until reply', request_delta)

                # TODO handle data
                # if (header_len > 12):
                #   dissector:call(bfr(16, header_len - 16 + 4):tvb(), info,
                #   subtree)

                return ril_msg
            elif (m_type == self.M_TYPE_UNSOL):
                print('DEBUG RIL UNSOL PACKET')
                print('DEBUG  length: ', header_len)
                print('DEBUG  type:   OnUnsolicitedResponse')

                command = int.from_bytes(bfr[8:14], byteorder='little')

                print('DEBUG  command:', maybe_unknown(UNSOL, ril_msg.command))

                ril_msg = RilUnsolicitedResponse(command, header_len)

                # TODO handle data
                # if (header_len > 8):
                #     dissector:call(bfr(12, header_len - 12 + 4):tvb(), info,
                #     subtree)

                return ril_msg
            else:
                print('WARNING wrong packet type', m_type)
        else:
            print('WARNING invalid direction')
        print('In-flight requests', len(self.pending_requests))

        # If data is left in buffer, run dissector on it
        if msg_len > header_len + 4:
            # TODO Handle
            print('WARNING data left in buffer')


def socket_copy(dissector, local, remote):
    ''' Copy content from to remote socket '''
    # TODO option for verbose output
    rilproxy_buffer_size = 3000  # TODO 3000 is not a power of 2
    bytes_read = local.recv(rilproxy_buffer_size)
    local_name = local.getsockname()[0]
    remote_name = remote.getsockname()[0]

    if len(bytes_read) < 0:
        raise RuntimeError('[{} -> {}] error reading {} socket'.format(
            local_name, remote_name, local_name))

    # debug output for ehternet header
    # ethernet_header = bytes_read[0:14]
    # ethernet_destination = ':'.join('%02x' % x for x in ethernet_header[0:6])
    # ethernet_source = ':'.join('%02x' % x for x in ethernet_header[6:12])
    # ethertype = int.from_bytes(ethernet_header[12:14], byteorder='big')

    # print('VERBOSE ETHERNET HEADER')
    # print('VERBOSE  destination MAC:', ethernet_destination)
    # print('VERBOSE  source MAC:     ', ethernet_source)
    # print('VERBOSE  EtherType:      ', ethertype)

    # debug output for IP Header
    ip_header = bytes_read[14:34]
    ip_protocol = ip_header[9]

    # print('VERBOSE IP HEADER')
    # print('VERBOSE  time to live:  ', ip_header[8])
    # print('VERBOSE  protocol:      ', ip_protocol)
    # print('VERBOSE  checksum:      ', ip_header[10:12])
    # print('VERBOSE  source IP:     ', socket.inet_ntoa(ip_header[12:16]))
    # print('VERBOSE  destination IP:', socket.inet_ntoa(ip_header[16:20]))
    if ip_protocol == UDP:
        # debug output for UDP Header
        udp_header = bytes_read[34:42]
        udp_source = int.from_bytes(udp_header[0:2], byteorder='big')
        udp_destination = int.from_bytes(udp_header[2:4], byteorder='big')

        print('VERBOSE UDP HEADER')
        print('VERBOSE  source port:     ', udp_source)
        print('VERBOSE  destination port:', udp_destination)
        # print('VERBOSE  length:          ',
        #       int.from_bytes(udp_header[4:6], byteorder='big'))
        # print('VERBOSE  checksum:        ', udp_header[6:8])

        if udp_source == RILPROXY_PORT:
            # print('VERBOSE MISC')
            # print('VERBOSE  packet size:', len(bytes_read))

            # remove headers
            udp_payload = bytes_read[42:]

            print('VERBOSE [{} -> {}] {}'.format(
                local_name, remote_name, udp_payload))

            # dissect the UDP payload
            ril_msg = dissector.dissect(udp_payload, local_name)

            if ril_msg:
                if validate(ril_msg):
                    bytes_written = remote.send(bytes_read)
            else:  # TODO wait before sending concatenated package
                print('Continuing: Payload was boring')
                bytes_written = remote.send(bytes_read)
        else:
            print('Continuing:', udp_source, 'is incorrect port')
        bytes_written = remote.send(bytes_read)
    else:
        print('Continuing:', ip_protocol, 'is not UDP')

        bytes_written = remote.send(bytes_read)
    if bytes_written < 1:
        raise RuntimeError('[{} -> {}] socket connection broken'.format(
            local_name, remote_name))
    if bytes_written < len(bytes_read):
        raise RuntimeError('[{} -> {}] read {} bytes, wrote {} bytes'.format(
            local_name, remote_name, len(bytes_read), bytes_written))


def main():
    '''Create sockets. Proxy all packets and validate RIL packets.'''
    # Open sockets
    local = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
    remote = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(ETH_P_ALL))

    local.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                     1)
    local.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                     str('ril0' + '\0').encode('utf-8'))
    local.bind(('ril0', 0))  # TODO maybe use the correct port here?
    remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                      1)
    remote.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                      str('enp0s29u1u4' + '\0').encode('utf-8'))
    remote.bind(('enp0s29u1u4', 0))

    # Proxy it
    sel = selectors.DefaultSelector()
    dissector = Dissector()

    sel.register(local, selectors.EVENT_READ)
    sel.register(remote, selectors.EVENT_READ)
    while True:
        print('...')
        events = sel.select()
        for key, mask in events:
            if key.fileobj is local:
                socket_copy(dissector, local, remote)
            else:
                socket_copy(dissector, remote, local)

    # Close sockets
    local.close()
    remote.close()


if __name__ == '__main__':
    main()
