#!/usr/bin/env python3
''' relay packets between the AP and BP interfaces'''
from validator import validate
from dissector import Dissector

from logging import basicConfig, debug, info, DEBUG
import selectors
import socket


# TODO make data mandatory
ETH_P_ALL = 0x0003
RILPROXY_PORT = 18912
UDP = 17
FMT_NUM = '%s: %s'
FMT_PKT = ' %s:\t%s'
FMT_NONE = '%s'


def socket_copy(dissector, local, remote, verbose=False):
    ''' Copy content from to remote socket '''
    # TODO option for debug output
    rilproxy_buffer_size = 3000  # TODO 3000 is not a power of 2
    bytes_read = local.recv(rilproxy_buffer_size)
    local_name = local.getsockname()[0]
    remote_name = remote.getsockname()[0]

    if len(bytes_read) < 0:
        raise RuntimeError('[{} -> {}] error reading {} socket'.format(
            local_name, remote_name, local_name))

    # debug output for ehternet header
    ethernet_header = bytes_read[0:14]
    ethernet_destination = ':'.join('%02x' % x for x in ethernet_header[0:6])
    ethernet_source = ':'.join('%02x' % x for x in ethernet_header[6:12])
    ethertype = int.from_bytes(ethernet_header[12:14], byteorder='big')

    if verbose:
        debug('ETHERNET HEADER')
        debug(FMT_PKT, 'destination MAC', ethernet_destination)
        debug(FMT_PKT, 'source MAC', ethernet_source)
        debug(FMT_PKT, 'EtherType', ethertype)

    # debug output for IP Header
    ip_header = bytes_read[14:34]
    ip_protocol = ip_header[9]

    if verbose:
        debug('IP HEADER')
        debug(FMT_PKT, ' time to live', ip_header[8])
        debug(FMT_PKT, ' protocol', ip_protocol)
        debug(FMT_PKT, ' checksum', ip_header[10:12])
        debug(FMT_PKT, ' source IP', socket.inet_ntoa(ip_header[12:16]))
        debug(FMT_PKT, ' destination IP', socket.inet_ntoa(ip_header[16:20]))
    if ip_protocol == UDP:
        # debug output for UDP Header
        udp_header = bytes_read[34:42]
        udp_source = int.from_bytes(udp_header[0:2], byteorder='big')

        if verbose:
            udp_destination = int.from_bytes(udp_header[2:4], byteorder='big')

            debug('UDP HEADER')
            debug(FMT_PKT, 'source port', udp_source)
            debug(FMT_PKT, 'destination port', udp_destination)
            debug(FMT_PKT, 'length',
                  int.from_bytes(udp_header[4:6], byteorder='big'))
            debug(FMT_PKT, 'checksum', udp_header[6:8])

        if udp_source == RILPROXY_PORT:
            if verbose:
                debug('packet size:', len(bytes_read))

            # remove headers
            udp_payload = bytes_read[42:]

            debug('[{} -> {}] {}'.format(
                local_name, remote_name, udp_payload))

            # dissect the UDP payload
            ril_msgs = dissector.dissect(udp_payload, local_name)

            for ril_msg in ril_msgs:
                if validate(ril_msg):
                    bytes_written = remote.send(bytes_read)
                else:
                    msg = '[{} -> {}] unnacceptable parcel {}'.format(
                        local_name, remote_name, ril_msg)
                    raise RuntimeError(msg)
            if ril_msgs == []:  # TODO wait before sending concatenated package
                info('Continuing: payload was boring')
                bytes_written = remote.send(bytes_read)
        else:
            info('Continuing: %s is incorrect port', udp_source)
        bytes_written = remote.send(bytes_read)
    else:
        info('Continuing: %s is not UDP', ip_protocol)

        bytes_written = remote.send(bytes_read)
    if bytes_written < 1:
        raise RuntimeError('[{} -> {}] socket connection broken'.format(
            local_name, remote_name))
    if bytes_written < len(bytes_read):
        raise RuntimeError('[{} -> {}] read {} bytes, wrote {} bytes'.format(
            local_name, remote_name, len(bytes_read), bytes_written))


def main():
    '''Create sockets. Proxy all packets and validate RIL packets.'''

    # Init logger
    basicConfig(format='%(levelname)s %(message)s', level=DEBUG)

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
        info('...')
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
