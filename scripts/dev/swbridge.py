#!/usr/bin/env python3
''' relay packets between the AP and BP interfaces'''
from validator import validate
from dissector import Dissector

from argparse import ArgumentParser
from selectors import DefaultSelector, EVENT_READ
import logging as lg
import socket as sc


ETH_P_ALL = 0x0003
RILPROXY_PORT = 18912
RILPROXY_BUFFER_SIZE = 3000  # TODO 3000 is not a power of 2
UDP = 17
FMT_NUM = '%s: %s'
FMT_PKT = ' %s:\t%s'
FMT_NONE = '%s'


def filter_bytes(dissector, bytes_read, local_name, remote, verbose):
    remote_name = remote.getsockname()[0]

    # debug output for ehternet header
    ethernet_header = bytes_read[0:14]
    ethernet_destination = ':'.join('%02x' % x for x in ethernet_header[0:6])
    ethernet_source = ':'.join('%02x' % x for x in ethernet_header[6:12])
    ethertype = int.from_bytes(ethernet_header[12:14], byteorder='big')

    if verbose:
        lg.debug('ETHERNET HEADER')
        lg.debug(FMT_PKT, 'destination MAC', ethernet_destination)
        lg.debug(FMT_PKT, 'source MAC', ethernet_source)
        lg.debug(FMT_PKT, 'EtherType', ethertype)

    # debug output for IP Header
    ip_header = bytes_read[14:34]
    ip_protocol = ip_header[9]

    if verbose:
        lg.debug('IP HEADER')
        lg.debug(FMT_PKT, ' time to live', ip_header[8])
        lg.debug(FMT_PKT, ' protocol', ip_protocol)
        lg.debug(FMT_PKT, ' checksum', ip_header[10:12])
        lg.debug(FMT_PKT, ' source IP', sc.inet_ntoa(ip_header[12:16]))
        lg.debug(FMT_PKT, ' destination IP', sc.inet_ntoa(ip_header[16:20]))
    if ip_protocol == UDP:
        # debug output for UDP Header
        udp_header = bytes_read[34:42]
        udp_source = int.from_bytes(udp_header[0:2], byteorder='big')

        if verbose:
            udp_destination = int.from_bytes(udp_header[2:4], byteorder='big')

            lg.debug('UDP HEADER')
            lg.debug(FMT_PKT, 'source port', udp_source)
            lg.debug(FMT_PKT, 'destination port', udp_destination)
            lg.debug(FMT_PKT, 'length',
                     int.from_bytes(udp_header[4:6], byteorder='big'))
            lg.debug(FMT_PKT, 'checksum', udp_header[6:8])
        if udp_source == RILPROXY_PORT:  # probably dest should also be checked
            if verbose:
                lg.debug('packet size:', len(bytes_read))

            # remove headers
            udp_payload = bytes_read[42:]

            lg.debug('[{} -> {}] {}'.format(
                local_name, remote_name, udp_payload))

            # dissect the UDP payload
            ril_msgs = dissector.dissect(udp_payload, local_name)

            if ril_msgs == []:  # TODO wait before sending concatenated package
                lg.info('Dropping: payload was boring')

                return bytes_read  # TODO return None
            for ril_msg in ril_msgs:
                if not validate(ril_msg):
                    msg = '[{} -> {}] unnacceptable parcel {}'.format(
                        local_name, remote_name, ril_msg)

                    raise RuntimeError(msg)

            # In case a concatenated parcel is invalid we already stop
            return bytes_read
        else:
            lg.info('Dropping: %s is incorrect port', udp_source)

            return bytes_read  # TODO return none
    else:
        lg.info('Dropping: %s is not UDP', ip_protocol)

        return bytes_read  # TODO return None


def socket_copy(dissector, local, remote, verbose=False):
    ''' Copy content from local to remote socket '''
    bytes_read = local.recv(RILPROXY_BUFFER_SIZE)
    local_name = local.getsockname()[0]
    remote_name = remote.getsockname()[0]

    if len(bytes_read) < 0:
        raise RuntimeError('[{} -> {}] error reading {} socket'.format(
            local_name, remote_name, local_name))
    if dissector:
        filtered_bytes = filter_bytes(dissector, bytes_read, local_name,
                                      remote, verbose)
        if filtered_bytes:
            bytes_written = remote.send(filtered_bytes)
    else:
        lg.debug('[{} -> {}] {}'.format(local_name, remote_name, bytes_read))

        bytes_written = remote.send(bytes_read)
    if bytes_written < 1:
        raise RuntimeError('[{} -> {}] socket connection broken'.format(
            local_name, remote_name))
    if bytes_written < len(bytes_read):
        raise RuntimeError('[{} -> {}] read {} bytes, wrote {} bytes'.format(
            local_name, remote_name, len(bytes_read), bytes_written))


def main(validate=False):
    '''Create sockets. Proxy all packets and validate RIL packets.'''
    # Configure command line parser
    parser = ArgumentParser(
        description='Proxy packets between AP VM and BP phone')

    parser.add_argument('-l', '--logging', default='info', type=str,
                        choices=['verbose', 'debug', 'info', 'warning',
                                 'error'],
                        help='log level')
    parser.add_argument('-v', '--validate', action='store_true',
                        help='filter non UDP and abort on invalid calls')

    args = parser.parse_args()

    # Init logger
    verbose = False

    if args.logging == 'verbose':
        lg.basicConfig(format='%(levelname)s %(message)s', level=lg.DEBUG)
        verbose = True
    elif args.logging == 'debug':
        lg.basicConfig(format='%(levelname)s %(message)s', level=lg.DEBUG)
    elif args.logging == 'info':
        lg.basicConfig(format='%(levelname)s %(message)s', level=lg.INFO)
    elif args.logging == 'warning':
        lg.basicConfig(format='%(levelname)s %(message)s', level=lg.WARNING)
    elif args.logging == 'error':
        lg.basicConfig(format='%(levelname)s %(message)s', level=lg.ERROR)

    # Open sockets
    local = sc.socket(sc.AF_PACKET, sc.SOCK_RAW, sc.htons(ETH_P_ALL))
    remote = sc.socket(sc.AF_PACKET, sc.SOCK_RAW, sc.htons(ETH_P_ALL))

    local.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR, 1)
    local.setsockopt(sc.SOL_SOCKET, sc.SO_BINDTODEVICE,
                     str('ril0' + '\0').encode('utf-8'))
    local.bind(('ril0', 0))
    remote.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR,
                      1)
    remote.setsockopt(sc.SOL_SOCKET, sc.SO_BINDTODEVICE,
                      str('enp0s29u1u4' + '\0').encode('utf-8'))
    remote.bind(('enp0s29u1u4', 0))

    # Proxy it
    sel = DefaultSelector()
    if args.validate or validate:
        dissector = Dissector()
    else:
        dissector = None

    sel.register(local, EVENT_READ)
    sel.register(remote, EVENT_READ)
    while True:
        lg.info('...')
        events = sel.select()
        for key, mask in events:
            if key.fileobj is local:
                socket_copy(dissector, local, remote, verbose)
            else:
                socket_copy(dissector, remote, local, verbose)

    # Close sockets
    local.close()
    remote.close()


if __name__ == '__main__':
    main()
