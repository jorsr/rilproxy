#!/usr/bin/env python3
from validator import Validator
from dissector import Dissector

from selectors import DefaultSelector, EVENT_READ
import logging as lg
import socket as sc


class SoftwareBridge(object):
    '''Relay packets between the AP and BP interfaces and filter if necessary
    '''
    ETH_P_ALL = 0x0003
    FMT_NUM = '%s: %s'
    FMT_PKT = ' %s:\t%s'
    FMT_NONE = '%s'
    RILPROXY_BUFFER_SIZE = 3000  # TODO 3000 is not a power of 2

    # ethertypes to let through
    ARP = '0806'
    IPV4 = '0800'

    # protocols to let through
    UDP = 17

    # ports to let through
    RILPROXY_PORT = 18912

    def filter_bytes(self, bytes_read, local_name, remote):
        '''filter UDP and RILPROXY_PORT only'''
        remote_name = remote.getsockname()[0]

        # read ehternet header
        ethernet_header = bytes_read[0:14]
        ethernet_destination = ':'.join('%02x' % x for x in
                                        ethernet_header[0:6])
        ethernet_source = ':'.join('%02x' % x for x in ethernet_header[6:12])
        ethertype = ethernet_header[12:14].hex()

        if self.verbose:
            lg.debug('ETHERNET HEADER')
            lg.debug(self.FMT_PKT, 'destination MAC', ethernet_destination)
            lg.debug(self.FMT_PKT, 'source MAC', ethernet_source)
            lg.debug(self.FMT_PKT, 'EtherType', ethertype)
        if ethertype == self.ARP:
            lg.info('Forwarding: sending ARP packet without dissecting')

            return bytes_read
        elif ethertype != self.IPV4:
            lg.info('Dropping: %s is neither IPv4 nor ARP', ethertype)

            return None

        # read IP Header
        ip_header = bytes_read[14:34]
        ip_protocol = ip_header[9]

        if self.verbose:
            lg.debug('IP HEADER')
            lg.debug(self.FMT_PKT, ' time to live', ip_header[8])
            lg.debug(self.FMT_PKT, ' protocol', ip_protocol)
            lg.debug(self.FMT_PKT, ' checksum', ip_header[10:12])
            lg.debug(self.FMT_PKT, ' source IP',
                     sc.inet_ntoa(ip_header[12:16]))
            lg.debug(self.FMT_PKT, ' destination IP',
                     sc.inet_ntoa(ip_header[16:20]))
        if ip_protocol != self.UDP:
            lg.info('Dropping: %s is not UDP', ip_protocol)

            return None

        # debug output for UDP Header
        udp_header = bytes_read[34:42]
        udp_source = int.from_bytes(udp_header[0:2], byteorder='big')

        if self.verbose:
            udp_destination = int.from_bytes(udp_header[2:4], byteorder='big')

            lg.debug('UDP HEADER')
            lg.debug(self.FMT_PKT, 'source port', udp_source)
            lg.debug(self.FMT_PKT, 'destination port', udp_destination)
            lg.debug(self.FMT_PKT, 'length', int.from_bytes(udp_header[4:6],
                                                            byteorder='big'))
            lg.debug(self.FMT_PKT, 'checksum', udp_header[6:8])
        if udp_source != self.RILPROXY_PORT:  # NOTE we dont check dest
            lg.info('Dropping: %s is incorrect port', udp_source)

            return None
        if self.verbose:
            lg.debug(self.FMT_NUM, 'packet size', len(bytes_read))

        # remove headers
        udp_payload = bytes_read[42:]
        payload_info = ([udp_payload[i:i+4].hex()
                         for i in range(0, len(udp_payload), 4)])

        lg.debug('[{} -> {}] {}'.format(local_name, remote_name, payload_info))

        # dissect the UDP payload
        ril_msgs = self.dissector.dissect(udp_payload, local_name)

        if self.dissector.cached(local_name):
            self.cache[local_name] = bytes_read
            lg.info('Dropping: part of the payload was cached')

            return None
        elif local_name in self.cache:
            if ril_msgs != []:
                lg.info('Forwarding: sending cached packet')
                remote.send(self.cache[local_name])
            else:
                lg.warning('Dropping: cached packet because of boring payload')

            del self.cache[local_name]
        if ril_msgs == []:
            lg.info('Dropping: payload was boring')

            return bytes_read
        for ril_msg in ril_msgs:
            lg.debug('running %s through verifier', ril_msg)
            self.validator.validate(ril_msg)

        # TODO do I really want to drop invalid packages?
        # in case a concatenated parcel is invalid we already stop
        lg.info('Forwarding: sending packet')

        return bytes_read

    def socket_copy(self, local, remote):
        '''Copy content from local to remote socket '''
        bytes_read = local.recv(self.RILPROXY_BUFFER_SIZE)
        local_name = local.getsockname()[0]
        remote_name = remote.getsockname()[0]

        if len(bytes_read) < 0:
            raise RuntimeError('[{} -> {}] error reading {} socket'.format(
                local_name, remote_name, local_name))
        if self.dissector:
            filtered_bytes = self.filter_bytes(bytes_read, local_name,
                                               remote)
            bytes_written = None

            if filtered_bytes:  # TODO possibly create new frame
                bytes_written = remote.send(filtered_bytes)
        if bytes_written:
            if bytes_written < 1:
                raise RuntimeError(
                    '[{} -> {}] socket connection broken'.format(local_name,
                                                                 remote_name))
            if bytes_written < len(bytes_read):
                raise RuntimeError(
                    '[{} -> {}] read {} bytes, wrote {} bytes'.format(
                        local_name, remote_name, len(bytes_read),
                        bytes_written))

    def main(self):
        '''Create sockets. Proxy all packets and validate RIL packets.'''

        # init logger
        if self.logging == 'verbose':
            lg.basicConfig(format='%(levelname)s %(message)s', level=lg.DEBUG)
            self.verbose = True
        elif self.logging == 'debug':
            lg.basicConfig(format='%(levelname)s %(message)s', level=lg.DEBUG)
        elif self.logging == 'info':
            lg.basicConfig(format='%(levelname)s %(message)s', level=lg.INFO)
        elif self.logging == 'warning':
            lg.basicConfig(format='%(levelname)s %(message)s',
                           level=lg.WARNING)
        elif self.logging == 'error':
            lg.basicConfig(format='%(levelname)s %(message)s', level=lg.ERROR)

        # open sockets
        local = sc.socket(sc.AF_PACKET, sc.SOCK_RAW, sc.htons(self.ETH_P_ALL))
        remote = sc.socket(sc.AF_PACKET, sc.SOCK_RAW, sc.htons(self.ETH_P_ALL))

        local.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR, 1)
        local.setsockopt(sc.SOL_SOCKET, sc.SO_BINDTODEVICE,
                         str('ril0' + '\0').encode('utf-8'))
        local.bind(('ril0', 0))
        remote.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR,
                          1)
        remote.setsockopt(sc.SOL_SOCKET, sc.SO_BINDTODEVICE,
                          str('enp0s29u1u4' + '\0').encode('utf-8'))
        remote.bind(('enp0s29u1u4', 0))

        # proxy it
        sel = DefaultSelector()
        if not self.proxy_only:
            self.dissector = Dissector()
            self.validator = Validator()

        sel.register(local, EVENT_READ)
        sel.register(remote, EVENT_READ)

        self.cache = {}  # from last packet of AP or BP

        while True:
            lg.info('...')
            events = sel.select()
            for key, mask in events:
                if key.fileobj is local:
                    self.socket_copy(local, remote)
                else:
                    self.socket_copy(remote, local)

        # close sockets
        local.close()
        remote.close()

    def __init__(self, proxy_only=False, logging='info'):
        self.proxy_only = proxy_only
        self.logging = logging
        if logging == 'verbose':
            self.verbose = True
        else:
            self.verbose = False


if __name__ == '__main__':
    bridge = SoftwareBridge(False, 'info')

    bridge.main()
