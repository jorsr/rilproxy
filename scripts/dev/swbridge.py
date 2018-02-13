#!/usr/bin/env python3
from dissector import Dissector, RilUnsolicitedResponse
from ril_h import UNSOL_SIGNAL_STRENGTH
from validator import Validator

from argparse import ArgumentParser
from selectors import DefaultSelector, EVENT_READ
# TODO Add countdown from time import time
import logging as lg
import socket as sc

from sismic.exceptions import ExecutionError


class SoftwareBridge(object):
    '''Relay packets between the AP and BP interfaces and filter if necessary

    Arguements for initialization:
    proxy_all -- do not filter packets (default False)
    validate -- run packets through validator (default False)
    wait -- wait 2 mins before activating the validator (default False)
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
        if self.proxy_all:
            lg.info('forwarding packet')

            return bytes_read

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
            lg.info(
                'forwarding packet: Sending ARP packet without dissecting.')

            return bytes_read
        elif ethertype != self.IPV4:
            lg.info('dropping %s packet: It is neither IPv4 nor ARP.',
                    ethertype)

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
            lg.info('dropping packet: %s is not UDP.', ip_protocol)

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
            lg.info('dropping packet: %s is the incorrect port.', udp_source)

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

        # Determine if we are still waiting
        if self.waiting:
            for ril_msg in ril_msgs:
                if isinstance(ril_msg, RilUnsolicitedResponse):
                    if ril_msg.command == UNSOL_SIGNAL_STRENGTH:
                        self.signal_count += 1
                        lg.info('waiting: Received signal %s times.',
                                self.signal_count)
                else:
                    self.signal_count = 0
                    lg.info('waiting: Received signal %s times.',
                            self.signal_count)
            if self.signal_count == 4:
                self.waiting = False
                self.validator = Validator()
                lg.info('starting validator now! PLEASE START USER ACTION!')
            # TODO add countdown
            #  and not self.signal_time:
            #     self.signal_time = time()
            # if self.signal_time and time() - self.signal_time > 120:
        if self.dissector.cached(local_name):
            self.cache[local_name] = bytes_read
            lg.info('dropping packet: Part of the payload was cached.')

            return None
        if ril_msgs == []:
            lg.info('dropping packet: Payload not recognized.')

            return bytes_read
        if self.validate and not self.waiting:
            for ril_msg in ril_msgs:
                lg.debug('running %s through validator', ril_msg)
                try:
                    self.validator.validate(ril_msg)
                except ExecutionError as e:
                    lg.error('dropping packet: %s', e)
                    if local_name in self.cache:
                        lg.error('dropping cache')

                        del self.cache[local_name]

                    return None
        if local_name in self.cache:
            if ril_msgs != []:
                lg.info('forwarding cache')
                remote.send(self.cache[local_name])
            else:
                lg.warning('dropping cache: Payload not recognized.')

            del self.cache[local_name]
        lg.info('forwarding packet')

        return bytes_read

    def socket_copy(self, local, remote):
        '''Copy content from local to remote socket '''
        bytes_read = local.recv(self.RILPROXY_BUFFER_SIZE)
        local_name = local.getsockname()[0]
        remote_name = remote.getsockname()[0]

        if len(bytes_read) < 0:
            raise RuntimeError('[{} -> {}] error reading {} socket'.format(
                local_name, remote_name, local_name))

        filtered_bytes = self.filter_bytes(bytes_read, local_name, remote)
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
                          str(self.phone_if + '\0').encode('utf-8'))
        remote.bind((self.phone_if, 0))

        # proxy it
        sel = DefaultSelector()

        # Create dissector and validator
        if self.proxy_all:
            self.dissector = None
            self.validator = None
        elif self.validate:
            self.dissector = Dissector(self.phone_if)
            self.validator = Validator()
        else:
            self.dissector = Dissector(self.phone_if)
            self.validator = None
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

    def __init__(self, phone_if, logging='info', proxy_all=False,
                 validate=False, wait=False):
        self.logging = logging
        self.phone_if = phone_if
        self.proxy_all = proxy_all
        self.validate = validate
        self.waiting = wait

        if wait:
            self.signal_time = None

        if logging == 'verbose':
            self.verbose = True
        else:
            self.verbose = False


if __name__ == '__main__':
    parser = ArgumentParser(
        description='Proxy packets between AP VM and BP phone')

    parser.add_argument('phone_if',
                        help='the network interface coming from the phone')

    bridge = SoftwareBridge(parser.parse_args().phone_if)

    bridge.main()
