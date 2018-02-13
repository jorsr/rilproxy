import ril_h as r

from logging import debug, error, info, warning


# TODO make data mandatory


class RilMessage(object):
    '''General RIL Message.

    All share data and length fields.
    Every message has an associated RIL command
    '''
    def __init__(self, command, length):
        self.command = command
        self.length = length


class RilRequest(RilMessage):
    '''A RIL Request.

    The fields are (in order):
     * Length
     * Command
     * Token
     * Data
    '''
    def __init__(self, command, length, token):
        self.token = token
        super().__init__(command, length)


class RilSolicitedResponse(RilMessage):
    '''A RIL Solicited Response to a RIL Request.

    The fields are (in order):
     * Length
     * M_Type (0 or 3)
     * Token
     * Error
     * Data
    Command is not in the actual message
    '''
    def __init__(self, command, err, length, reply_to, token):
        self.error = err
        self.token = token
        reply_to = reply_to
        super().__init__(command, length)


class RilUnsolicitedResponse(RilMessage):
    '''A RIL Unsolicited Response.

    The fields are (in order):
     * Length
     * M_Type (1 or 4)
     * Command
     * Data
    '''
    def __init__(self, command, length):
        self.command = command
        super().__init__(command, length)


def maybe_unknown(dictionary, value):
    '''Return "unknown" for NULL values'''
    if value in dictionary.keys():
        return dictionary[value]
    return str(value) + ' is unknown'


class Dissector(object):
    '''Dissects RIL Packets.

    Based on the Lua Wireshark dissector by Componolit.
    '''
    # Inset custom rilproxy request constants
    REQUEST_SETUP = 0xc715
    REQUEST_TEARDOWN = 0xc717
    r.REQUEST[REQUEST_SETUP] = "SETUP"
    r.REQUEST[REQUEST_TEARDOWN] = "TEARDOWN"

    # Inset additional constant defined by ril.h
    r.REQUEST[r.RESPONSE_ACKNOWLEDGEMENT] = "RESPONSE_ACKNOWLEDGEMENT"

    # Constants for response types defined by libril/ril.cpp
    RESPONSE_SOLICITED = 0
    RESPONSE_UNSOLICITED = 1
    RESPONSE_SOLICITED_ACK = 2
    RESPONSE_SOLICITED_ACK_EXP = 3
    RESPONSE_UNSOLICITED_ACK_EXP = 4

    bytes_missing = {}  # from last packet of AP or BP
    cache = {}  # from last packet of AP or BP
    last_token = 0  # from last request
    request_num = 0  # from last request
    requests = {}  # all requests
    pending_requests = []  # from last few requests
    packet_num = 0  # from last packet

    def cached(self, source):
        '''is something in the cache for this source?'''

        return source in self.cache

    def dissect(self, bfr, source):
        '''Dissect the RIL packets and return a list of RIL message objects.'''
        pckt_len = len(bfr)
        self.packet_num += 1
        fmt_num = '\tDissector: [' + str(self.packet_num) + '] %s: %s'
        fmt_pkt = '\tDissector: [' + str(self.packet_num) + ']  %s:\t%s'
        fmt_none = '\tDissector: [' + str(self.packet_num) + '] %s'

        debug(fmt_num, 'buffer length (raw)', pckt_len)

        # Follow-up to a message where length header indicates more bytes than
        # available in the message.
        if source in self.cache and self.bytes_missing[source] > 0:
            self.cache[source] = b''.join([self.cache[source], bfr])
            self.bytes_missing[source] = self.bytes_missing[source] - pckt_len

            debug(fmt_num, 'buffer length (reassembled)',
                  len(self.cache[source]))

            # Still fragments missing, wait for next packet
            if self.bytes_missing[source] > 0:
                debug(fmt_none, 'caching the package again')

                return []

            bfr = self.cache[source]
            pckt_len = len(bfr)

            del self.cache[source]

        # Advance request counter
        self.request_num = self.request_num + 1

        # Message must be at least 4 bytes
        if pckt_len < 4:
            warning(fmt_num, 'dropping short buffer of length', pckt_len)

            return []

        header_len = int.from_bytes(bfr[0:4], byteorder='big')

        if header_len < 4:
            warning(fmt_num, 'dropping short header of length', header_len)

            return []

        #  FIXME: Upper limit?
        if header_len > 3000:
            warning(fmt_num, 'dropping long buffer of length', header_len)
            self.bytes_missing[source] = 0

            if source in self.cache:
                del self.cache[source]

            return []
        if pckt_len <= (header_len - 4):
            self.bytes_missing[source] = header_len - pckt_len + 4
            self.cache[source] = bfr

            debug(fmt_none, 'caching the package')
            self.print_cache()

            return []

        if source in self.cache:
            warning(fmt_num, 'Clearing cache', self.cache[source])

            del self.cache[source]

        self.bytes_missing[source] = 0
        command_or_type = int.from_bytes(bfr[4:8], byteorder='little')
        ril_msgs = []

        if (source == 'ril0'):
            debug(fmt_none, 'RIL REQUEST')
            debug(fmt_pkt, 'length', header_len)
            debug(fmt_pkt, 'command', maybe_unknown(r.REQUEST,
                                                    command_or_type))
            if (header_len > 4):
                token = int.from_bytes(bfr[8:12], byteorder='little')

                debug(fmt_pkt, 'token', token)

                ril_msg = RilRequest(command_or_type, header_len, token)
                ril_msgs.append(ril_msg)
                self.requests[ril_msg.token] = {
                    'command': ril_msg.command,
                    'request_num': self.request_num
                }

                # RESPONSE_ACKNOWLEDGEMENT does not expect a response
                if ril_msg.command != r.RESPONSE_ACKNOWLEDGEMENT:
                    self.pending_requests.append(ril_msg.token)

                if ril_msg.token - self.last_token > 0:
                    debug(fmt_num, 'token delta', ril_msg.token -
                          self.last_token)

                self.last_token = ril_msg.token

                # TODO handle data
                # if (header_len > 8):
                #    dissector:call(bfr[12, header_len - 12 + 4]:tvb(), info,
                #    subtree)
            elif command_or_type == self.REQUEST_SETUP:
                ril_msg = RilMessage(command_or_type, header_len)

                ril_msgs.append(ril_msg)
        elif source == self.phone_if:
            m_type = int.from_bytes(bfr[4:8], byteorder='little')

            if (m_type in [self.RESPONSE_SOLICITED,
                           self.RESPONSE_SOLICITED_ACK_EXP]):
                if m_type == self.RESPONSE_SOLICITED:
                    debug(fmt_none, 'RIL SOLICITED RESPONSE')
                elif m_type == self.RESPONSE_SOLICITED_ACK_EXP:
                    debug(fmt_none, 'RIL SOLICITED RESPONSE (expect ACK)')
                debug(fmt_pkt, 'length', header_len)

                token = int.from_bytes(bfr[8:12], byteorder='little')

                debug(fmt_pkt, 'token', token)

                err = int.from_bytes(bfr[12:16], byteorder='little')

                debug(fmt_pkt, 'error', maybe_unknown(r.ERRNO, err))

                try:
                    request = self.requests[token]
                    request_delta = self.request_num - request['request_num']
                    ril_msg = RilSolicitedResponse(request['command'], err,
                                                   header_len,
                                                   request['request_num'],
                                                   token)

                    if ril_msg.token in self.pending_requests:
                        self.pending_requests.remove(ril_msg.token)
                        ril_msgs.append(ril_msg)
                        debug(fmt_pkt, 'command',
                              maybe_unknown(r.REQUEST, ril_msg.command))
                        debug(fmt_num, 'packets until reply', request_delta)
                    else:
                        error(fmt_num,
                              'discarding because we already removed token',
                              ril_msg.token)
                except KeyError:
                    error(fmt_none, 'dropping bcs token has never been used')

                # TODO handle data
                # if (header_len > 12):
                #   dissector:call(bfr(16, header_len - 16 + 4):tvb(), info,
                #   subtree)
            elif (m_type in [self.RESPONSE_UNSOLICITED,
                             self.RESPONSE_UNSOLICITED_ACK_EXP]):
                if m_type == self.RESPONSE_UNSOLICITED:
                    debug(fmt_none, 'RIL UNSOLICITED RESPONSE')
                elif m_type == self.RESPONSE_UNSOLICITED_ACK_EXP:
                    debug(fmt_none, 'RIL UNSOLICITED RESPONSE (expect ACK)')
                debug(fmt_pkt, 'length', header_len)

                command = int.from_bytes(bfr[8:12], byteorder='little')

                debug(fmt_pkt, 'command', maybe_unknown(r.UNSOL, command))

                ril_msg = RilUnsolicitedResponse(command, header_len)
                ril_msgs.append(ril_msg)

                # TODO handle data
                # if (header_len > 8):
                #     dissector:call(bfr(12, header_len - 12 + 4):tvb(), info,
                #     subtree)
            elif (m_type == self.RESPONSE_SOLICITED_ACK):
                debug(fmt_none, 'RIL SOLICITED RESPONSE (ACK)')
                debug(fmt_pkt, 'length', header_len)

                token = int.from_bytes(bfr[8:12], byteorder='little')

                debug(fmt_pkt, 'token', token)
            else:
                warning(fmt_num, 'wrong packet type', m_type)
        else:
            error(fmt_none, 'invalid direction')
        info(fmt_num, 'In-flight requests', self.pending_requests)

        # If data is left in buffer, run dissector on it
        len_diff = pckt_len - (header_len + 4)
        if len_diff > 0:
            # SETUP request is padded with 10 bytes FIXME Why?
            if command_or_type == self.REQUEST_SETUP:
                if len_diff == 10:
                    return ril_msgs

            # RESPONSE_ACKNOWLEDGEMENT request is padded with 6 bytes FIXME
            if ril_msgs != []:
                if ril_msgs[-1].command == r.RESPONSE_ACKNOWLEDGEMENT:
                    if len_diff == 6:
                        return ril_msgs
            info('..running dissector again..')
            additional_ril_msgs = self.dissect(bfr[header_len + 4:], source)
            for msg in additional_ril_msgs:
                ril_msgs.append(msg)

        return ril_msgs

    def print_cache(self):
        debug('\tDissector: [' + str(self.packet_num) + '] cache')
        for source in self.cache.keys():
            debug('\tDissector: [' + str(self.packet_num) + '] %s: %s', source,
                  ([self.cache[source][i:i+4].hex()
                    for i in range(0, len(self.cache[source]), 4)]))

    def __init__(self, phone_if):
        self.phone_if = phone_if
