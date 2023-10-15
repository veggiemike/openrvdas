#!/usr/bin/env python3

import logging
import socket
import struct
import sys

from os.path import dirname, realpath
sys.path.append(dirname(dirname(dirname(realpath(__file__)))))
from logger.readers.reader import Reader  # noqa: E402
from logger.utils.formats import Text  # noqa: E402

# The maximum length of UDP record we can receive. Records will be
# truncated at this length. Note that the effective maximum value for
# this parameter is the underlying system's Maximum Transmission Unit
# (MTU). If read_buffer_size is set larger than the MTU and a packet
# longer than the MTU is received, the system will throw an
#    [Errno 40] Message too long
# (caught by this Reader) and the entire packet will be discarded. On
# Linux machines, it appears that the MTU may be up to 65k; on MacOS,
# the default is 4096. See
#     https://stackoverflow.com/questions/22819214/udp-message-too-long
#
# FIXME: surely we can do better here...  a nice optimal size to read is 4k
#        (page size on most systems), so that should be the default size.  if
#        the user wants to try and receive something larger, why not let them
#        and see what happens?  Oviously on Mac, it won't work, and we'll have
#        to handle some sort of exception, but it will totally work on Linux.
#        I'm sure there's a standard way to query the systems maximum recv
#        size...
#
READ_BUFFER_SIZE = 4096  # max number of characters to read in one call


################################################################################
# Read to the specified file. If filename is empty, read to stdout.
class UDPReader(Reader):
    """
    Read UDP broadcast and multicast records from a socket.
    """
    ############################

    # FIXME: change source to mc_ip or mc_group or something?  don't use
    #        mc_source, though, that's used by UDPWriter to specify the source
    #        interface of outgoung mc traffic and would be confusing.
    #
    # FIXME: doesn't take host to listen on?  what are we only listening on
    #        INADDR_ANY?  what if i want to listen on a specific interface?
    #
    def __init__(self, port, source='', eol=None,
                 read_buffer_size=READ_BUFFER_SIZE,
                 encoding='utf-8', encoding_errors='ignore'):
        """
        ```
        port         Port to listen to for packets

        source       If specified, multicast group id to listen for

        eol          If not specified, assume one record per network packet.  If
                     specified, buffer network reads until the eol
                     character has been seen, and return the entire record
                     at once, retaining everything after the eol for the
                     start of the subsequent record. If multiple eol characters
                     are encountered in a packet, split the packet and return
                     the first of them, buffering the remainder for subsequent
                     calls.

                       FIXME: that's pretty strange for UDP, sounds standard
                              for TCP.  UDP is a datagram protocol... 1 packet
                              == 1 record, that's kinda the point.

                       FIXME: does this even conceptually work?  If remote
                              system sends a 2K datagram, and we do a
                              recv(1024), is the remaining 1024 bytes still on
                              the wire?  Or does it get dropped on the floor.
                              Test this.

                       FIXME: from udp(7):

                              "By default, Linux UDP does path MTU (Maximum
                              Transmission Unit) discovery.  This means the
                              kernel will keep track of the MTU to a specific
                              target IP address and return EMSGSIZE when a UDP
                              packet write exceeds it.  When this happens, the
                              application should decrease the packet size.
                              Path MTU discovery can be also turned off using
                              the IP_MTU_DISCOVER socket option or the
                              /proc/sys/net/ipv4/ip_no_pmtu_disc file; see
                              ip(7) for details.  When turned off, UDP will
                              fragment outgoing UDP packets that exceed the
                              interface MTU.  However, disabling it is not
                              recommended for performance and reliability
                              reasons."

                              So, we could have our MAX_READ_SIZE set to None
                              until we bump into a EMSGSIZE error, then set our
                              MAX_READ_SIZE to something smaller and try to do
                              our own fragmentation with trailing eol.  Testing
                              that will be fun.  sock.send('a'*102400)?


        read_buffer_size
                The maximum length of UDP record we can receive. Records will be
                truncated at this length. Note that the effective maximum value for
                this parameter is the underlying system's Maximum Transmission Unit
                (MTU). If read_buffer_size is set larger than the MTU and a packet
                longer than the MTU is received, the system will throw an "[Errno 40]
                Message too long" (caught by this Reader) and the entire packet will
                be discarded. On Linux machines, it appears that the MTU may be up to
                65k; on MacOS, the default is 4096.

        encoding - 'utf-8' by default. If empty or None, do not attempt any decoding
                and return raw bytes. Other possible encodings are listed in online
                documentation here:
                https://docs.python.org/3/library/codecs.html#standard-encodings

        encoding_errors - 'ignore' by default. Other error strategies are 'strict',
                'replace', and 'backslashreplace', described here:
                https://docs.python.org/3/howto/unicode.html#encodings

        ```
        """
        super().__init__(output_format=Text,
                         encoding=encoding,
                         encoding_errors=encoding_errors)

        # 'eol' comes in as a (probably escaped) string. We need to
        # unescape it, which means converting to bytes and back.
        if eol is not None:
            eol = self._unescape_str(eol)
        self.eol = eol
        self.read_buffer_size = read_buffer_size

        # Where we'll aggregate incomplete records if an eol char is specified
        #
        # FIXME: shouldn't ever happen unless you're doing something incredibly
        #        dumb.
        #
        # FIXME: maybe this is for working around MTU?  are we automatically
        #        fragmenting writes larger than 4k into multiple packets?
        #
        # FIXME: is there a max size for this?
        #
        self.record_buffer = ''

        self.socket = socket.socket(family=socket.AF_INET,
                                    type=socket.SOCK_DGRAM,
                                    proto=socket.IPPROTO_UDP)
        # FIXME: unneeded
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

        # If source is specified, subscribe to it as a multicast group
        if source:
            # FIXME: should probably take `mc_source` like UDPWriter to specify
            #        interface for mc traffic... maybe call it `mc_interface`
            #        over here?
            mreq = struct.pack("4sl", socket.inet_aton(source), socket.INADDR_ANY)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        try:  # Raspbian doesn't recognize SO_REUSEPORT
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)
        except AttributeError:
            logging.warning('Unable to set socket REUSEPORT; may be unsupported.')

        # If source is empty, we're listening for broadcasts, otherwise
        # listening for multicast on IP 'source'
        self.socket.bind((source, port))

    ############################
    #
    # FIXME: does this read the next UDP packet or the next eol-terminated
    #        record?  yes.
    #
    # FIXME: jeez, should UDPWriter be auto-fragmenting records larger than 4k
    #        and sticking eol on the end of the last packet?
    #
    def read(self):
        """
        Read the next UDP packet.
        """
        # If no eol character/string specified, just read a packet and
        # return it as the next record.
        if not self.eol:
            try:
                record = self.socket.recv(self.read_buffer_size)
            except OSError as e:
                logging.error('UDPReader error: %s', str(e))
                return None
            logging.debug('UDPReader.read() received %d bytes', len(record))
            return self._decode_bytes(record)

        # If an eol character/string has been specified, we may have to
        # loop our reads until we see an eol.
        while True:
            eol_pos = self.record_buffer.find(self.eol)
            if eol_pos > -1:
                # We have an eol string somewhere in our buffer. Return
                # everything up to it.
                record_end = eol_pos + len(self.eol)
                record = self.record_buffer[0:record_end-1]
                logging.debug('UDPReader found eol; returning record')
                self.record_buffer = self.record_buffer[record_end:]
                return record

            # If no eol string, read, append, and try again.
            record = self.socket.recv(self.read_buffer_size)
            logging.debug('UDPReader.read() received %d bytes', len(record))
            if record:
                self.record_buffer += self._decode_bytes(record)
