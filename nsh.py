import struct
from packet_base import packet_base

from ipv4 import *
from ipv6 import *
from mpls import *
from ethernet import *

class nsh(packet_base):
    "Network Service Header"

    NSH_PORT = 6633

    IPV4_PROTOCOL = 0x1
    IPV6_PROTOCOL = 0x2
    ETHERNET_PROTOCOL = 0x3
    NSH_PROTOCOL = 0x4
    MPLS_PROTOCOL = 0x5

    MIN_LEN = 8 # Minimal length in Bytes of the NSH header
    VERSION = 0
    IS_OAM = 0
    DEFAULT_TTL = 63

    "Assuming no meta-data"
    NO_MD_LEN = 0x02
    NO_MD_TYPE = 0x02

    def __init__(self, raw=None, prev=None, spi=0, si=255, ttl=63, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.v = nsh.VERSION
        self.oam = nsh.IS_OAM
        self.ttl = nsh.DEFAULT_TTL
        self.len = nsh.NO_MD_LEN            # length of the NSH header in 4-bytes-word
        self.mdtype = nsh.NO_MD_TYPE
        self.protocol = nsh.IPV4_PROTOCOL
        self.spi = spi
        self.si = si
        self.next = b''

        if raw is not None:
            self.parse(raw)
        
        self._init(kw)

    def __str__(self):
        s = "[ NSHv%s ttl:%s length:%s spi:%s si:%s ]" %(
            self.v, self.ttl, self.len, self.spi, self.si)
        
        return s
    
    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.next = None
        self.raw = raw
        dlen = len(raw)
        if dlen < (nsh.MIN_LEN):
            self.msg('warning NSH packet data too short to parse header: data len %u' % (dlen,))
            return
        
        (v2oam1u1ttl4, ttl2len6, u4mdtype4, protocol, spi16, spi8, si) = \
            struct.unpack('!BBBBHBB',raw[:nsh.MIN_LEN])
        
        self.v = v2oam1u1ttl4 >> 6
        self.oam = (v2oam1u1ttl4 & 0b00100000) >> 5
        self.ttl = ((v2oam1u1ttl4 & 0b00001111) << 2) + (ttl2len6 >> 6)
        # self.ttl -= 1
        self.len = ttl2len6 & 0b00111111
        self.mdtype = u4mdtype4 & 0b00001111
        self.protocol = protocol
        self.spi = (spi16 << 8) + spi8
        self.si = si

        if self.v != nsh.VERSION:
            self.msg('(nsh parse) warning: NSH version %u not 0' % nsh.VERSION)
            return
        
        if self.len*4 < nsh.MIN_LEN:
            self.msg('(nsh parse) warning: NSH header is too short (Length=%u => header total length=%u)'\
                 %(self.len, self.len*4))
            return
        
        if self.len*4 > dlen:
            self.msg('(nsh parse) warning: NSH header is truncated')
            return
        
        self.parsed=True

        if self.protocol == nsh.IPV4_PROTOCOL:
            self.next = ipv4(raw=raw[self.len*4:], prev=self)
        elif self.protocol == nsh.IPV6_PROTOCOL:
            self.next = ipv6(raw=raw[self.len*4:], prev=self)
        elif self.protocol == nsh.MPLS_PROTOCOL:
            self.next = mpls(raw=raw[self.len*4:], prev=self)
        elif self.protocol == nsh.ETHERNET_PROTOCOL:
            self.next = ethernet(raw=raw[self.len*4:], prev=self)
        elif self.protocol == nsh.NSH_PROTOCOL:
            self.next = nsh(raw=raw[self.len*4:], prev=self)
        else:
            self.next = raw[self.len*4:]

        if isinstance(self.next, packet_base) and not self.next.parsed:
            self.next = raw[self.len*4:]

    def hdr(self, payload):

        v2oam1u1ttl4 = (self.v << 6) + (self.oam << 5) + (self.ttl >> 2)
        ttl2len6 = ((self.ttl & 0b00000011) << 6) + (self.len)
        u4mdtype4 = self.mdtype
        protocol = self.protocol
        spi16 = self.spi >> 8
        spi8 = self.spi & 0b11111111
        si = self.si

        return struct.pack('!BBBBHBB',\
            v2oam1u1ttl4, ttl2len6, u4mdtype4, protocol, spi16, spi8, si)