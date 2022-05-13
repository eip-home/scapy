#!/usr/bin/python

from scapy.compat import orb
from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, \
    ShortField, StrLenField, BitField, PacketListField, \
    ShortEnumField, ByteField, IntField, XNBytesField
from scapy.layers.inet6 import _hbhopts, _OptionsField, _OTypeField



_eipiels_base = {
    0x01: "Short Identifier"
}

_eipiels_ext = {
    0x0001: "HMAC"
}

class EIPBase(Packet):

    name = "EIP 1 byte code"
    code = 1

    fields_desc = [
        BitField("code", code, 2),
        BitField("len", 0, 6),
        ByteEnumField("type", None, _eipiels_base),
        ShortField("id", None)
    ]

    def alignment_delta(self, curpos):  # alignment requirement : 8n+0
        # x = 0
        # y = 0
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta
        return 0



class EIPShortIdentifier(Packet):

    name = "EIP Short Identifier"
    fields_desc = [
        BitField("code", 1, 2),
        BitField("len", 0, 6),
        ByteEnumField("type", 0x01, _eipiels_base),
        ShortField("id", 0xCCCC)
    ]
    
    
class EIPHmac(Packet):

    name = "EIP HMAC"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        FieldLenField("lennew", None, length_of="hmac", fmt="B"),
        ShortEnumField("type", 0xAAAA, _eipiels_ext),
        ByteField("reserved", 0x00),
        IntField("keyid", 0),
        StrLenField("hmac", b"\x11", length_from=lambda pkt: pkt.lennew)
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = len(pkt)-9
            #pkt = b"\xBB" + pkt[1:]
            #pkt = pkt[0] & (var_len << 2) + pkt[1:]
            #print (int.from_bytes( pkt[0], "little" ))
            my_list = []
            my_list.append(pkt[0] | (var_len <<2))
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)

#adjust=lambda pkt, x: x/4

class EIPIEUnknown(Packet):

    name = "EIP Unknown Information Element"

    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", 5, 6),
        ByteEnumField("type", None, _eipiels_base),
        StrLenField("value", "", length_from=lambda pkt: pkt.len * 4)
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])  # Option type
            if o in _eipielscls:
                return _eipielscls[o]
        return cls


class EIP(Packet):
    """
    Extensible In-band Processing

    See https://eip-home.github.io/eip-headers/draft-eip-headers-definitions.html
    """

    name = "EIP"

    fields_desc = [
        _OTypeField("otype", 0x3e, _hbhopts),
        FieldLenField("len", None, length_of="ielems", fmt="B"),
        PacketListField("ielems", [EIPShortIdentifier()], EIPIEUnknown, 2,
                      length_from=lambda pkt: pkt.len)
    ]

    def alignment_delta(self, curpos):  # alignment requirement : 8n+6
        x = 8
        y = 6
        delta = x * ((curpos - y + x - 1) // x) + y - curpos
        return delta


_eipielscls = {
    0x01: EIPShortIdentifier
}


_hbhopts['0x3e'] = EIP
