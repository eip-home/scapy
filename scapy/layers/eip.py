#!/usr/bin/python

from scapy.compat import orb
from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, \
    ShortField, StrLenField, BitField, PacketListField
from scapy.layers.inet6 import _hbhopts, _OptionsField, _OTypeField



_eipiels = {
    0x01: "Short Identifier"
}


class EIPShortIdentifier(Packet):

    name = "EIP Short Identifier"

    fields_desc = [
        BitField("code", 1, 2),
        BitField("len", 0, 6),
        ByteEnumField("type", 0xCA, _eipiels),
        ShortField("id", 0xFFFF)
    ]

    def alignment_delta(self, curpos):  # alignment requirement : 8n+0
        # x = 0
        # y = 0
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta
        return 0

    # fields_desc = [
    #     BitField("code", 1, 2),
    #     BitField("len", 0, 6),
    #     ByteEnumField("type", 0x01, _eipiels),
    #     ShortField("id", 0)
    # ]


class EIPIEUnknown(Packet):

    name = "EIP Unknown Information Element"

    # fields_desc = [
    #     BitField("code", 0, 2),
    #     BitField("len", 0, 6),
    #     ByteEnumField("type", None, _eipiels),
    #     StrLenField("value", "", length_from=lambda pkt: pkt.len * 4)
    # ]

    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", 5, 6),
        ByteEnumField("type", 0XBA, _eipiels),
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