#!/usr/bin/python

from scapy.compat import orb
from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, \
    ShortField, StrLenField, BitField, PacketListField, \
    ShortEnumField, ByteField, IntField, XNBytesField
from scapy.layers.inet6 import _hbhopts, _OptionsField, _OTypeField

LUT = [0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240,
       8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120,
       248, 4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180,
       116, 244, 12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60,
       188, 124, 252, 2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50,
       178, 114, 242, 10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218,
       58, 186, 122, 250, 6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214,
       54, 182, 118, 246, 14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94,
       222, 62, 190, 126, 254, 1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81,
       209, 49, 177, 113, 241, 9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89,
       217, 57, 185, 121, 249, 5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85,
       213, 53, 181, 117, 245, 13, 141, 77, 205, 45, 173, 109, 237, 29, 157,
       93, 221, 61, 189, 125, 253, 3, 131, 67, 195, 35, 163, 99, 227, 19, 147,
       83, 211, 51, 179, 115, 243, 11, 139, 75, 203, 43, 171, 107, 235, 27,
       155, 91, 219, 59, 187, 123, 251, 7, 135, 71, 199, 39, 167, 103, 231, 23,
       151, 87, 215, 55, 183, 119, 247, 15, 143, 79, 207, 47, 175, 111, 239,
       31, 159, 95, 223, 63, 191, 127, 255]

def reverseBitOrder(uint8):
    return LUT[uint8]

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
        #FieldLenField("lennew", None, length_of="hmac", fmt="B"),
        ShortEnumField("type", 0x0001, _eipiels_ext),
        ByteField("reserved", 0xFF),
        IntField("keyid", 0),
        StrLenField("hmac", b"\00\01\02\03\04\05\06\07", length_from=lambda pkt: pkt.len)
    ]

    #FIXME : we still have to understand the representation of Bitfield !! 
    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-8)/4)
            my_list = [pkt[0] | reverseBitOrder(var_len <<2)]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)

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
