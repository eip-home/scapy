#!/usr/bin/python

from scapy.compat import orb
from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, NBytesField, \
    ShortField, StrLenField, BitField, PacketListField, \
    ShortEnumField, ByteField, IntField, XNBytesField, XStrLenField
from scapy.layers.inet6 import _hbhopts, _hbhoptcls, _OptionsField, _OTypeField

_eipiels_base = {
    0x01: "Short Identifier"
}

_eipiels_ext = {
    0x0001: "HMAC",
    0x0002: "CPT"
}

class HMACField(StrLenField):
      def i2repr(self, pkt, x):
            return ' '.join(b.encode('hex') for b in x)


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

    def extract_padding(self, p):
        return b"", p
    
    
class EIPCPT(Packet):

    # we are adding by default 8 bytes HMAC initialized with
    # b"\00\01\02\03\04\05\06\07"
    # we are also adding a key id inizialized with 0x1234

    name = "EIP CPT"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        #FieldLenField("lennew", None, length_of="hmac", fmt="B"),
        ShortEnumField("type", 0x0002, _eipiels_ext),
        BitField("version", 0, 3),
        BitField("reserved", 0, 5),
        StrLenField("mcdstack", 40 * b"\00", length_from=lambda pkt: pkt.len * 4)
    ]

    def extract_padding(self, p):
        return b"", p

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-8)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)
    
    
class EIPHmac(Packet):

    # we are adding by default 8 bytes HMAC initialized with
    # b"\00\01\02\03\04\05\06\07"
    # we are also adding a key id inizialized with 0x1234

    name = "EIP HMAC"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        #FieldLenField("lennew", None, length_of="hmac", fmt="B"),
        ShortEnumField("type", 0x0001, _eipiels_ext),
        ByteField("reserved", 0xFF),
        IntField("keyid", 0x1234),
        XStrLenField("hmac", b"\00\01\02\03\04\05\06\07", length_from=lambda pkt: pkt.len * 4)
    ]

    def extract_padding(self, p):
        return b"", p

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-8)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)

class EipIeUnknown(Packet):

    name = "EIP Unknown Information Element"

    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        NBytesField("unknown",None,3),
        StrLenField("value", "", length_from=lambda pkt: pkt.len * 4)
    ]

    def extract_padding(self, p):
        return b"", p

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])  # IE type
            o = o >> 6
            if o == 1:
                print ("uno")
                o = orb(_pkt[1])  # IE type
                print ("codice" )
                print (o)
                if o in _eipiels_cls:
                    print ("yes")
                    return _eipiels_cls[o]
            elif o == 2:
                print ("due")
                o = orb(_pkt[1])*256+orb(_pkt[2])  # IE extended type
                if o in _eipiels_ext_cls:
                    return _eipiels_ext_cls[o]
            elif o == 3:
                pass
        print ("cls")
        return cls

# class EipIeBaseUnknown(Packet):

#     name = "EIP Unknown Base Information Element"

#     fields_desc = [
#         BitField("code", 2, 2),
#         BitField("len", None, 6),
#         ByteEnumField("type", None, _eipiels_base),
#         ShortField("valuefixed", None),
#         StrLenField("value", "", length_from=lambda pkt: pkt.len * 4)
#     ]

#     @classmethod
#     def dispatch_hook(cls, _pkt=None, *args, **kargs):
#         print ("dopo uno")
#         if _pkt:
#             o = orb(_pkt[1])  # IE type
#             print ("codice" )
#             print (o)
#             if o in _eipiels_cls:
#                 return _eipiels_cls[o]
#         return cls

# class EipIeExtUnknown(Packet):

#     name = "EIP Unknown Ext Information Element"

#     fields_desc = [
#         BitField("code", 2, 2),
#         BitField("len", None, 6),
#         ShortEnumField("type", None, _eipiels_ext),
#         ByteField("valuefixed", None),
#         StrLenField("value", "", length_from=lambda pkt: pkt.len * 4)
#     ]

#     @classmethod
#     def dispatch_hook(cls, _pkt=None, *args, **kargs):
#         print ("dopo due")
#         if _pkt:
#             o = orb(_pkt[1])*256+orb(_pkt[2])  # IE extended type
#             if o in _eipiels_ext_cls:
#                 return _eipiels_ext_cls[o]
#         return cls


class EIP(Packet):
    """
    Extensible In-band Processing

    See https://eip-home.github.io/eip-headers/draft-eip-headers-definitions.html
    """

    name = "EIP"

    #for the dissection we need to replace EipIeBaseUnknown
    fields_desc = [
        _OTypeField("otype", 0x3e, _hbhopts),
        FieldLenField("len", None, length_of="ielems", fmt="B"),
        PacketListField("ielems", [], EipIeUnknown,
                      length_from=lambda pkt: pkt.len)
    ]

    def extract_padding(self, p):
        return b"", p

    def alignment_delta(self, curpos):  # alignment requirement : 4n+6
        x = 4
        y = 6
        delta = x * ((curpos - y + x - 1) // x) + y - curpos
        return delta


_eipiels_cls = {
    0x01: EIPShortIdentifier
}


_eipiels_ext_cls = {
    0x0001: EIPHmac,
    0x0002: EIPCPT
}


_hbhoptcls [0x3e] = EIP
_hbhopts[0x3e] = "EIP"
