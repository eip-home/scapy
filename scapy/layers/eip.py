#!/usr/bin/python

import re
import time
from scapy.compat import orb
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.fields import BitEnumField, BitFieldLenField, ByteEnumField, ConditionalField, Field, FieldLenField, FieldListField, LongField, MultipleTypeField, NBytesField, PacketField, \
    ShortField, StrLenField, BitField, PacketListField, \
    ShortEnumField, ByteField, IntField, XNBytesField, XStrLenField
from scapy.layers.inet6 import _hbhopts, _hbhoptcls, _OptionsField, _OTypeField

ShortIdentifierCode = 0x01
ProcessingAcceleratorCode = 0x02
TimestampCode = 0x03

HmacCode = 0x0001
CPTCode = 0x0002
LongIdentifierCode = 0x0003
GSRCode = 0x0004


class HMACInvalidLengthField(Scapy_Exception):
    """
    basic frame structure not standard conform
    (missing TLV, invalid order or multiplicity)
    """
    pass


class MCDStackInvalidLengthField(Scapy_Exception):
    """
    basic frame structure not standard conform
    (missing TLV, invalid order or multiplicity)
    """
    pass


class LongIdentifierInvalidLengthField(Scapy_Exception):
    """
    basic frame structure not standard conform
    (missing TLV, invalid order or multiplicity)
    """
    pass


class TimestampsInvalidLengthField(Scapy_Exception):
    """
    basic frame structure not standard conform
    (missing TLV, invalid order or multiplicity)
    """
    pass


_eipiels_base = {
    ShortIdentifierCode: "Short Identifier",
    ProcessingAcceleratorCode: "Processing Accelerator",
    TimestampCode: "Timestamp"
}

_eipiels_ext = {
    HmacCode: "HMAC",
    CPTCode: "CPT",
    LongIdentifierCode: "Long Identifier",
    GSRCode: "Geotagging for Semantic Routing",
}

idtypes = {
    0: "Generic Long Identifier only",
    1: "Sequence Number only",
    2: "Sequence Number and Generic Long Identifier"
}

# class HMACField(StrLenField):
#       def i2repr(self, pkt, x):
#             return ' '.join(b.encode('hex') for b in x)


# class EIPBase(Packet):

#     name = "EIP 1 byte code"
#     code = 1

#     fields_desc = [
#         BitField("code", code, 2),
#         BitField("len", 0, 6),
#         ByteEnumField("type", None, _eipiels_base),
#         ShortField("id", None)
#     ]

#     def alignment_delta(self, curpos):  # alignment requirement : 8n+0
#         # x = 0
#         # y = 0
#         # delta = x * ((curpos - y + x - 1) // x) + y - curpos
#         # return delta
#         return 0



class EIPShortIdentifier(Packet):

    name = "EIP Short Identifier"
    fields_desc = [
        BitField("code", 1, 2),
        BitField("len", 0, 6),
        ByteEnumField("type", ShortIdentifierCode, _eipiels_base),
        ShortField("id", 0)
    ]

    def extract_padding(self, p):
        return b"", p


class EIPProcessingAccelerator(Packet):

    name = "EIP Processing Accelerator"
    fields_desc = [
        BitField("code", 1, 2),
        BitField("len", 0, 6),
        ByteEnumField("type", ProcessingAcceleratorCode, _eipiels_base),
        ShortField("id", 0)
    ]

    def extract_padding(self, p):
        return b"", p


# class EIPTimestampField(Field):
#     re_hmsm = re.compile("([0-2]?[0-9])[Hh:](([0-5]?[0-9])([Mm:]([0-5]?[0-9])([sS:.]([0-9]{0,3}))?)?)?$")  # noqa: E501

#     def i2repr(self, pkt, val):
#         if val is None:
#             return "--"
#         else:
#             sec, milli = divmod(val, 1000)
#             min, sec = divmod(sec, 60)
#             hour, min = divmod(min, 60)
#             return "%d:%d:%d.%d" % (hour, min, sec, int(milli))

#     def any2i(self, pkt, val):
#         if isinstance(val, str):
#             hmsms = self.re_hmsm.match(val)
#             if hmsms:
#                 h, _, m, _, s, _, ms = hmsms.groups()
#                 ms = int(((ms or "") + "000")[:3])
#                 val = ((int(h) * 60 + int(m or 0)) * 60 + int(s or 0)) * 1000 + ms  # noqa: E501
#             else:
#                 val = 0
#         elif val is None:
#             val = int((time.time() % (24 * 60 * 60)) * 1000)
#         return val

# class EIP1BytesTimestampField(ByteField, EIPTimestampField):
#     pass

# class EIP2BytesTimestampField(ShortField, EIPTimestampField):
#     pass

# class EIP4BytesTimestampField(IntField, EIPTimestampField):
#     pass

# class EIP8BytesTimestampField(LongField, EIPTimestampField):
#     pass


# class TimestampParamsField(ShortField):
#     def i2repr(self, pkt, x):
#         return "%d sec" % (4 * x)


class EIPTimestamp(Packet):

    TS_TYPES = {
        0x01: 'Basic Timestamp LTV',
    }

    TS_LENGTHS = {
        0b00: '1 Byte Timestamp',
        0b01: '2 Bytes Timestamp',
        0b10: '4 Bytes Timestamp',
        0b11: '8 Bytes Timestamp',
    }

    TS_FORMATS = {
        0b0001: '1 ns Timestamp Format',
        0b0010: '10 ns Timestamp Format',
        0b0011: '100 ns Timestamp Format',
        0b0100: '1 us Timestamp Format',
        0b0101: '10 us Timestamp Format',
        0b0110: '100 us Timestamp Format',
        0b0111: '1 ms Timestamp Format',
        0b1000: 'NTP (only for 8 bytes) Timestamp Format',
        0b1001: 'Linux epoch (only for 8 bytes) Timestamp Format',
    }

    name = "EIP Timestamp"
    fields_desc = [
        BitField("code", 1, 2),
        BitField("len", None, 6),
        ByteEnumField("type", 0x03, _eipiels_base),
        ByteEnumField("tstype", 0x01, TS_TYPES),
        BitEnumField("tslen", 0b00, 2, TS_LENGTHS),
        BitEnumField("tsformat", 0b0001, 4, TS_FORMATS),
        BitField("reserved", 0b00, 2),
        #ShortField("params", 0),

        FieldListField("timestamps", [], IntField("timestamp", 0),  # TODO: support variable timestamp lengths depending on the tslen field
                        length_from=lambda pkt: pkt.len * 4)
    ]

    def extract_padding(self, p):
        return b"", p

    def _check(self):
        """
        run layer specific checks
        """
        
        # if self.timestamps is not None:
        #     timestamps_len = len(self.timestamps)
        #     if timestamps_len % 4 != 0:
        #         raise TimestampsInvalidLengthField(
        #             'timestamps must be in multiples of 4 octets - '
        #             'got timestamps of size {}'.format(timestamps_len))


    def post_dissect(self, s):
        self._check()
        return super().post_dissect(s)

    def do_build(self):
        self._check()
        return super().do_build()

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-4)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)
    
    
class EIPLongIdentifier(Packet):

    name = "EIP Long Identifier"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        #BitFieldLenField("len", None, 6, length_of="id", adjust=lambda _,x: int((x+4)/4)),
        ShortEnumField("type", LongIdentifierCode, _eipiels_ext),
        ByteEnumField("idtype", 0, idtypes),
        ConditionalField(IntField("seqnum", 0), lambda pkt:pkt.idtype in [1, 2]),
        ConditionalField(StrLenField("id", "", length_from=lambda pkt: 0 if pkt.len is None else (pkt.len * 4)-4), lambda pkt:pkt.idtype in [0, 2])
    ]

    def extract_padding(self, p):
        return b"", p

    def _check(self):
        """
        run layer specific checks
        """
        
        if self.id is not None:
            id_len = len(self.id)
            if id_len % 4 != 0:
                raise LongIdentifierInvalidLengthField(
                    'long identifier must be in multiples of 4 octets - '
                    'got long identifier of size {}'.format(id_len))


    def post_dissect(self, s):
        self._check()
        return super().post_dissect(s)

    def do_build(self):
        self._check()
        return super().do_build()

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-4)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)
    
    
class EIPCPT(Packet):

    # we are adding by default 8 bytes MCD stack initialized with
    # 40 b"\00"

    name = "EIP CPT"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        #BitFieldLenField("len", None, 6, length_of="mcdstack", adjust=lambda _,x: int(x/4)),
        #FieldLenField("lennew", None, length_of="hmac", fmt="B"),
        ShortEnumField("type", CPTCode, _eipiels_ext),
        BitField("subtype", 0, 3),
        BitField("reserved", 0, 5),
        XStrLenField("mcdstack", 40 * b"\x00", length_from=lambda pkt: 0 if pkt.len is None else (pkt.len * 4)-4)
    ]

    def extract_padding(self, p):
        return b"", p

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-4)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)

    def _check(self):
        """
        run layer specific checks
        """
        mcdstack_len = len(self.mcdstack)
        pass  # TODO: add checks on the MCD length

    def post_dissect(self, s):
        self._check()
        return super().post_dissect(s)

    def do_build(self):
        self._check()
        return super().do_build()
    
    
class EIPHmac(Packet):

    # we are adding by default 8 bytes HMAC initialized with
    # b"\00\01\02\03\04\05\06\07"
    # we are also adding a key id inizialized with 0x1234

    name = "EIP HMAC"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        #BitFieldLenField("len", None, 6, length_of="hmac", adjust=lambda _,x: int((x+4)/4)),
        #FieldLenField("lennew", None, length_of="hmac", fmt="B"),
        ShortEnumField("type", HmacCode, _eipiels_ext),
        ByteField("reserved", 0x00),
        IntField("keyid", 0),
        XStrLenField("hmac", b"", length_from=lambda pkt: 0 if pkt.len is None else (pkt.len * 4)-4)
    ]

    def extract_padding(self, p):
        return b"", p

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-4)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)

    def _check(self):
        """
        run layer specific checks
        """
        hmac_len = len(self.hmac)
        if hmac_len % 8 != 0 or hmac_len > 32:
            raise HMACInvalidLengthField(
                'hmac must be in multiples of 8 octets, at most 32 octets long - '
                'got hmac of size {}'.format(hmac_len))

    def post_dissect(self, s):
        self._check()
        return super().post_dissect(s)

    def do_build(self):
        self._check()
        return super().do_build()


class EIPGSRPositionGeohashShort(Packet):
    """Position Field for Geohash Short"""
    name = "Position for GSR (Geohash Short)"
    fields_desc = [
        BitField("lat", 0, 15),
        BitField("long", 0, 15),
        BitField("padding", 0, 2),
    ]


class EIPGSRPositionGeohashLong(Packet):
    """Position Field for Geohash Long"""
    name = "Position for GSR (Geohash Long)"
    fields_desc = [
        BitField("lat", 0, 30),
        BitField("long", 0, 30),
        BitField("padding", 0, 4),
    ]
    
    
class EIPGSR(Packet):

    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |1 0|  Length   |Geotagging for Semantic Routing|Type |   RES   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Position (Variable)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    GEOHASH_SHORT = 0b000
    GEOHASH_LONG = 0b001

    GSR_TYPES = {
        GEOHASH_SHORT: "Geohash Short",
        GEOHASH_LONG: "Geohash Long",
    }

    name = "EIP Geotagging for Semantic Routing (GSR)"
    fields_desc = [
        BitField("code", 2, 2),
        BitField("len", None, 6),
        ShortEnumField("type", GSRCode, _eipiels_ext),
        BitEnumField("gsrtype", GEOHASH_SHORT, 3, GSR_TYPES),
        BitField("reserved", 0, 5),
        MultipleTypeField(
            [
                # Position for Geohash Short
                (PacketField("position", EIPGSRPositionGeohashShort, EIPGSRPositionGeohashShort), lambda pkt: pkt.gsrtype == EIPGSR.GEOHASH_SHORT),
                # Position for Geohash Long
                (PacketField("position", EIPGSRPositionGeohashLong, EIPGSRPositionGeohashLong), lambda pkt: pkt.gsrtype == EIPGSR.GEOHASH_LONG),
            ],
            StrLenField("position", "", length_from=lambda pkt: pkt.len * 4)
        )
    ]

    def extract_padding(self, p):
        return b"", p

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.len is None:
            var_len = int((len(pkt)-4)/4)
            my_list = [pkt[0] | var_len ]
            pkt = bytes(my_list) + pkt[1:]
            
        return super().post_build(pkt, pay)


class EipIeUnknown(Packet):

    name = "EIP Unknown Information Element"

    fields_desc = [
        BitField("code", 2, 2),
        BitFieldLenField("len", None, 6, length_of="value", adjust=lambda pkt,x: int((x+4)/4)),
        NBytesField("unknown",None,3),
        StrLenField("value", "", length_from=lambda pkt: 0 if pkt.len is None else (pkt.len * 4)-4)
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
    ShortIdentifierCode: EIPShortIdentifier,
    ProcessingAcceleratorCode: EIPProcessingAccelerator,
    TimestampCode: EIPTimestamp,
}


_eipiels_ext_cls = {
    HmacCode: EIPHmac,
    CPTCode: EIPCPT,
    LongIdentifierCode: EIPLongIdentifier,
    GSRCode: EIPGSR,
}


_hbhoptcls [0x3e] = EIP
_hbhopts[0x3e] = "EIP"
