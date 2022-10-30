#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPHmac, EIPShortIdentifier, EIPLongIdentifier
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_short_hmac_long():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
        options=[
            EIP(
                ielems=[
                    EIPShortIdentifier(id=0x1234),
                    EIPHmac(
                        keyid=0x1234,
                        hmac=b'\x00\x01\x02\x03\x04\x05\x06\x07'
                    ),
                    EIPLongIdentifier(
                        idtype=2,
                        seqnum=0x1234,
                        id=b"\x00\x01\x02\x03\x04\x05\x06\07"
                    )
                ]
            )
        ]
    )
    wrpcap('eip_short_hmac_long.pcap', pkt, append=False)


if __name__ == '__main__':
    test_short_hmac_long()
