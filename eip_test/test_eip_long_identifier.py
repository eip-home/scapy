#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPLongIdentifier
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_eip_long_identifier():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
        options=[
            EIP(
                ielems=[
                    EIPLongIdentifier(idtype=2, seqnum=0x1234, id=b"\x00\x01\x02\x03\x04\x05\x06\07")
                ]
            )
        ]
    )
    wrpcap('eip_long_id.pcap', pkt, append=False)


if __name__ == '__main__':
    test_eip_long_identifier()
