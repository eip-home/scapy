#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPShortIdentifier
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_eip_short_identifier():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
            options=[
                EIP(
                    ielems=[
                        EIPShortIdentifier(id=0x1234)
                    ]
                )
            ]
    )
    wrpcap('eip_short.pcap', pkt, append=False)


if __name__ == '__main__':
    test_eip_short_identifier()
