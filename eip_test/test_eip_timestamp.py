#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPTimestamp
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_timestamp():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
            options=[
                EIP(
                    ielems=[
                        EIPTimestamp(
                            tstype=2, tslen=2, tsformat=2, timestamps=[1, 2, 3, 4]
                        )
                    ]
                )
            ]
    )
    wrpcap('eip_timestamp.pcap', pkt, append=False)


if __name__ == '__main__':
    test_timestamp()
