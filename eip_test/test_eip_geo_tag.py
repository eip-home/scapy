#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPGSR, EIPGSRPositionGeohashShort
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_geo_tag():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
        options=[
            EIP(
                ielems=[
                    EIPGSR(
                        gsrtype=EIPGSR.GEOHASH_SHORT,
                        position=EIPGSRPositionGeohashShort(lat=0x1234, long=0x5678)
                    )
                ]
            )
        ]
    )
    wrpcap('eip_geo_tag.pcap', pkt, append=False)


if __name__ == '__main__':
    test_geo_tag()
