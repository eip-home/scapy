#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPCPT, MCDElementUltra
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_cpt():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
        options=[
            EIP(
                ielems=[
                    EIPCPT(
                        cpttype=EIPCPT.CPT_ULTRA,
                        mcdstack=[
                            MCDElementUltra(ts=1, intf=2, load=4) /
                            MCDElementUltra(ts=2, intf=2, load=4)
                        ]
                    )
                ]
            )
        ]
    )
    wrpcap('eip_cpt.pcap', pkt, append=False)


if __name__ == '__main__':
    test_cpt()
