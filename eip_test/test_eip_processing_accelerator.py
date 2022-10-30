#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPProcessingAccelerator
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_eip_processing_accelerator():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / \
        IPv6(src='faaa::1', dst='faaa::2') / \
        IPv6ExtHdrHopByHop(
        options=[
            EIP(
                ielems=[
                    EIPProcessingAccelerator(id=0x1234)
                ]
            )
        ]
    )
    wrpcap('eip_proc_acc.pcap', pkt, append=False)


if __name__ == '__main__':
    test_eip_processing_accelerator()
