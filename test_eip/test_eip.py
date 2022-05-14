#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPHmac, EIPShortIdentifier
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


if __name__ == '__main__':
    #pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / IPv6ExtHdrHopByHop(options=[EIP()])
    #pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(), EIPShortIdentifier()])])
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(), EIPHmac()])])
    wrpcap('eip.pcap', pkt, append=False)
