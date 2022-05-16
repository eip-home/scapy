#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPHmac, EIPShortIdentifier
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

scapy_cap = rdpcap ("eip2.pcap")
for packet in scapy_cap:
    packet.show()
