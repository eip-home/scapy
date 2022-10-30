#!/usr/bin/python

import sys

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPHmac, EIPShortIdentifier
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap


def dissect_pcap(filename):
    scapy_cap = rdpcap(filename)
    for packet in scapy_cap:
        packet.show()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python dissect_eip.py <pcap>')
        sys.exit()

    dissect_pcap(sys.argv[1])