#!/usr/bin/python

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.eip import EIP, EIPCPT, EIPGSR, EIPGSRPositionGeohashLong, EIPGSRPositionGeohashShort, EIPHmac, EIPProcessingAccelerator, EIPShortIdentifier, EIPLongIdentifier, EIPTimestamp
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_eip_short_identifier():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(id=0x1234)])])
    wrpcap('eip_short.pcap', pkt, append=False)


def test_eip_hmac():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPHmac(keyid=0x1234, hmac=b'\x00\x01\x02\x03\x04\x05\x06\x07')])])
    wrpcap('eip_hmac.pcap', pkt, append=False)


def test_eip_long_identifier():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPLongIdentifier(idtype=2, seqnum=0x1234, id=b"\x00\x01\x02\x03\x04\x05\x06\07")])])
    wrpcap('eip_long_id.pcap', pkt, append=False)


def test_eip_processing_accelerator():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPProcessingAccelerator(id=0x1234)])])
    wrpcap('eip_proc_acc.pcap', pkt, append=False)

def test_short_hmac():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(id=0x1234), EIPHmac(keyid=0x1234, hmac=b'\x00\x01\x02\x03\x04\x05\x06\x07')])])
    wrpcap('eip_short_hmac.pcap', pkt, append=False)

def test_short_hmac_long():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(id=0x1234), EIPHmac(keyid=0x1234, hmac=b'\x00\x01\x02\x03\x04\x05\x06\x07'), EIPLongIdentifier(idtype=2, seqnum=0x1234, id=b"\x00\x01\x02\x03\x04\x05\x06\07")])])
    wrpcap('eip_short_hmac_long.pcap', pkt, append=False)

def test_timestamp():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp(tstype=2, tslen=2, tsformat=2, timestamps=[1, 2, 3, 4])])])
    #           IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp()])])
    #            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp(tstype=2, tslen=2, tsformat=2, timestamps=[1, 2, 3, 4])])])
    #            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp()])])
    wrpcap('eip_timestamp.pcap', pkt, append=False)

def test_geohash_short():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPGSR(gsrtype=EIPGSR.GEOHASH_SHORT, position=EIPGSRPositionGeohashShort(lat=0x1234, long=0x5678))])])
    #           IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp()])])
    #            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp(tstype=2, tslen=2, tsformat=2, timestamps=[1, 2, 3, 4])])])
    #            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp()])])
    wrpcap('eip_geohash_short.pcap', pkt, append=False)

def test_geohash_long():
    pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
                IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPGSR(gsrtype=EIPGSR.GEOHASH_LONG, position=EIPGSRPositionGeohashLong(lat=0x1234, long=0x5678))])])
    #           IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp()])])
    #            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp(tstype=2, tslen=2, tsformat=2, timestamps=[1, 2, 3, 4])])])
    #            IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPTimestamp()])])
    wrpcap('eip_geohash_long.pcap', pkt, append=False)


if __name__ == '__main__':
    #pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / IPv6ExtHdrHopByHop(options=[EIP()])
    #pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(), EIPShortIdentifier()])])
    #pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
    #        IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(), EIPHmac()])])
    #        IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPShortIdentifier(), EIPShortIdentifier(), EIPShortIdentifier()])])
    #pkt = Ether(src='90:e2:ba:84:d5:ec', dst='90:e2:ba:84:d7:78') / IPv6(src='faaa::1', dst='faaa::2') / \
    #        IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPHmac(hmac=b'\x00\x01\x02\x03\x04\x05\x06\x07')])])
    #        IPv6ExtHdrHopByHop(options=[EIP(ielems=[EIPCPT(mcdstack=b'\x00\x01\x02\x03\x04\x05\x06\x07')])])
    #wrpcap('eip_hmac.pcap', pkt, append=False)
    test_eip_short_identifier()
    test_eip_hmac()
    test_eip_long_identifier()
    test_eip_processing_accelerator()
    test_short_hmac()
    test_short_hmac_long()
    test_timestamp()
    test_geohash_short()
    test_geohash_long()
