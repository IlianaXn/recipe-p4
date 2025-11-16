#!/usr/bin/env python
import sys
import socket
import random
import time
import random

from scapy.all import sendp, sniff, get_if_list, get_if_hwaddr, wrpcap
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i: # change to interface that we have
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<4:
        print('pass 3 arguments: <destination> "<message>" <echo_count>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    message = sys.argv[2]
    echo_count = int(sys.argv[3])
    iface = get_if()

    ether_dst = "00:00:00:00:00:00"

    print("Sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt /IP(dst=addr,proto=6) / message

    sendp(pkt, iface=iface, verbose=False)
    print("Initial packet sent")
    time.sleep(0.5)

    packet_count = 0
    final_packet = None

    def packet_callback(pkt):
        nonlocal packet_count, final_packet
        packet_count += 1
        print(f"Received packet #{packet_count}")
        if packet_count <= echo_count:
            print(f"  -> Echoing back packet #{packet_count}")
            sendp(pkt, iface=iface, verbose=False)
        else:
            print(f"  -> Storing packet #{packet_count} locally")
            final_packet = pkt
            return False

    print(f"Listening on {iface} for {echo_count + 1} packets...")
    sniff(iface=iface, prn=packet_callback, count=echo_count + 1, store=False, filter="not src host " + addr)

    if final_packet:
        print("Final packet received:")
        final_packet.show2()
        if final_packet.haslayer(IP):
            ip_layer = final_packet[IP]
            payload = bytes(ip_layer.payload)
            codeword = payload[:2].hex()
            with open('codewords.txt', 'a') as f:
                f.write(f"{codeword}\n")
            print(f"Extracted codeword: {codeword} (saved to codewords.txt)")

if __name__ == '__main__':
    main()