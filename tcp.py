#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#  Present a 'rot13' TCP echo service on any IP and port.  
#

from scapy.all import *

import os
import codecs # for rot13

# my pytab wrapper around basic system-specific syscalls
import pytap

tun, ifname = pytap.open('tap0') 
print "Allocated interface %s. Configuring it." % ifname
pytap.configure_tap(ifname, '01:02:03:04:05:01', '10.5.0.1')

# About-face for a packet: swap src and dst in specified layer
def swap_src_and_dst(pkt, layer):
  pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst 

#
#  Now process packets
#
while 1:
  binary_packet = os.read(tun, 2048)   # get packet routed to our "network"
  packet = Ether(binary_packet)        # Scapy parses byte string into its packet object

  if packet.haslayer(ICMP) and packet[ICMP].type == 8 : # ICMP echo-request
    pong = packet.copy() 
    swap_src_and_dst(pong, Ether)
    swap_src_and_dst(pong, IP)
    pong[ICMP].type='echo-reply'
    pong[ICMP].chksum = None   # force recalculation
    pong[IP].chksum   = None
    os.write(tun, pong.build())  # send back to the kernel

  elif packet.haslayer(ARP) and packet[ARP].op == 1 : # ARP who-has
    arp_req = packet;  # don't need to copy, we'll make reply from scratch

    # make up a new MAC for every IP address, using the address' last octet 
    s1, s2, s3, s4 = arp_req.pdst.split('.')
    fake_src_mac = "01:02:03:04:05:" + ("%02x" % int(s4))  

    # craft an ARP response
    arp_rpl = Ether(dst=arp_req.hwsrc, src=fake_src_mac)/ARP(op="is-at", psrc=arp_req.pdst, pdst="10.5.0.1", hwsrc=fake_src_mac, hwdst=arp_req.hwsrc)
    os.write(tun, arp_rpl.build() ) # send back to kernel

  elif packet.haslayer(TCP) and packet[TCP].flags & 0x02 :  # SYN, respond with SYN+ACK
    synack = packet.copy()
    swap_src_and_dst(synack, Ether)
    swap_src_and_dst(synack, IP)
    tcp = synack[TCP]
    tcp.sport, tcp.dport = tcp.dport, tcp.sport 
    tcp.ack = packet[TCP].seq +1 
    tcp.seq = 0x1000
    tcp.flags |= 0x10    # add ACK
    synack[IP].chksum = None
    synack[TCP].chksum = None

    os.write(tun, synack.build() )

  elif packet.haslayer(TCP) and packet[TCP].flags & 0x10 and packet.haslayer(Raw) and len(packet[Raw].load) > 0 :  # data, echo it back
    ack = packet.copy()
    swap_src_and_dst(ack, Ether)
    swap_src_and_dst(ack, IP)
    tcp = ack[TCP]
    tcp.sport, tcp.dport = tcp.dport, tcp.sport 
    tcp.ack = packet[TCP].seq + len(packet[Raw].load) 
    tcp.seq = packet[TCP].ack

    # extract TCP's payload with packet[Raw].load
    ack[Raw].load = codecs.encode( ack[Raw].load, 'rot13')

    tcp.flags |= 0x10    # add ACK
    ack[IP].chksum = None
    ack[TCP].chksum = None

    os.write(tun, ack.build() )
  elif packet.haslayer(IPv6) :    # ignore it
    pass
  else:      # just print the packet. Use "packet.summary()" for one-line summary, "packet.show()" for detailed parse. 
    print "Unhandled packet: " + packet.summary()
