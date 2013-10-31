#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#   Create fake MAC addresses on the fly.
#

from scapy.all import *

import os

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

  elif packet.haslayer(DNS) and packet[DNS].qr == 0:
    print "Get DNS request: "
    print packet.summary()
    print packet.show()
    dns_req_dns_layer = packet[DNS].copy()
    dns_req_fwd = IP(dst="8.8.8.8")/UDP()/dns_req_dns_layer
    dns_res=srp1(Ether()/dns_req_fwd) 
    #sendp(Ether()/dns_req_fwd, iface="eth1")
    
    print "8.8.8.8 returns:"
    print dns_res.summary()
    print dns_res.show()
   
    print "crafting DNS response:"
    dns_res_copy = dns_res.copy()


    dns_res_copy[IP].src="10.5.0.20"
    dns_res_copy[IP].dst="10.5.0.1"
    dns_res_copy[IP].chksum=None

    s1, s2, s3, s4 = dns_res_copy[IP].src.split('.')
    fake_src_mac = "01:02:03:04:05:" + ("%02x" % int(s4))  

    dns_res_copy[Ether].src=fake_src_mac
    dns_res_copy[Ether].chksum=None
    
    dns_res_copy[UDP].dport=packet.sport
    dns_res_copy[UDP].chksum=None

    del(dns_res_copy[UDP].len)
    del(dns_res_copy[IP].len)

    dns_rpl = Ether(src=fake_src_mac, dst=packet.src)/dns_res_copy[IP]

    print dns_rpl.summary()
    print dns_rpl.show()

    print "writing back to kernel"
    #wireshark(dns_rpl)
    os.write(tun, dns_rpl.build() )
    

  else:      # just print the packet. Use "packet.summary()" for one-line summary
    print "Unknown packet: "
    print packet.summary()