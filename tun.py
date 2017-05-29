#!/usr/bin/env python

#
#  Open and configure a tun (not tap) interface, print packets routed
#   to it by the kernel.
#

from scapy.all import *

import os
import subprocess

import pytap    # my wrapper around basic system-specific syscalls

tun, ifname = pytap.open('tun0') 
print "Allocated interface %s. Configuring it." % ifname

# Change as needed. Note that "ping 10.5.0.1" would not produce
#   any packets arriving at tun0, but "ping 10.5.0.x" where x=2..254 will. 
subprocess.check_call("ifconfig %s 10.5.0.1 up" % ifname, shell=True)
subprocess.check_call("route add -net 10.5.0.0 netmask 255.255.255.0 dev %s" % ifname, shell=True)

#  Now process packets
while 1:
  binary_packet = os.read(tun, 2048)   # get packet that got routed to our "network"
  
  # The packet may be IPv4 or IPv6.
  #   Parsing IPv6 as IPv4 will give strange results, so check version first.
  if ord(binary_packet[0]) & 0xf0 == 0x60 :
    packet = IPv6(binary_packet)  # Scapy parses byte string into a packet object
  else:
    packet = IP(binary_packet)    
  print packet.summary()
  print hexdump(packet)

  

