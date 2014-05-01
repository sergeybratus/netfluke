#!/usr/bin/env python

#
#  Methods to create and configure a TAP interface in pure python. 
#
#  https://github.com/montag451/pytun may be a better choice, but
#   it requires compiling a C extension, which may be a burden on a Mac
#   without XCode installed.
#

import os, sys
import fcntl
import struct
import subprocess

#
#  Let's try for a generic open
#
def open(ifname):
    if sys.platform == 'linux2' :
      return open_tap_linux(ifname)
    elif sys.platform == 'darwin' :
      return open_tap_macos(ifname)
    else:
      print "Don't have a generic open for platform %s\n" % sys.platform
      return None, None
    
#-------[ Begin OS-specific setup ] ---------
# Linux: -------------------------
#
# Constants needed to make a "magic" call to /dev/net/tun to create
#  a tap0 device that reads and writes raw Ethernet packets

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
TUNMODE = IFF_TAP
TUNSETOWNER = TUNSETIFF + 2

# Open TUN device file, create tap0
#
#  To open a new transient device, put "tap%d" into ioctl() below.
#   To open a persistent device, use "tap0" or the actual full name.
#
#  You can create a persistent device with "openvpn --mktun --dev tap0".
#   This device will show up on ifconfig, but will have "no link" unless  
#   it is opened by this or similar script even if you bring it up with
#   "ifconfig tap0 up". This can be confusing.
#
#  Copied from https://gist.github.com/glacjay/585369 
#   IFF_NO_PI is important! Otherwise, tap will add 4 extra bytes per packet, 
#     and this will confuse Scapy parsing.

def open_tap_linux(ifname = "tap0"):
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifs = fcntl.ioctl(tun, TUNSETIFF, struct.pack("16sH", ifname, TUNMODE | IFF_NO_PI))
    granted_ifname = ifs[:16].strip("\x00")  # will be tap0
    #  Optionally, we want tap0 be accessed by the normal user.
    fcntl.ioctl(tun, TUNSETOWNER, 1000)
    print "Allocated interface %s. Don't forget to configure it!" % granted_ifname
    return tun, granted_ifname

# MacOS X: -------------------------
#
#  For Mac OS X, there is no /dev/net/tun to do ioctls on. Instead, 
#     you need to load tap.kext to create /dev/tap0 ... /dev/tapN and
#     then open /dev/tap0 directly. 
#  A usable binary version of tap.kext comes with TunnelBlick:
#     Since in a typical configuration TunnelBlick only uses /dev/tunX not tap0,
#     it seems that you can load tap.kext without interfering with openvpn.
#
#subprocess.check_call("kextload /Applications/Tunnelblick.app/Contents/Resources/tap.kext", shell=True)
#
#  Alternatively MacPorts has a package tuntaposx ("port install tuntaposx").
#     Note: you can only have one version loaded at a time! kextunload if needed,
#           check with kextstat 
#
#  Cisco's Anyconnect VPN client would also interfere, see http://tuntaposx.sourceforge.net/faq.xhtml
#     for commands to stop it and load/unload kernel drivers.

def open_tap_macos(ifname='tap0'):
    subprocess.check_call("kextload /opt/local/Library/Extensions/tap.kext", shell=True)
    tun = os.open("/dev/%s" % ifname, os.O_RDWR)
    # Seems like the right IFF_NO_PI setting is default on Mac, no need for ioctl.
    print "Allocated interface %s. Don't forget to configure it!" % ifname
    return tun, ifname

#-------[ end OS-specific setup ] ---------

