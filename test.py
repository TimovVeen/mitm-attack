from itertools import count
from scapy.all import *

iface="Ethernet"

ipa="224.0.0.252"
# while True:
#     pkt = sniff(count=1, iface=iface, filter="not arp and not icmp and ether dst "+"b4:2e:99:f1:f7:db"+" and not ip dst "+"192.168.2.254")[0]
#     pkt.show()

def get_mac(ip):
    arp_request_broadcast = Ether(src="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) # Broadcast MAC address: ff:ff:ff:ff:ff:ff
    # Get list with answered hosts
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, iface=iface)[0]
    return answered_list[0][1].hwsrc if len(answered_list) > 0 else 0

print(get_mac(ipa))