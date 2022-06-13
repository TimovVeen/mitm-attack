import packet_sniffer

def check_packet(pkt):
    if pkt.haslayer(HTTP):
        print("http     - {}".format(pkt.show()))
    if pkt.haslayer(TCP):
        print("tcp     - {}".format(pkt.show()))
        
    return pkt

if __name__ == "__main__":
    packet_sniffer.main(check_packet)
    print("Done")
