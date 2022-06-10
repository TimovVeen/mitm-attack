import packet_sniffer

def check_packet(pkt):
    if pkt.haslayer(DNS):
        print("     - {}".format(pkt[DNS].show()))
    return pkt

if __name__ == "__main__":
    packet_sniffer.main(check_packet)
    print("Done")
