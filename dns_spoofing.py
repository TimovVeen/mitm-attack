import packet_sniffer

def check_packet(pkt):
    if pkt.haslayer(DNS):
        print("     - {}".format(pkt.show()))
        # check for dns site
        #if site is the good one send dns response back

        # the pkt returned is the packet that will be send over the network
        
    return pkt

if __name__ == "__main__":
    packet_sniffer.main(check_packet)
    print("Done")
