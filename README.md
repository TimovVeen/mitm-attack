# mitm-attack
==============================================================================
==============================================================================


                       @@@@@@@   @@   @@@@@@  @@@@@@@
                       @  @  @   @@     @@    @  @  @
                       @  @  @   @@     @@    @  @  @ 
                       @  @  @   @@     @@    @  @  @
                       @     @   @@     @@    @     @ 

                        ARP poisoning/spoofing tool

                 Copyright 2022 Microsoft Tech Support Team

==============================================================================
==============================================================================

This is the manual for our MITM tool group 20 Lab on Offensive Computer Security

==============================================================================
                R E Q U I R E D   I N S T A L L A T I O N S
==============================================================================

    - Python 3
    - Scapy
    
==============================================================================
                                M A N U A L
==============================================================================

To start the MITM tool, use the following command in the program directory:
  sudo python3 arp-poisoning.py <args>

The following arguments can be passed to define the behaviour of the tool:
  -h, --help                    show arguments in command line
  -t, --target [TARGETS ...]    provide array of ip-addresses to poison <REQUIRED>
  -g, --gateway [GATEWAYS ...]  provide second array of addresses. if empty this will be equal to the array or targets
  -i, --iface IFACE             provide the network interface on which packets will be sniffed and sent [default: enp0s3]
  -o, --oneway                  enable one-way poisoning (only targets -> gateways)
  -z, --silent                  enable silent poisoning
  -d, --dns                     enable dns-spoofing
  -u --url [URLS ...]           provide array or URLs to spoof, the last element is the ip victims will be redirected to
  -s, --ssl                     enable ssl-stripping
  -v, --verbose                 enable verbose mode (more comments)
