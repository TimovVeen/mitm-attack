from itertools import count
from scapy.all import *
load_layer("http")

iface="Ethernet"

ipa="224.0.0.252"
# while True:
#     pkt = sniff(count=1, iface=iface, filter="not arp and not icmp and ether dst "+"b4:2e:99:f1:f7:db"+" and not ip dst "+"192.168.2.254")[0]
#     pkt.show()

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
# with open("test.html", "wb") as file:
    # file.write(answer.load)


import socket
import ssl
import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import scapy.config
import scapy.packet as packet

dn = 'www.google.com'

# Get the IP address of a Google HTTP endpoint
l = socket.getaddrinfo(dn, 443, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
assert len(l) > 0, 'No address found :('

s = socket.socket(l[0][0], l[0][1], l[0][2])
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if hasattr(socket, 'SO_REUSEPORT'):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
ip_and_port = l[0][4]

# Testing support for ALPN
assert(ssl.HAS_ALPN)

# Building the SSL context
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_ctx.set_ciphers(':'.join([  # List from ANSSI TLS guide v.1.1 p.51
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-SHA384',
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-ECDSA-AES128-SHA256',
                'ECDHE-RSA-AES128-SHA256',
                'ECDHE-ECDSA-CAMELLIA256-SHA384',
                'ECDHE-RSA-CAMELLIA256-SHA384',
                'ECDHE-ECDSA-CAMELLIA128-SHA256',
                'ECDHE-RSA-CAMELLIA128-SHA256',
                'DHE-RSA-AES256-GCM-SHA384',
                'DHE-RSA-AES128-GCM-SHA256',
                'DHE-RSA-AES256-SHA256',
                'DHE-RSA-AES128-SHA256',
                'AES256-GCM-SHA384',
                'AES128-GCM-SHA256',
                'AES256-SHA256',
                'AES128-SHA256',
                'CAMELLIA128-SHA256'
            ]))     
ssl_ctx.set_alpn_protocols(['h2'])  # h2 is a RFC7540-hardcoded value
ssl_sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA")

ssl_sock.connect(ip_and_port)
assert('h2' == ssl_sock.selected_alpn_protocol())

scapy.config.conf.debug_dissector = True
ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
srv_set = ss.recv()
srv_set.show()

srv_max_frm_sz = 1<<14
srv_hdr_tbl_sz = 4096
srv_max_hdr_tbl_sz = 0
srv_global_window = 1<<14
for setting in srv_set.payload.settings:
    if setting.id == h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE:
        srv_hdr_tbl_sz = setting.value
    elif setting.id == h2.H2Setting.SETTINGS_MAX_HEADER_LIST_SIZE:
        srv_max_hdr_lst_sz = setting.value
    elif setting.id == h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE:
        srv_global_window = setting.value


# We verify that the server window is large enough for us to send some data.
srv_global_window -= len(h2.H2_CLIENT_CONNECTION_PREFACE)
assert(srv_global_window >= 0)

ss.send(packet.Raw(h2.H2_CLIENT_CONNECTION_PREFACE))

set_ack = h2.H2Frame(flags={'A'})/h2.H2SettingsFrame()
set_ack.show()

own_set = h2.H2Frame()/h2.H2SettingsFrame()
max_frm_sz = (1 << 24) - 1
max_hdr_tbl_sz = (1 << 16) - 1
win_sz = (1 << 31) - 1
own_set.settings = [
    h2.H2Setting(id = h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
    h2.H2Setting(id = h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
    h2.H2Setting(id = h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
    h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
]

h2seq = h2.H2Seq()
h2seq.frames = [
    set_ack,
    own_set
]
# We verify that the server window is large enough for us to send our frames.
srv_global_window -= len(str(h2seq))
assert(srv_global_window >= 0)
ss.send(h2seq)

# Loop until an acknowledgement for our settings is received
new_frame = None
while isinstance(new_frame, type(None)) or not (
        new_frame.type == h2.H2SettingsFrame.type_id 
        and 'A' in new_frame.flags
    ):
    if not isinstance(new_frame, type(None)):
        # If we received a frame about window management 
        if new_frame.type == h2.H2WindowUpdateFrame.type_id:
            # For this tutorial, we don't care about stream-specific windows, but we should :)
            if new_frame.stream_id == 0:
                srv_global_window += new_frame.payload.win_size_incr
        # If we received a Ping frame, we acknowledge the ping, 
        # just by setting the ACK flag (A), and sending back the query
        elif new_frame.type == h2.H2PingFrame.type_id:
            new_flags = new_frame.getfieldval('flags')
            new_flags.add('A')
            new_frame.flags = new_flags
            srv_global_window -= len(str(new_frame))
            assert(srv_global_window >= 0)
            ss.send(new_frame)
        else:
            assert new_frame.type != h2.H2ResetFrame.type_id \
                and new_frame.type != h2.H2GoAwayFrame.type_id, \
                "Error received; something is not right!"
    try:
        new_frame = ss.recv()
        new_frame.show()
    except:
        import time
        time.sleep(1)
        new_frame = None