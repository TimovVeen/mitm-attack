import ssl
import socket
from scapy.all import *
load_layer("http")



import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import scapy.config

HOST, PORT = 'google.com', 443

# hostname = 'www.python.org'
# context = ssl.create_default_context()

# # with socket.create_connection((hostname, 443)) as sock:
# with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#     print(ssock.version())
#     # ssock.send(req)
#     # print(ssock.recv(1280))

# import socket
dn = 'www.google.com'

# Get the IP address of a Google HTTP endpoint
l = socket.getaddrinfo(dn, PORT, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
assert len(l) > 0, 'No address found :('

s = socket.socket(l[0][0], l[0][1], l[0][2])
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if hasattr(socket, 'SO_REUSEPORT'):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
ip_and_port = l[0][4]

print(ip_and_port)

context = ssl.create_default_context()
with context.wrap_socket(s, server_hostname=HOST) as ssl_sock:

    ssl_sock.connect(ip_and_port)

    # print(ssock.version())
    scapy.config.conf.debug_dissector = True
    print(h2.H2Frame.Raw)
    ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
    srv_set = ss.recv()
    srv_set.show()