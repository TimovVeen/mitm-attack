from http.cookies import SimpleCookie
import scapy.all as S
S.load_layer("http")
import requests
import traceback
from enum import Enum
class HttpRequestType(Enum):
    GET = 1
    POST = 2

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

def print_response(r):
    print("url: {}".format(r.url))
    print("status: {}".format(r.status_code))
    print("headers: {}".format(r.headers))
    print("cookies: {}".format(r.cookies))
    print("content: {}".format(r.content.decode("utf-8")))

def http_response(ssl_response, http_request):
    (url, content, headers, cookies) = parse_ssl_response(ssl_response)
    
    pkt =   S.Ether(src = http_request[S.Ether].dst, dst = http_request[S.Ether].dst)/\
            S.IP(src = http_request[S.IP].dst, dst = http_request[S.IP].src)/\
            S.TCP(sport = http_request[S.TCP].dport, dport = http_request[S.TCP].sport, seq = http_request[S.TCP].ack, ack = http_request[S.TCP].seq + len(http_request[S.TCP]))/\
            HTTP()/\
            HTTPResponse(Server = url, Set_Cookie = cookies)/\
            content

    return pkt

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



def parse_ssl_response(response):
    url = response.url
    if url.startswith('https://'):
        url.replace('https://', 'http://')
    
    cookie_string = "; ".join([str(x)+"="+str(y) for x,y in response.cookies.items()])
    
    pkt =   S.Ether(src = http_request[S.Ether].dst, dst = http_request[S.Ether].dst)/\
            S.IP(src = http_request[S.IP].dst, dst = http_request[S.IP].src)/\
            S.TCP(sport = http_request[S.TCP].dport, dport = http_request[S.TCP].sport, seq = http_request[S.TCP].ack, ack = http_request[S.TCP].seq + len(http_request[S.TCP]))/\
            HTTP()/\
            HTTPResponse(Server = url, Set_Cookie = cookie_string)/\
            content
    
    return (url, r.content.decode("utf-8"), r.headers, cookie_string)
    




http_request = S.Ether()/S.IP()/S.TCP()/HTTP()/HTTPRequest(Host = 'www.google.com')
print(http_request.summary())

r = ssl_request(http_request)
print_response(r)

pkt = http_response(HttpRequestType.GET, http_request,  r.url, r.content.decode("utf-8"), r.headers, r.cookies)
pkt.show()
print(pkt.summary())
traceback.print_exc()








        