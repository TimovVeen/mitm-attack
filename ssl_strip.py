import packet_sniffer
import requests

from enum import Enum
class HttpRequestType(Enum):
    GET = 1
    POST = 2

    
def check_packet(pkt, args):
    if pkt.haslayer(HTTP):
        print("http     - {}".format(pkt.show()))

        
    return pkt


def ssl_request(type: HttpRequestType, url: str, data: dict = None, headers: dict = None, cookies: dict = None):
    r = None
    if type == HttpRequestType.GET:
        r = requests.get(url, params=data, headers=headers, cookies=cookies)
    elif type == HttpRequestType.POST:
        r = requests.post(url, json=data, headers=headers, cookies=cookies)

    return (r, r.url, r.text, r.status_code, r.headers, r.cookies, r.content)