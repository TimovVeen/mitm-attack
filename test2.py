from scapy.all import *
load_layer("http")
import requests
import traceback
from enum import Enum
class HttpRequestType(Enum):
    GET = 1
    POST = 2

def ssl_request(type: HttpRequestType, url: str, data: dict = None, headers: dict = None, cookies: dict = None):
    r = None
    if type == HttpRequestType.GET:
        r = requests.get(url, params=data, headers=headers, cookies=cookies)
    elif type == HttpRequestType.POST:
        r = requests.post(url, json=data, headers=headers, cookies=cookies)

    return (r, r.url, r.content, r.status_code, r.headers, r.cookies, r.content)


def print_response(r):
    print("url: {}".format(r.url))
    print("status: {}".format(r.status_code))
    print("headers: {}".format(r.headers))
    print("cookies: {}".format(r.cookies))
    print("content: {}".format(r.content.decode("utf-8")))

def parse_URL(url: str):
    if url.startswith('https://'):
        url.replace('https://', 'http://')
    elif url.startswith('http://'):
        url.replace('http://', 'https://')
    return url

def http_request(type: HttpRequestType, url: str, content: str, headers: dict = None, cookies: dict = None):
    pkt = Ether/IP()/TCP()/HTTP()/HTTPResponse(Server = parse_URL(url))/content

(r, url, content, status, headers, cookies, content) = ssl_request(HttpRequestType.GET, 'https://www.google.com')
# print_response(r)

pkt = http_request(HttpRequestType.GET, r.url, r.content.decode("utf-8"), r.headers, r.cookies)
# pkt.show()
print(pkt)
traceback.print_exc()