from urllib import response
import requests

res=requests.get('https://www.google.com')
print(res.content)