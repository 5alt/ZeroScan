import requests
import json

def certspotter_api(domain):
    data_set = set()
    url = "https://certspotter.com/api/v0/certs?domain={}".format(domain)
    subdomain_data = []
    response = requests.get(url)
    for i in range(0, len(response.json())):
        try:
            subdomain_data += response.json()[i]['dns_names']
        except:
            continue
    return set(subdomain_data)

def passive_search(domain):
    return certspotter_api(domain)

if __name__ == '__main__':
    print certspotter_api('5alt.me') 
