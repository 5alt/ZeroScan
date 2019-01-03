import requests
import json

def certsh_api(domain):
    data_set = set()
    url = "https://crt.sh/?q=%25.{0}&output=json".format(domain)
    resp = requests.get(url)
    if resp.status_code != 200:
        return []
    fixed_raw = '[%s]' % str(resp.text).replace('}{', '},{')
    for cert in json.loads(fixed_raw):
        data_set.update([cert.get('name_value')])
    return data_set

def passive_search(domain):
    return certsh_api(domain)

if __name__ == '__main__':
    print passive_search('5alt.me') 
