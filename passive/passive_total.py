import requests
import os

def pt_query(value):
    if not os.environ.get('passivetotal_key') or not os.environ.get('passivetotal_secret'):
        return []
    url = 'https://api.passivetotal.org/v2/enrichment/subdomains'
    auth = (os.environ.get('passivetotal_key'), os.environ.get('passivetotal_secret'))
    params = {'query': value}
    try:
        # Timeout can also act as a quasi break on hosting sites/large return values - remove the timeout if you really want the nodes
        pt_response = requests.get(url, params=params, auth=auth, timeout=60)
        if pt_response.status_code == 504: # Gateway Timeout error
            return []
        else:
            api_result = pt_response.json()
            return api_result['subdomains']
    except:
        pass
    return []
    

def passive_search(domain):
    return pt_query(domain)

if __name__ == '__main__':
    os.environ['passivetotal_key'] = ""
    os.environ['passivetotal_secret'] = ""
    print pt_query('5alt.me')