import requests
import json
import os

def passive_domain(domain):
	subdomains = set()
	try:
		# virusTotalApi
		virusTotalApiKey = os.environ.get('virustotal_key')
		url = 'https://www.virustotal.com/vtapi/v2/domain/report'
		parameters = {'domain': domain, 'apikey': virusTotalApiKey}
		domains = requests.get(url, params = parameters).json()["subdomains"]
		for i in domains: subdomains.add(i)
	except Exception as e:
		print e
	return subdomains

def passive_search(domain, subdomains):
    subdomains.update(passive_domain(domain))


if __name__ == '__main__':
	print passive_domain("5alt.me")
