import requests
import json

def passive_domain(domain):
	subdomains = set()
	try:
		# virusTotalApi
		virusTotalApiKey = "9ca790fe3dde490e8fbb5190aa2b2b2ab2406f31e174eb51c37f74a8f88ef1a6"
		url = 'https://www.virustotal.com/vtapi/v2/domain/report'
		parameters = {'domain': domain, 'apikey': virusTotalApiKey}
		domains = requests.get(url, params = parameters).json()["subdomains"]
		for i in domains: subdomains.add(i)
	except Exception as e:
		print e
	return subdomains

if __name__ == '__main__':
	print passive_domain("5alt.me")
