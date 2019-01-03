import requests
import json

def passive_domain(domain):
	try:
		# hackertarget
		url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s' % domain
		ret = requests.get(url).json()["subdomains"]
	except Exception as e:
		return []
	return set(ret)

def passive_search(domain):
	return passive_domain(domain)


if __name__ == '__main__':
	print passive_domain("5alt.me")
