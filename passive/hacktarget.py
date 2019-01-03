import requests
import json

def passive_domain(domain):
	try:
		# hackertarget
		url = 'https://api.hackertarget.com/hostsearch/?q=%s' % domain
		ret = [i.split(',')[0] for i in requests.get(url).text.split('\n') if i]
	except Exception as e:
		return []
	return set(ret)

def passive_search(domain):
	return passive_domain(domain)


if __name__ == '__main__':
	print passive_domain("5alt.me")
