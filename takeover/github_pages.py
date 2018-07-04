import requests

APEX_VALUES          = ['192.30.252.153', '192.30.252.154', '185.199.108.153', '185.199.109.153', '185.199.110.153', '185.199.111.153']
CNAME_VALUE          = [".github.io"]
RESPONSE_FINGERPRINT = "There isn't a GitHub Pages site here."

def detector(domain, ip, cname):
	if APEX_VALUES:
		if ip in APEX_VALUES:
			return True
	if filter(lambda x: x in cname, CNAME_VALUE):
		return True
	try:
		if RESPONSE_FINGERPRINT in requests.get('http://%s' % domain).text:
			return True
	except Exception as e:
		pass
	return False