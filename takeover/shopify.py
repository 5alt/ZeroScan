import requests

APEX_VALUES          = ['23.227.38.32']
CNAME_VALUE          = ["shops.myshopify.com"]
RESPONSE_FINGERPRINT = "Sorry, this shop is currently unavailable."

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