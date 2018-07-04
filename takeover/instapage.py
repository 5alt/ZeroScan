import requests

APEX_VALUES          = None
CNAME_VALUE          = ["pageserve.co", "secure.pageserve.co"]
RESPONSE_FINGERPRINT = "You've Discovered A Missing Link. Our Apologies!"

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