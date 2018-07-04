import requests

APEX_VALUES          = ['66.6.44.4']
CNAME_VALUE          = ["domains.tumblr.com"]
RESPONSE_FINGERPRINT = "Whatever you were looking for doesn't currently exist at this address."

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