# https://docs.microsoft.com/en-us/azure/traffic-manager/traffic-manager-overview
# https://xz.aliyun.com/t/4673
import requests
from tools import resolve_host_ip

APEX_VALUES          = None
CNAME_VALUE          = [".herokudns.com"]

def detector(domain, ip, cname):
	if APEX_VALUES:
		if ip in APEX_VALUES:
			return True
	if filter(lambda x: x in cname, CNAME_VALUE):
		try:
			if resolve_host_ip(cname):
				return True
		except Exception as e:
			pass
	return False
