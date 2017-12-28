import json
# https://dnsdb.io/zh-cn/ 
def parse_dnsdb_json(f):
	with open(f, 'r') as fp:
		data = fp.read().strip()

	ret = set()

	for i in data.split("\n"):
		ret.add(json.loads(i)["host"])

	return ret
