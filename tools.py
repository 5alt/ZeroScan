# coding=utf8
import dns.resolver
import os
import socket
import tldextract
import requests
'''
answers = dns.resolver.query('www.qq.com', 'CNAME')
print ' query qname:', answers.qname, ' num ans.', len(answers)
for rdata in answers:
	print ' cname target address:', rdata.target
'''

def get_domain(domain):
	r = tldextract.extract(domain)
	return "%s.%s" % (r.domain, r.suffix)

def get_cname(domain):
	try:
		return str(dns.resolver.query(domain, 'CNAME')[0].target).strip('.')
	except:
		return False

def get_cdn(domain, cname=None):
	'''
	cdn if has cname and cname do not match
	'''
	if not cname:
		cname = get_cname(domain)
	return get_domain(cname) != get_domain(domain) if cname else False

def check_extensive_domain(domain):
	try:
		#dns.resolver.query('fuckyou23333333.'+domain, 'A')
		return True, dns.resolver.query('salt66666666666.'+domain, 'A').response.answer[0][0].address
	except:
		return False, None


def scanableSubDomain(domain):
	ret = []
	if list(domain).count('.') >= 3:
		parts = domain.split('.')
		ret.append('.'.join(parts[1:]))
		ret += scanableSubDomain('.'.join(parts[1:]))
	return ret

def ip2int(ip):
	return reduce(lambda x,y:(x<<8)+y,map(int,ip.split('.')))

def is_internal_ip(ip):
	try:
		ip = ip2int(ip)
	except:
		return False
	net_a = ip2int('10.255.255.255') >> 24
	net_b = ip2int('172.31.255.255') >> 20
	net_c = ip2int('192.168.255.255') >> 16
	return ip >> 24 == net_a or ip >>20 == net_b or ip >> 16 == net_c

def resolve_host_ip(host):
	ret = set()
	try:
		r = socket.getaddrinfo(host, None)
		for i in r:
			if ':' not in i[4][0]:
				ret.add(i[4][0])
	except Exception as e:
		pass
	return list(ret)

def check_cloud(ip):
	cloud = [u'腾讯云', u'阿里云']
	ret = requests.get('http://ip.cn/index.php?ip='+ip, headers={'User-Agent': 'curl/7.54.0'}).text

	for c in cloud:
		if c in ret:
			return True

	return False

def report(data, outname="report.html"):
	table_first_template = '''<tr>
			  <th scope="row" rowspan="{num}">{ip}</th>
			  <td rowspan="{num}">{ports}</td>
			  <td><a href="http://{domain}">{domain}</a></td>
			</tr>
	'''

	table_other_template = '''<tr>
			  <td><a href="http://{domain}">{domain}</a></td>
			</tr>
	'''

	html_file = '''
	<head>
	<!-- 最新版本的 Bootstrap 核心 CSS 文件 -->
	<link rel="stylesheet" href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

	<!-- 可选的 Bootstrap 主题文件（一般不用引入） -->
	<link rel="stylesheet" href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">

	<!-- 最新的 Bootstrap 核心 JavaScript 文件 -->
	<script src="https://cdn.bootcss.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
	</head>
	<table class="table table-bordered">
		  <thead>
			<tr>
			  <th scope="row">ip</th>
			  <th>开放端口</th>
			  <th>绑定域名</th>
			</tr>
		  </thead>
		  <tbody>
		  %s
		  </tbody>
		</table>
	'''
	html = ''

	ips =  data.keys()
	ips.sort()

	for ip in ips:
		domains = data[ip]["domain"]
		ports = ", ".join([str(p) for p in data[ip]["ports"]])
		for i in range(len(domains)):
			if i == 0:
				html += table_first_template.format(ip=ip, ports=ports, domain=domains[i], num=len(domains))
			else:
				html += table_other_template.format(domain=domains[i])

	with open("show.html", "w") as f:
		f.write(html_file % html)

if __name__ == '__main__':
	print get_cdn('5alt.me')
