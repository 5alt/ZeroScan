# coding=utf8
import dns.resolver
import os
import socket
import tldextract
import requests
import json
import re
'''
answers = dns.resolver.query('www.qq.com', 'CNAME')
print ' query qname:', answers.qname, ' num ans.', len(answers)
for rdata in answers:
	print ' cname target address:', rdata.target
'''

def check_port_service_static(port):
	port = str(port)
	data = json.load(open("dict/port_service.json", "r"))
	return data.get(port)

def check_port_service_nmap(port):
	port = str(port)
	f = open("dict/nmap-services.txt", "r")
	data = f.read()
	for line in data.split("\n"):
		parts = line.split(";")
		nmap_port = parts[1].split("/")[0]
		if port == nmap_port:
			return parts[0]
	return None

def check_port_service(host, port):
	service = check_port_service_static(port)
	if service: return service
	service = check_port_service_dynamic(host, port)
	if service != "Unknown": return service
	service = check_port_service_nmap(port)
	if service: return service
	return None

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

def check_ip(domain):
	parts = domain.split('.')
	if len(parts) == 4:
		for p in parts:
			if not p.isdigit():
				return False
		return True
	return False	

def scanable_subdomain(domain):
	ret = []
	if check_ip(domain):
		return ret
	if domain.startswith('*.'):
		return [domain[2:]]
	if list(domain).count('.') >= 3:
		parts = domain.split('.')
		ret.append('.'.join(parts[1:]))
		ret += scanable_subdomain('.'.join(parts[1:]))
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
		tmp = []
		for i in range(len(data[ip]["ports"])):
			tmp.append("%d(%s)" % (data[ip]["ports"][i], data[ip]["service"][i]))
		ports = ", ".join(tmp)
		for i in range(len(domains)):
			if i == 0:
				html += table_first_template.format(ip=ip, ports=ports, domain=domains[i], num=len(domains))
			else:
				html += table_other_template.format(domain=domains[i])

	with open("show.html", "w") as f:
		f.write(html_file % html)

def check_port_service_dynamic(host, port):
	TIMEOUT=3

	PROBES=[
	'\r\n\r\n',
	'GET / HTTP/1.0\r\n\r\n',
	'GET / \r\n\r\n',
	'\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
	'\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
	'\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
	'\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
	'\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
	'\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
	'< NTP/1.2 >\n',
	'< NTP/1.1 >\n',
	'< NTP/1.0 >\n',
	'\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
	'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
	'\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
	'\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
	'\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0'
	]

	SIGNS=[
	'http|^HTTP.*',
	'ssh|SSH-2.0-OpenSSH.*',
	'ssh|SSH-1.0-OpenSSH.*',
	'netbios|^\x79\x08.*BROWSE',
	'netbios|^\x79\x08.\x00\x00\x00\x00',
	'netbios|^\x05\x00\x0d\x03',
	'netbios|^\x83\x00',
	'netbios|^\x82\x00\x00\x00',
	'netbios|\x83\x00\x00\x01\x8f',
	'backdoor-fxsvc|^500 Not Loged in',
	'backdoor-shell|GET: command',
	'backdoor-shell|sh: GET:',
	'bachdoor-shell|[a-z]*sh: .* command not found',
	'backdoor-shell|^bash[$#]',
	'backdoor-shell|^sh[$#]',
	'backdoor-cmdshell|^Microsoft Windows .* Copyright .*>',
	'db2|.*SQLDB2RA',
	'db2jds|^N\x00',
	'dell-openmanage|^\x4e\x00\x0d',
	'finger|^\r\n	Line	  User',
	'finger|Line	 User',
	'finger|Login name: ',
	'finger|Login.*Name.*TTY.*Idle',
	'finger|^No one logged on',
	'finger|^\r\nWelcome',
	'finger|^finger:',
	'finger|^must provide username',
	'finger|finger: GET: ',
	'ftp|^220.*\n331',
	'ftp|^220.*\n530',
	'ftp|^220.*FTP',
	'ftp|^220 .* Microsoft .* FTP',
	'ftp|^220 Inactivity timer',
	'ftp|^220 .* UserGate',
	'http|^HTTP/0.',
	'http|^HTTP/1.',
	'http|<HEAD>.*<BODY>',
	'http|<HTML>.*',
	'http|<html>.*',
	'http|<!DOCTYPE.*',
	'http|^Invalid requested URL ',
	'http|.*<?xml',
	'http|^HTTP/.*\nServer: Apache/1',
	'http|^HTTP/.*\nServer: Apache/2',
	'http-iis|.*Microsoft-IIS',
	'http-iis|^HTTP/.*\nServer: Microsoft-IIS',
	'http-iis|^HTTP/.*Cookie.*ASPSESSIONID',
	'http-iis|^<h1>Bad Request .Invalid URL.</h1>',
	'http-jserv|^HTTP/.*Cookie.*JServSessionId',
	'http-tomcat|^HTTP/.*Cookie.*JSESSIONID',
	'http-weblogic|^HTTP/.*Cookie.*WebLogicSession',
	'http-vnc|^HTTP/.*VNC desktop',
	'http-vnc|^HTTP/.*RealVNC/',
	'ldap|^\x30\x0c\x02\x01\x01\x61',
	'ldap|^\x30\x32\x02\x01',
	'ldap|^\x30\x33\x02\x01',
	'ldap|^\x30\x38\x02\x01',
	'ldap|^\x30\x84',
	'ldap|^\x30\x45',
	'smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
	'msrdp|^\x03\x00\x00\x0b',
	'msrdp|^\x03\x00\x00\x11',
	'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
	'msrdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
	'msrdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
	'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
	'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
	'msrdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
	'msrdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
	'msrdp-proxy|^nmproxy: Procotol byte is not 8\n$',
	'msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
	'msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
	'mssql|^\x04\x01\0C..\0\0\xaa\0\0\0/\x0f\xa2\x01\x0e.*',
	'mssql|^\x05\x6e\x00',
	'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
	'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
	'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
	'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
	'mssql|^\x04\x01\0\x25\0\0\x01\0\0\0\x15\0\x06\x01.*',
	'mssql|^\x04\x01\x00\x25\x00\x00\x01.*',
	'telnet|^xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd.*',
	'mssql|;MSSQLSERVER;',
	'mysql|^\x19\x00\x00\x00\x0a',
	'mysql|^\x2c\x00\x00\x00\x0a',
	'mysql|hhost \'',
	'mysql|khost \'',
	'mysql|mysqladmin',
	'mysql|whost \'',
	'mysql-blocked|^\(\x00\x00',
	'mysql-secured|this MySQL',
	'mongodb|^.*version.....([\.\d]+)',
	'nagiosd|Sorry, you \(.*are not among the allowed hosts...',
	'nessus|< NTP 1.2 >\x0aUser:',
	'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
	'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
	'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
	'oracle-https|^220- ora',
	'oracle-rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
	'oracle-rmi|^\x4e\x00\x09',
	'postgres|Invalid packet length',
	'postgres|^EFATAL',
	'rlogin|login: ',
	'rlogin|rlogind: ',
	'rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
	'rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
	'rpc|\x01\x86\xa0',
	'rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
	'rpc|^\x80\x00\x00',
	'rsync|^@RSYNCD:.*',
	'smux|^\x41\x01\x02\x00',
	'snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
	'snmp|\x41\x01\x02',
	'socks|^\x05[\x00-\x08]\x00',
	'ssh|^SSH-',
	'ssh|^SSH-.*openssh',
	'ssl|^..\x04\0.\0\x02',
	'ssl|^\x16\x03\x01..\x02...\x03\x01',
	'ssl|^\x16\x03\0..\x02...\x03\0',
	'ssl|SSL.*GET_CLIENT_HELLO',
	'ssl|-ERR .*tls_start_servertls',
	'ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
	'ssl|^\x16\x03\0..\x02\0\0F\x03\0',
	'ssl|^\x15\x03\0\0\x02\x02\.*',
	'ssl|^\x16\x03\x01..\x02...\x03\x01',
	'ssl|^\x16\x03\0..\x02...\x03\0',
	'sybase|^\x04\x01\x00',
	'telnet|^\xff\xfd',
	'telnet|Telnet is disabled now',
	'telnet|^\xff\xfe',
	'tftp|^\x00[\x03\x05]\x00',
	'http-tomcat|.*Servlet-Engine',
	'uucp|^login: password: ',
	'vnc|^RFB.*',
	'webmin|.*MiniServ',
	'webmin|^0\.0\.0\.0:.*:[0-9]',
	'websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a']


	def prepsigns():
		signlist=[]
		for 	item in SIGNS:
			#print item
			(label,pattern)=item.split('|',2)
			sign=(label,pattern)
			signlist.append(sign)	
		return signlist	
		
	def matchbanner(banner,slist):
		for item in slist:
			p=re.compile(item[1])
			if p.search(banner)!=None:
				return item[0]
		return 'Unknown'

	signs = prepsigns()

	sd=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sd.settimeout(TIMEOUT)
	service='Unknown'
	try:
		sd.connect((host,port))
	except Exception as e:
		print e
		pass
	try:
		result = sd.recv(256)
		service=matchbanner(result,signs)
	except:
		for probe in PROBES:
			try:
				sd.close()
				sd=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sd.settimeout(TIMEOUT)
				sd.connect((host,port))
				sd.sendall(probe)
			except:
				continue	
			try:
				result = sd.recv(256)
				service=matchbanner(result,signs)
				if service!='Unknown':
					break
			except Exception as e:
				pass
	return service

if __name__ == '__main__':
	print get_cdn('5alt.me')
