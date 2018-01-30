#! /usr/bin/env python
from scapy.all import *
import os
import subprocess
import time
import sqlite3 as db
import json

import config
import helper, tools
from subdomain import virustotal, dnsdb, DuckDuckSearch, crtsh
from subdomain.GSDFA import GoogleSSLdomainFinder
import subDomainsBrute.subDomainsBrute as subDomainsBrute

class subDomainsBruteOpt:
	def __init__(self, domain, dictionary="subnames.txt"):
		self.file= "subDomainsBrute"+os.sep+"dict"+os.sep+dictionary
		self.threads = 200
		self.output = os.path.join(config.OUTPUT_DIR, '%s.txt'%domain)
		self.i = False
		self.full_scan = False


domains = helper.load_domain_from_file()
subdomains = set()
domain_ip = {}

# virustotal
for d in domains:
	subdomains.update(virustotal.passive_domain(d))

# DuckDuckSearch
for d in domains:
	#subdomains.update(DuckDuckSearch.subdomain(d))
	main_domain = tools.get_domain(d)
	duck_path = os.path.join(config.INPUT_DIR, "%s_duck.json" % main_domain)
	if os.path.exists(duck_path):
		subdomains.update(json.load(open(duck_path, 'r')))
	else:
		duck_domain = DuckDuckSearch.subdomain(duck_path)
		json.dump(duck_domain, open(duck_path, 'w'))
		subdomains.update(duck_domain)

# dnsdb
for d in domains:
	main_domain = tools.get_domain(d)
	dnsdb_path = os.path.join(config.INPUT_DIR, "%s.json" % main_domain)
	if os.path.exists(dnsdb_path):
		subdomains.update(dnsdb.parse_dnsdb_json(dnsdb_path))

# crtsh
expand_domain = set()
for d in domains:
	sub, expand = crtsh.subdomain(d)
	subdomains.update(sub)
	expand_domain.update(expand)

# GoogleSSLdomainFinder
for d in domains:
	main_domain = tools.get_domain(d)
	google_ssl_path = os.path.join(config.INPUT_DIR, "%s_google_ssl.json" % main_domain)
	if os.path.exists(google_ssl_path):
		subdomains.update(json.load(open(google_ssl_path, 'r')))
	else:
		google_ssl_domain = GoogleSSLdomainFinder(d,'show').list().keys()
		json.dump(google_ssl_domain, open(google_ssl_path, 'w'))
		subdomains.update(google_ssl_domain)

# expand domains
for domain in subdomains:
	domains.update(tools.scanableSubDomain(domain))

for domain in expand_domain:
	domains.update(tools.scanableSubDomain(domain))

# subDomainsBrute
#os.chdir('subDomainsBrute')
for domain in domains:
	isext, ip = tools.check_extensive_domain(domain)
	if not os.path.exists(os.path.join(config.OUTPUT_DIR, '%s.txt'%domain)):
		if tools.get_domain(domain) == domain:
			d = subDomainsBrute.SubNameBrute(target=domain, options=subDomainsBruteOpt(domain))
		else:
			d = subDomainsBrute.SubNameBrute(target=domain, options=subDomainsBruteOpt(domain, "next_sub.txt"))
		d.run()
		d.outfile.flush()
		d.outfile.close()
	r = helper.parse_domains_brute(domain, ip)
	subdomains.update(r.keys())
	domain_ip.update(r)
#os.chdir('..')


helper.install_domains()

sqlitepath = os.path.join(config.OUTPUT_DIR,'domains.db')
conn = db.connect(sqlitepath)
conn.text_factory = str
cursor = conn.cursor()
sql = "INSERT INTO domains(domain, ip, cname, cdn, internal) VALUES(?, ?, ?, ?, ?)"

ips = set()
cdn_ip = set()
cdn_domain = set()

for domain in subdomains:
	cname = tools.get_cname(domain)
	cdn = tools.get_cdn(domain, cname)
	ipl = domain_ip.get(domain, None)
	if cdn:
		cdn_domain.add(domain)
	if not ipl:
		ipl = tools.resolve_host_ip(domain)
	else:
		ipl = ipl.split(",")
	for ip in ipl:
		internal = tools.is_internal_ip(ip)
		if not cdn and not internal:
			ips.add(ip)
		elif cdn:
			cdn_ip.add(ip)
		try:
			status = cursor.execute(sql, (domain, ip, cname, cdn, internal))
			conn.commit()
		except Exception as e:
			print e

conn.close()

ips = ips-cdn_ip

with open(os.path.join(config.OUTPUT_DIR,config.IPS), 'w') as f:
	f.write('\n'.join(ips).strip())

recv_process = None
if ips:
	recv_process = subprocess.Popen(["python", "recv.py"])

time.sleep(5)

dst_port = (1, 65535)
for ip in ips:
	try:
		send(IP(dst=ip)/TCP(dport=dst_port,flags="S"))
	except KeyboardInterrupt:
		break
	except Exception as e:
		print e
		continue
	time.sleep(3)

print "send done"
time.sleep(120)

# second stage scan
scanned_ips = set()
conn = helper.get_ports_conn()
cur = conn.cursor()
cur.execute("SELECT * FROM open")
rows = cur.fetchall()
for row in rows:
	ip, port, service, comment = row
	scanned_ips.add(ip)
conn.close()

second_stage_ips = ips - scanned_ips

dst_port = (1, 65535)
for ip in second_stage_ips:
	try:
		send(IP(dst=ip)/TCP(dport=dst_port,flags="S"))
	except KeyboardInterrupt:
		break
	except Exception as e:
		print e
		continue
	time.sleep(3)

print "second stage send done"
time.sleep(120)

recv_process.kill()

# cdn_domain above

ip_all = {}
internal_domain = set()

conn = helper.get_domains_conn()
cur = conn.cursor()
cur.execute("SELECT * FROM domains WHERE cdn=0")
rows = cur.fetchall()
for row in rows:
	domain, ip, cname, cdn, internal = row
	if internal:
		internal_domain.add(domain)
		continue
	if not ip_all.get(ip, None):
		ip_all[ip] = {'domain': [], 'ports': [], 'service': []}
	if domain not in ip_all[ip]['domain']:
		ip_all[ip]['domain'].append(domain)
conn.close()

conn = helper.get_ports_conn()
cur = conn.cursor()
cur.execute("SELECT * FROM open")
rows = cur.fetchall()
for row in rows:
	ip, port, service, comment = row
	ip_all[ip]['ports'].append(port)
	ip_all[ip]['service'].append(service)
conn.close()

json.dump(ip_all, open(os.path.join(config.OUTPUT_DIR, "ip_all.json"), "w"))
json.dump(list(cdn_domain), open(os.path.join(config.OUTPUT_DIR, "cdn_domain.json"), "w"))
json.dump(list(internal_domain), open(os.path.join(config.OUTPUT_DIR, "internal_domain.json"), "w"))

tools.report(ip_all, outname=config.REPORT_FILENAME)
