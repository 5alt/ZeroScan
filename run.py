#! /usr/bin/env python
from scapy.all import *
import os
import subprocess
import time
import sqlite3 as db
import json
import imp

import config
import helper, tools
import subDomainsBrute.subDomainsBrute as subDomainsBrute

class subDomainsBruteOpt:
    def __init__(self, domain, dictionary="subnames.txt"):
        self.file= "subDomainsBrute"+os.sep+"dict"+os.sep+dictionary
        self.threads = 200
        self.output = os.path.join(config.OUTPUT_DIR, '%s.txt'%domain)
        self.i = False
        self.full_scan = False

def load_modules(path):
    modules = []
    for f in os.listdir(path):
        if f.endswith('.py') and not f.endswith('__init__.py'):
            modules.append(imp.load_source(f[:-3], path + os.sep + f))
    return modules


class DomainInfoCollection:
    def __init__(self,domains):
        self.domains = domains
        self.subdomains = set()
        self.cdn_domain = set()
        self.ips = set()
        self.domain_ip = {}
        self.internal_domain = set()
        self.ip_all = {}
        self.takeover_domain = set()
        self.takeover_domain_check = set()

    def passive_search(self):
        modules = load_modules(config.PASSIVE_SEARCH_DIR)
        for domain in self.domains:
            for module in modules:
                subdomains = module.passive_search(domain)
                subdomains = filter(lambda x: x.endswith(domain), subdomains)
                subdomains = map(lambda x: x.lower(), subdomains)
                self.subdomains.update(subdomains)

    def active_search(self):
        scanable_domain = set()
        for d in self.subdomains:
            scanable_domain.update(tools.scanable_subdomain(d))

        self.subdomains = set(filter(lambda x: not x.startswith('*.'), self.subdomains))

        for domain in scanable_domain:
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
            self.subdomains.update(r.keys())
            self.domain_ip.update(r)

    def process_subdomain(self):
        helper.install_domains()
        sqlitepath = os.path.join(config.OUTPUT_DIR,'domains.db')
        conn = db.connect(sqlitepath)
        conn.text_factory = str
        cursor = conn.cursor()
        sql = "INSERT INTO domains(domain, ip, cname, cdn, internal) VALUES(?, ?, ?, ?, ?)"

        ips = set()
        cdn_ip = set()

        for domain in self.subdomains:
            cname = tools.get_cname(domain)
            cdn = tools.get_cdn(domain, cname)
            ipl = self.domain_ip.get(domain, None)
            if cdn:
                self.cdn_domain.add(domain)
            if not ipl:
                ipl = tools.resolve_host_ip(domain)
            else:
                ipl = ipl.split(",")
            for ip in ipl:
                internal = tools.is_internal_ip(ip)
                if not cdn and not internal:
                    ips.add(ip)
                elif cdn:
                    self.takeover_domain_check.add((domain, ip, cname))
                    cdn_ip.add(ip)
                if not internal:
                    self.internal_domain.add(domain)
                try:
                    status = cursor.execute(sql, (domain, ip, cname, cdn, internal))
                    conn.commit()
                except Exception as e:
                    print e
        self.ips = ips-cdn_ip
        with open(os.path.join(config.OUTPUT_DIR,config.IPS), 'w') as f:
            f.write('\n'.join(self.ips).strip())

    def takeover(self):
        modules = load_modules(config.TAKEOVER_DIR)
        for domain, ip, cname in self.takeover_domain_check:
            for m in modules:
                if m.detector(domain, ip, cname):
                    self.takeover_domain.add(domain)
                    break

    def port_scan(self):
        recv_process = None
        if self.ips:
            recv_process = subprocess.Popen(["python", "recv.py"])

        time.sleep(5)

        dst_port = (1, 65535)
        for ip in self.ips:
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

        scanned_ips = set()
        conn = helper.get_ports_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM open")
        rows = cur.fetchall()
        for row in rows:
            ip, port, service, comment = row
            scanned_ips.add(ip)
        conn.close()

        second_stage_ips = self.ips - scanned_ips

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

    def collate(self):
        conn = helper.get_domains_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM domains WHERE cdn=0")
        rows = cur.fetchall()
        for row in rows:
            domain, ip, cname, cdn, internal = row
            if internal:
                self.internal_domain.add(domain)
                continue
            if not self.ip_all.get(ip, None):
                self.ip_all[ip] = {'domain': [], 'ports': [], 'service': []}
            if domain not in self.ip_all[ip]['domain']:
                self.ip_all[ip]['domain'].append(domain)
        conn.close()

        conn = helper.get_ports_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM open")
        rows = cur.fetchall()
        for row in rows:
            ip, port, service, comment = row
            self.ip_all[ip]['ports'].append(port)
            self.ip_all[ip]['service'].append(service)
        conn.close()

    def report(self):
        json.dump(self.ip_all, open(os.path.join(config.OUTPUT_DIR, "ip_all.json"), "w"))
        json.dump(list(self.cdn_domain), open(os.path.join(config.OUTPUT_DIR, "cdn_domain.json"), "w"))
        json.dump(list(self.internal_domain), open(os.path.join(config.OUTPUT_DIR, "internal_domain.json"), "w"))

        with open(os.path.join(config.OUTPUT_DIR, 'domain_takeover.txt'), 'a') as f:
            f.write('\n'.join(self.takeover_domain).strip())
        tools.report(self.ip_all, outname=config.REPORT_FILENAME)
        

def runall():
    targets = helper.load_domain_from_file()
    domain_info_coll = DomainInfoCollection(targets)
    domain_info_coll.passive_search()
    domain_info_coll.active_search()
    domain_info_coll.process_subdomain()
    domain_info_coll.takeover()
    domain_info_coll.port_scan()
    domain_info_coll.collate()
    domain_info_coll.report()

def runportscan():
    targets = helper.load_alldomains_from_file()
    domain_info_coll = DomainInfoCollection([])
    domain_info_coll.subdomains = targets
    domain_info_coll.process_subdomain()
    domain_info_coll.takeover()
    domain_info_coll.port_scan()
    domain_info_coll.collate()
    domain_info_coll.report()

'''
main
'''
if __name__ == '__main__':
    runall()


