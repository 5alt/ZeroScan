# coding=utf8
import config
import sqlite3 as db
import os
import requests

def load_domain_from_file():
	with open(config.INPUT_DOMAIN_FILE, 'r') as f:
		data = f.read().strip()
	return set(data.split('\n'))

def load_alldomains_from_file():
	with open(config.INPUT_ALL_DOMAINS_FILE, 'r') as f:
		data = f.read().strip()
	return set(data.split('\n'))


def load_ips_from_file():
	with open(os.path.join(config.OUTPUT_DIR,config.IPS), 'r') as f:
		data = f.read().strip()
	return set(data.split('\n'))

def parse_domains_brute(domain, extip=None):
	'''
	如果域名泛解析，则通过HTTP请求的Host来判断是否真的绑定在webserver上
	在检查响应的时候，一般同一个错误页面的响应长度是一样的，除非响应中包含 host，所以需要在替换掉host之后再比较长度
	'''
	def get_error_page(extip, fhost):
		error_page = ''
		try:
			error_page = requests.get('https://%s' % extip, headers={'host': fhost}, verify=True).text.replace(fhost, "")
		except Exception as e:
			pass
		if not error_page:
			try:
				fhost = 'salt66666666.'+domain
				error_page = requests.get('http://%s' % extip, headers={'host': fhost}).text.replace(fhost, "")
			except Exception as e:
				pass
		return len(error_page)

	with open(os.path.join(config.OUTPUT_DIR, '%s.txt'%domain), 'r') as f:
		data = f.read().strip()
	ret = {}

	if extip:
		fhost = 'salt66666666.'+domain
		error_page = get_error_page(extip, fhost)

	for line in data.split('\n'):
		if not line.strip():
			continue
		line = line.replace(' ', '').replace('\t', '')
		parts = line.split(domain)
		if extip and extip in line:
			if not error_page:
				continue
			else:
				page = get_error_page(extip, parts[0]+domain)
				if page == error_page:
					continue

		ret[parts[0]+domain] = parts[1]
	return ret

def get_domains_conn():
	sqlitepath = os.path.join(config.OUTPUT_DIR, "domains.db")
	conn = db.connect(sqlitepath)
	conn.text_factory = str
	return conn


def get_ports_conn():
	sqlitepath = os.path.join(config.OUTPUT_DIR, "ports.db")
	conn = db.connect(sqlitepath)
	conn.text_factory = str
	return conn


def insert_port(ip, port, service=None):
	conn = get_ports_conn()
	cursor = conn.cursor()
	sql = "INSERT INTO open(ip, port, service) VALUES(?, ?, ?)"
	try:
		status = cursor.execute(sql, (ip, port, service))
		conn.commit()
	except Exception as e:
		print e
	conn.close()

def check_port_scanned(ip, port):
	conn = get_ports_conn()
	cursor = conn.cursor()
	sql = "SELECT * FROM open WHERE ip=? and port=?"
	cursor.execute(sql, (ip, port))
	rows = cursor.fetchall()
	if rows:
		return True
	else:
		return False


def install_ports():
	sqlitepath = os.path.join(config.OUTPUT_DIR, "ports.db")
	install = ''
	if not os.path.exists(sqlitepath):
		install = '''
	CREATE TABLE open(
		`ip` VARCHAR(64) NOT NULL,
		`port` INTEGER,
		`service` varchar(64),
		`comment` TEXT,
		PRIMARY KEY(`ip`, `port`)
	);
	'''
	if install:
		conn = conn = get_ports_conn()
		cursor = conn.cursor()
		cursor.execute(install)
		conn.commit()
		conn.close()


def install_domains():
	sqlitepath = os.path.join(config.OUTPUT_DIR, "domains.db")
	install = ''
	if not os.path.exists(sqlitepath):
		install = '''
	CREATE TABLE `domains`(
		`domain` varchar(255) NOT NULL,
		`ip` TEXT NOT NULL,
		`cname` varchar(255),
		`cdn` INTEGER,
		`internal` INTEGER,
		PRIMARY KEY(`domain`, `ip`)
	);
	'''
	if install:
		conn = get_domains_conn()
		cursor = conn.cursor()
		cursor.execute(install)
		conn.commit()
		conn.close()


if __name__ == '__main__':
	conn = get_domains_conn()
	cur = conn.cursor()
	cur.execute("SELECT * FROM domains")
	rows = cur.fetchall()
	for row in rows:
		print row
