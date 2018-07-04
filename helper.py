import config
import sqlite3 as db
import os

def load_domain_from_file():
	with open(config.INPUT_DOMAIN_FILE, 'r') as f:
		data = f.read().strip()
	return set(data.split('\n'))


def load_ips_from_file():
	with open(os.path.join(config.OUTPUT_DIR,config.IPS), 'r') as f:
		data = f.read().strip()
	return set(data.split('\n'))

def parse_domains_brute(domain, extip=None):
	with open(os.path.join(config.OUTPUT_DIR, '%s.txt'%domain), 'r') as f:
		data = f.read().strip()
	ret = {}
	for line in data.split('\n'):
		if not line.strip():
			continue
		if extip and extip in line:
			continue
		line = line.replace(' ', '').replace('\t', '')
		parts = line.split(domain)
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
