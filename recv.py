#! /usr/bin/env python
from scapy.all import *

import config
import helper
from tools import check_port_service

# http://biot.com/capstats/bpf.html
# http://www.freebuf.com/sectool/94507.html
helper.install_ports()
whitelist = helper.load_ips_from_file()

f="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"

def callback(pkt):
	#pkt.show()
	if pkt[IP].src in whitelist:
		print "%s:%s"%(pkt[IP].src, pkt[TCP].sport)
		if helper.check_port_scanned(pkt[IP].src, pkt[TCP].sport):
			return
		service = check_port_service(pkt[IP].src, pkt[TCP].sport)
		helper.insert_port(pkt[IP].src, pkt[TCP].sport, service)

sniff(prn=callback, filter=f, store=0)