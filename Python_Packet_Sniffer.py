#!/usr/bin/python

import socket
import os
import struct
import binascii

def analyze_tcp_header(data):
	tcp_hdr = struct.unpack("!2H2I4H",data[:20])
	src_port = tcp_hdr[0]
	dst_port = tcp_hdr[1]
	seq_num = tcp_hdr[2]
	ack_num = tcp_hdr[3]
	data_offset = tcp_hdr[4] >> 12
	reserved = (tcp_hdr[4] >> 6) & 0x03ff
	flags = tcp_hdr[4] & 0x003f
	urg = flags & 0x0020
	ack = flags & 0x0010
	ack = flags & 0x0008
	rst = flags & 0x0004
	syn = flags & 0x0002
	fin = flags & 0x0001
	window = tcp_hdr[5]
	checksum = tcp_hdr[6]
	urg_ptr = tcp_hdr[7]
	
	data = data[20:]
	return data 
	
def analyze_udp_header(data):
	udp_hdr = strunct.unpack("!4H",data[:8])
	src_port = udp_hdr[0]
	dst_port = udp_hdr[1]
	length = udp_hdr[2]
	chk_sum = udp_hdr[3]
	
	data = data[8:]
	return data

def analyze_ip_header(data):
	ip_hdr =struct.unpack("!6H4s4s",data[:20])
	ver = ip_hdr[0] >> 12 #ROR 12 bits
	ihl = (ip_hdr[0] >> 8) & 0x0f #00001111
	tos = ip_hdr[0] & 0x00ff
	tot_len = ip_hdr[1]
	ip_id = ip_hdr[2]
	flags = ip_hdr[3] >> 13
	frag_offset = ip_hdr[3] & 0x1fff
	ip_ttl = ip_hdr[4] >> 8
	ip_proto = ip_hdr[4] & 0x00ff
	chk_sum = ip_hdr[5]
	src_addr = socket.inet_ntoa(ip_hdr[6])
	dst_addr = socket.inet_ntoa(ip_hdr[7])
	
	no_frag = flags >> 1
	more_frag = flags & 0x1
	
	print "~~~~~~~~~~~~~~~~~~~~~~~IP Header~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	print "|\tVersion:  \t%hu" %ver
	print "|\tIHL:      \t%hu" %ihl
	print "|\tTOS:      \t%hu" %tos
	print "|\tLength:   \t%hu" %tot_len
	print "|\tID:       \t%hu" %ip_id
	print "|\tNO Frag:  \t%hu" %frag_offset
	print "|\tMore Frag:\t%hu" %more_frag
	print "|\tOffset:   \t%hu" %frag_offset
	print "|\tTTL:      \t%hu" %ip_ttl
	print "|\tNext_Protocol:\t%hu" %ip_proto
	print "|\tChecksum: \t%hu" %chk_sum
	print "|\tSource IP:\t%s" %src_addr
	print "|\tDestination IP:\t%hu" %ver
	
	if ip_proto == 6:  #tcp magic number
		next_proto = "tcp"
	elif ip_proto ==17: #udp magic number
		next_proto = "udp"
	else:
		next_proto = "other"
		
 	data = data[20:]
	return data , next_proto 

def analyze_ether_header(data):
	ip_bool = False
	eth_hdr = struct.unpack("!6s6sH",data[:14])  #IPv4 = 0x0800
	dest_mac = binascii.hexlify(eth_hdr[0]) #destination address
	src_mac = binascii.hexlify(eth_hdr[1]) #source address
	proto = eth_hdr[2] >> 8 #next protocol
	
	
	print "~~~~~~~~~~~~~~~~~~~~~~~Ethernet Header~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	print "|\tDestination Mac: %s:%s:%s:%s:%s:%s" % (dest_mac[0:2],dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12])
	print "|\t\tSource Mac: %s:%s:%s:%s:%s:%s" % (src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])
	print "|\t\tProtocol: %hu" % proto
	
	if proto== 0x86:
		ip_bool = True
	
	data = data[14:]
	return data, ip_bool
	
def main():
	sniffer_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
	#sniffer_socket.bind(()) <== raw sockets don't do this
	recv_data = sniffer_socket.recv(2048)  #returns binary data (struct)
	os.system('clear')
	
	data, ip_bool = analyze_ether_header(recv_data)
	if ip_bool:
		data , next_proto = analyze_ip_header(data)
	else:
		return
	if next_proto == "tcp":
		data = analyze_tcp_header(data)
	elif next_proto == "udp":
		data = anayze_udp_header(data)
	else:
		return
	
while True:
	main()
	
