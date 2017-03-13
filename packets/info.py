
print("PACKET PARSING / PROJECT NEPTUNE")

# Developer:     Harris
# GitHub:        github.com/harrisjnu

####Function Library Imports

import socket, sys
from struct import *


def packet_type(raw):
    packet = (raw.recvfrom(65565))[0]
    eth_head = packet[:14]  # 14 is Length of Ethernet Header
    eth_head_read = unpack('!6s6sH', eth_head)
    proto = socket.ntohs(eth_head_read[2])
    #print(proto)
    if proto == 8:
        return "IP"
    else:
        return "NON IP PACKET"

def packet_ipv4(raw):
    packet = (raw.recvfrom(65565))[0]
    ip_head = packet[14:20 + 14] # First 20 Character of IP Header
    ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
    ip_vers = ip_head_read[0] >> 4 # Moving 4 bit to Right
    #print(ip_vers)
    if ip_vers == 4:
        return True
    else:
        return False

def payload_proto(raw):
    packet = (raw.recvfrom(65565))[0]
    ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
    ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
    protocol = ip_head_read[6]
    if protocol == 6:
        return "TCP"
    elif protocol == 1:
        return "ICMP"
    elif protocol == 17:
        return "UDP"
    else:
        return protocol

def src_addr(raw):
    packet = (raw.recvfrom(65565))[0]
    ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
    ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
    s_addr = socket.inet_ntoa(ip_head_read[8])
    return s_addr

def dst_addr(raw):
    packet = (raw.recvfrom(65565))[0]
    ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
    ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
    d_addr = socket.inet_ntoa(ip_head_read[8])
    return d_addr

class tcp:
    def src_port(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        t = ip_head_len + 14
        t_head = packet[t:t + 20]
        tcp_head = unpack('!HHLLBBHHH', t_head)
        src_port = tcp_head[0]
        return src_port

    def dst_port(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        t = ip_head_len + 14
        t_head = packet[t:t + 20]
        tcp_head = unpack('!HHLLBBHHH', t_head)
        dst_port = tcp_head[1]
        return dst_port

    def sqn_num(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        t = ip_head_len + 14
        t_head = packet[t:t + 20]
        tcp_head = unpack('!HHLLBBHHH', t_head)
        sq_num = tcp_head[2]
        return sq_num

    def ack_num(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        t = ip_head_len + 14
        t_head = packet[t:t + 20]
        tcp_head = unpack('!HHLLBBHHH', t_head)
        ak_num = tcp_head[3]
        return ak_num

    def data_payload(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        t = ip_head_len + 14
        t_head = packet[t:t + 20]
        tcp_head = unpack('!HHLLBBHHH', t_head)
        offset_reserv = tcp_head[4]
        tcp_head_len = offset_reserv >> 4
        tcp_head_load = 14 + ip_head_len + ip_head_len * 4
        #data_load = len(packet - tcp_head_load)
        data = packet[tcp_head_load:]
        #print(type(data))
        #print(data)
        try:
            data = data.decode("utf-8")
        except:
            pass
        return str(data)
        #return (data)

class udp:
    def src_port(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        udp_head_start = ip_head_len + 14
        #UDP HEADER is len 8
        udp_head = packet[udp_head_start:udp_head_start + 8]
        udp_head_read = unpack('!HHHH', udp_head)
        src_port = udp_head_read[0]
        return src_port

    def dst_port(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        udp_head_start = ip_head_len + 14
        #UDP HEADER is len 8
        udp_head = packet[udp_head_start:udp_head_start + 8]
        udp_head_read = unpack('!HHHH', udp_head)
        dst_port = udp_head_read[0]
        return dst_port

    def data_payload(raw):
        packet = (raw.recvfrom(65565))[0]
        ip_head = packet[14:20 + 14]  # First 20 Character of IP Header
        ip_head_read = unpack('!BBHHHBBH4s4s', ip_head)
        ver_iphead_len = ip_head_read[0]
        ver_iphead_len = ver_iphead_len & 0xF
        ip_head_len = ver_iphead_len * 4
        udp_head_start = ip_head_len + 14
        # UDP HEADER is len 8
        udp_head = packet[udp_head_start:udp_head_start + 8]
        udp_head_read = unpack('!HHHH', udp_head)
        head_load = 14 + ip_head_len + 8
        data = len(packet) - head_load
        data = packet[head_load:]
        try:
            data = data.decode("utf-8")
        except:
            pass
        return str(data)














