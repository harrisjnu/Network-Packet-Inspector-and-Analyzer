
# Developer:     Harris
# GitHub:        github.com/harrisjnu

####Function Library Imports

# ROOT/MAIN PROGRAM

import socket, sys
from packets.info import *

# create an INET, STREAMing socket

for i in range(1000000):
    try:
        raw = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    if payload_proto(raw) == "TCP":
        print("PAYLOAD PROTOCOL:    " + str(payload_proto(raw)))
        print("SOURCE IP ADDR:    " + str(src_addr(raw)))
        print("SOURCE PORT NO:    " + str(tcp.src_port(raw)))
        print("DESTINATION IP ADDR:    " + str(dst_addr(raw)))
        print("DESTINATION PORT NO:    " + str(tcp.dst_port(raw)))
        print("PAYLOAD DATA:    " + tcp.data_payload(raw))
    else:
        continue

    if payload_proto(raw) == "UDP":
        print("UDP PACKET DETECTED")
        print(udp.src_port(raw))
        print(udp.data_payload(raw))
    else:
        continue



    #print(ip_header.src_ip(raw,"iphead"))
    #print(tcp_header.ack_no(raw,"tcphead"))