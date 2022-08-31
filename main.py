import dpkt
import socket
import datetime


def print_flows(dic):
    counter = 1
    for key, val in dic.items():
        print('### flow number', counter)
        print(key[0], ',', key[2], '-->', key[1], ',', key[3], ':', key[4], ':',
              val[6], '; sent packets:', val[0], ', received packets:', val[1], ', sent bytes:', val[2],
              ', received bytes:', val[3], ', timestamp: (', val[4], ',', val[5], ')')
        counter += 1


def find_flows(pcap):
    dic = dict()
    for time, packet in pcap:

        ip = -1
        ip_src = -1
        ip_dst = -1
        src_port = -1
        dst_port = -1
        protocol = -1

        eth = dpkt.ethernet.Ethernet(packet)

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            ip_src = socket.inet_ntoa(ip.src)
            ip_dst = socket.inet_ntoa(ip.dst)

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                protocol = 'tcp'
                src_port = ip.data.sport
                dst_port = ip.data.dport

            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                protocol = 'udp'
                src_port = ip.data.sport
                dst_port = ip.data.dport

        if ip == -1 or \
                ip_src == -1 or ip_dst == -1 or \
                src_port == -1 or dst_port == -1 or \
                protocol == -1:
            continue

        temp1_tuple = (ip_src, ip_dst, src_port, dst_port, protocol)
        temp2_tuple = (ip_dst, ip_src, dst_port, src_port, protocol)

        # sent packets, received packets, sent bytes, received bytes, first time, last time, protocol
        test_list = [1,
                     0,
                     len(bytes(ip.data)),
                     0,
                     str(datetime.datetime.utcfromtimestamp(time)),
                     str(datetime.datetime.utcfromtimestamp(time)),
                     "Unknown"]

        keys = dic.keys()

        if temp1_tuple in keys:
            dic[temp1_tuple][0] += 1
            dic[temp1_tuple][2] += len(bytes(ip.data))
            dic[temp1_tuple][5] = str(datetime.datetime.utcfromtimestamp(time))

        elif temp2_tuple in keys:
            dic[temp2_tuple][1] += 1
            dic[temp2_tuple][3] += len(bytes(ip.data))
            dic[temp2_tuple][5] = str(datetime.datetime.utcfromtimestamp(time))

        else:
            dic[temp1_tuple] = test_list
    print_flows(dic)


if __name__ == '__main__':
    find_flows(dpkt.pcap.Reader(open('example.pcap', 'rb')))
