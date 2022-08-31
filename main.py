import dpkt
import socket


def find_flows(pcap):
    for time, packet in pcap:

        ip = -1
        ip_src = -1, ip_dst = -1
        src_port = -1, dst_port = -1
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


if __name__ == '__main__':
    find_flows(dpkt.pcap.Reader(open('example.pcap', 'rb')))
