""" 
Caleb Naeger - cmn4315@rit.edu
Foundations of Computer Networks
"""
import argparse
import scapy.all as scapy


def host_filter(packets, host):
    ret_packs = []
    for packet in packets:
        if packet


def port_filter(packets, port):
    pass


def net_filter(packets, net):
    pass


def boolean_filters(packets, flags):
    ret_packs = []
    if "ip" in flags and flags["ip"]:
        ret_packs.append(proto_filter(packets, 'IP'))
    if "tcp" in flags and flags["tcp"]:
        ret_packs.append(proto_filter(packets, 'TCP'))
    if "udp" in flags and flags["udp"]:
        ret_packs.append(proto_filter(packets, 'UDP'))
    if "icmp" in flags and flags["icmp"]:
        ret_packs.append(proto_filter(packets, 'ICMP'))

    return ret_packs


def proto_filter(packets, proto):
    ret_packs = []
    for packet in packets:
        if packet.haslayer(proto):
            ret_packs.append(packet)


def process_packets(filename: str, count: int, flags: dict):
    packets = scapy.rdpcap(filename, count=count)
    if "host" in flags:
        packets = host_filter(packets, flags["host"])
    if "port" in flags:
        packets = port_filter(packets, flags["port"])
    if "net" in flags:
        packets = net_filter(packets, flags["net"])
    
    packets = boolean_filters(packets, flags)


def main():
    # Create the parser
    parser = argparse.ArgumentParser(description='Packet sniffer for analyzing pcap files.')
    
    # Add arguments
    parser.add_argument('-r', type=str, required=True, help='The name of the file to read.')
    parser.add_argument('-c', type=int, required=False, help='The number of packets to analyze.')
    parser.add_argument('-host', required=False, type=str, help="Apply a filter to the analyzer, by host IP.")
    parser.add_argument('-port', required=False, type=str, help="Apply a filter to the analyzer, by port number.")
    parser.add_argument('-ip', action='store_true', required=False, help="Include Ethernet packets with the IP protocol")
    parser.add_argument('-tcp', action='store_true', required=False, help="Include TCP packets.")
    parser.add_argument('-udp', action='store_true', required=False, help="Include UDP packets.")
    parser.add_argument('-icmp', action='store_true', required=False, help="Include ICMP packets.")
    parser.add_argument('-net', required=False, type=str, help="Apply a filter to the analyzer, based on network address.")

    
    # Parse arguments
    args = parser.parse_args()
    flags = {}
    for arg in vars(args):
        if arg:
            flags[arg] = getattr(args,arg)
    print(flags)
    process_packets(args.r, args.c, flags)

if __name__ == "__main__":
    main()

