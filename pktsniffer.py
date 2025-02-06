""" 
Caleb Naeger - cmn4315@rit.edu
Foundations of Computer Networks
"""
import argparse
import scapy.all as scapy


def read_packets(filename: str):
    packets = scapy.rdpcap(filename, count=1)
    for packet in packets:
        print(packet.show())

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description='Packet sniffer for Analyzing pcap files.')
    
    # Add arguments
    parser.add_argument('-r', type=str, required=True, help='The name of the file to read.')
    parser.add_argument('-c', type=int, required=False, help='The number of packets to analyze.')
    parser.add_argument('-host', required=False, type=str, help="Apply a filter to the analyzer, by host IP.")
    parser.add_argument('-port', required=False, type=str, help="Apply a filter to the analyzer, by port number.")
    parser.add_argument('-ip', required=False, help="Include Ethernet packets with the IP protocol")
    parser.add_argument('-tcp', required=False, help="Include TCP packets.")
    parser.add_argument('-udp', required=False, help="Include UDP packets.")
    parser.add_argument('-icmp', required=False, help="Include ICMP packets.")
    parser.add_argument('-net', required=False, help="Apply a filter to the analyzer, based on network address.")

    
    # Parse arguments
    args = parser.parse_args()
    read_packets(args.r)

main()

