""" 
Caleb Naeger - cmn4315@rit.edu
Foundations of Computer Networks
"""
import argparse
from os import wait
from typing import Union
import scapy.all as scapy

def build_filter_string(flags):
    string_flags = ["host","port","net"]
    boolean_flags = ["ip","tcp","udp","icmp"]

    and_string = ""
    or_string = ""

    for flag in string_flags:
        if flags[flag] is not None:
            if and_string != "":
                and_string += " && "
            and_string += f"{flag} {flags[flag]}"
    for flag in boolean_flags:
        if flags[flag]:
            if or_string != "":
                or_string += " || "
            or_string += f"{flag}"
    
    if and_string != "":
        and_string = f"({and_string})"
    if or_string != "":
        or_string = f"({or_string})"

    return f"{and_string}{ ' && ' if and_string != "" and or_string != "" else ""}{or_string}"


def ethernet_string(packet) -> str:
    string = "Ethernet:\n"
    for field in packet['Ether'].fields.keys():
        string += f"\t{field}: {packet['Ether'].fields[field]}\n"
    return string


def ether_proto_string(packet) -> str:
    layer = packet['Ether'].payload
    string = f"{layer.name}:\n"
    for field in layer.fields.keys():
        string += f"\t\t{field}: {layer.fields[field]}\n"
    return string


def proto_string(packet) -> str:
    layer = packet['Ether'].payload.payload
    string = f"{layer.name}:\n"
    for field in layer.fields:
        string += f"\t\t\t{field}: {layer.fields[field]}\n"
    return string

def print_packets(packets):
    for packet in packets:
        string = "-"*80 + '\n'
        string += ethernet_string(packet)
        string += ether_proto_string(packet)
        string += proto_string(packet)
        string += "-"*80 + '\n'
        print(string)


def process_packets(filename: str, count: Union[int, None], filter:str):
    packets = []
    print(filter)
    if count is not None:
        packets = scapy.sniff(offline=filename, count=count, filter=filter)
    else:
        packets = scapy.sniff(offline=filename, filter=filter)

    print_packets(packets)


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
    filter = build_filter_string(flags)
    process_packets(args.r, args.c, filter)

if __name__ == "__main__":
    main()

