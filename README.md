# `pktsniffer.py`

## Description
`pktsniffer` is a Python utility for reading, filtering, and displaying the contents of packet capture (.pcap) files. It supports filtering based on protocol, port number, network number, and hostname.

## Getting Started:
### Starting the Virtual Environment
When installing dependencies for any Python project, it is good practice to do so from within a virtual environment.
To create a virtual environment for this project, run `python3 -m venv .venv` from a terminal window. 
To start the venv, on a Unix-based system, run `source .venv/bin/activate` from the same directory.

### Installing Dependencies
This project depends on the Scapy Python library. To install this (and other required dependencies for building the documentation),
run the following command from within the venv:
`pip install -r requirements.txt`

## Running pktsniffer
`pktsniffer` is a Command Line Application. The general command format is given by:
```
python3 pktsniffer.py [-h] -r R [-c C] [-host HOST] 
[-port PORT] [-ip] [-tcp] [-udp] [-icmp] [-net NET]
```
For a description of each command line argument, run:
`python3 pktsniffer.py -h`

In a broad sense, the arguments are divided into three main groups: 

 - Meta Flags: including `-r` and `-c`, these arguments control the meta operation of the program, specifying the file to read and number of packets to analyze respectively.
 - String Filters: including `-host`, `-port` and `-net`, this group filters for packets based on user-provided strings, only including packets that match all provided string filters. 
 - Boolean Filters: including `-ip`, `-tcp`, `-udp`, and `-icmp`, this group tells the program to include packets that contain any of the protocol layers specified. If none are provided, all packets are included. 

### Usage Examples:
Below are some example commands, with descriptions of the intended result:

 - `python3 pktsniffer.py -r smaller.pcap -c 5`
	 - read 5 packets from `smaller.pcap`
 - `python3 pktsniffer.py -r smaller.pcap -ip`
	 - read and display all IP packets from `smaller.pcap`
 - `python3 pktsniffer.py -r smaller.pcap -tcp -udp`
	 - read and display all TCP packets and all UDP packets from `smaller.pcap`
 - `python3 pktsniffer.py -r smaller.pcap -port 80`
	 - read and display all packets from `smaller.pcap` where the source or destination port of the packet is 80
 - `python3 pktsniffer.py -r smaller.pcap -net 192.168.1.0`
	 - read and display all packets from `smaller.pcap` where either the source or destination IP belongs to the `192.168.1.x` network

