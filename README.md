Packet Sniffer (pktsniffer.py)

Overview

pktsniffer.py is a Python-based network packet analyzer that reads a .pcap file and extracts detailed summaries of network traffic. The program supports filtering based on host, port, protocol, and network, and can generate structured reports of captured packets.

Features:

Reads and analyzes packets from .pcap files.
Extracts Ethernet, IP, TCP, UDP, and ICMP headers.
Supports filtering by:
Host (--host <IP>)
Port (--port <PORT>)
Protocol (--tcp, --udp, --icmp)
Network (--net <NETWORK>)
Packet count limit (-c <COUNT>)
Outputs structured packet details

Prerequisites

Ensure you have Python installed along with the required dependencies:

pip install -r requirements.txt

Usage

Basic Packet Analysis

    python pktsniffer.py -r network_traffic.pcap

Filtering Examples

Filter by Host:

    python pktsniffer.py -r network_traffic.pcap --host 192.168.1.1

Filter by Port (e.g., DNS traffic on port 53):

    python pktsniffer.py -r network_traffic.pcap --port 53

Filter by TCP Protocol:

    python pktsniffer.py -r network_traffic.pcap --tcp

Filter by UDP Protocol:

    python pktsniffer.py -r network_traffic.pcap --udp

Filter by Network (e.g., all traffic in 192.168.1.x subnet):

    python pktsniffer.py -r network_traffic.pcap --net 192.168.1

Limit the Number of Packets Analyzed:

    python pktsniffer.py -r network_traffic.pcap -c 10

Generating Documentation with Sphinx:

I couldn't figure out how to do this.