import argparse
import scapy.all as scapy

def parse_packet(packet):
    """
    Parses network packet and prints details.
    
    Parameters:
        packet: A single network packet captured from the pcap file.
    """
    print("\n--- Packet Captured ---")

    # Extract and display Ethernet header details
    if packet.haslayer(scapy.Ether):
        eth = packet.getlayer(scapy.Ether)
        print(f"Ethernet: {eth.src} -> {eth.dst} | Type: {hex(eth.type)}")

    # Extract and display IP header details
    if packet.haslayer(scapy.IP):
        ip = packet.getlayer(scapy.IP)
        print(f"IP: {ip.src} -> {ip.dst} | TTL: {ip.ttl} | Protocol: {ip.proto}")

    # Extract and display TCP header details
    if packet.haslayer(scapy.TCP):
        tcp = packet.getlayer(scapy.TCP)
        print(f"TCP: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}")

    # Extract and display UDP header details
    if packet.haslayer(scapy.UDP):
        udp = packet.getlayer(scapy.UDP)
        print(f"UDP: {udp.sport} -> {udp.dport}")

    # Extract and display ICMP header details
    if packet.haslayer(scapy.ICMP):
        icmp = packet.getlayer(scapy.ICMP)
        print(f"ICMP Type: {icmp.type} | Code: {icmp.code}")

def main():
    """
    Main function that handles command-line arguments and processes packets from a pcap file.
    """
    # Initialize argument parser
    parser = argparse.ArgumentParser(description="Packet Sniffer - Analyze packets from a .pcap file")
    
    # Add arguments for the pcap file, count limit, and filters
    parser.add_argument("-r", "--read", required=True, help="Path to pcap file")
    parser.add_argument("-c", "--count", type=int, help="Limit number of packets analyzed")
    parser.add_argument("filter", nargs="*", help="Filter packets (host, port, ip, tcp, udp, icmp, net)")
    
    # Parse command-line arguments
    args = parser.parse_args()
    
    # Read packets from provided .pcap file
    try:
        packets = scapy.rdpcap(args.read)  # Load packets from pcap file
    except FileNotFoundError:
        print(f"Error: File '{args.read}' not found.")
        return

    # Determine how many packets to process
    count = args.count if args.count else len(packets)
    
    print(f"\nAnalyzing {count} packets from {args.read}...\n")
    
    # Loop through packets and process them
    for packet in packets[:count]:
        parse_packet(packet)

if __name__ == "__main__":
    main()