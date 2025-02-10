import argparse
import scapy.all as scapy

def parse_packet(packet):
    """
    Parses network packet and prints details.
    
    Parameters:
        packet: A network packet captured from the pcap file.
    """
    print("\nPacket Captured:")

    # display Ethernet 
    if packet.haslayer(scapy.Ether):
        eth = packet.getlayer(scapy.Ether)
        print(f"Ethernet: {eth.src} -> {eth.dst} | Type: {hex(eth.type)}")

    # display IP
    if packet.haslayer(scapy.IP):
        ip = packet.getlayer(scapy.IP)
        print(f"IP: {ip.src} -> {ip.dst} | TTL: {ip.ttl} | Protocol: {ip.proto}")

    # display TCP
    if packet.haslayer(scapy.TCP):
        tcp = packet.getlayer(scapy.TCP)
        print(f"TCP: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}")

    # display UDP
    if packet.haslayer(scapy.UDP):
        udp = packet.getlayer(scapy.UDP)
        print(f"UDP: {udp.sport} -> {udp.dport}")

    # display ICMP
    if packet.haslayer(scapy.ICMP):
        icmp = packet.getlayer(scapy.ICMP)
        print(f"ICMP Type: {icmp.type} | Code: {icmp.code}")


def filter_packets(packets, filters):
    """
    Filters packets based on filters.

    Parameters:
        packets : list of packets.
        filters : filtering options.

    Returns:
        list: Filtered packets.
    """
    filtered_packets = []

    for packet in packets:
        match = True  # packet matches unless a filter says otherwise

        # Filter by host
        if filters.get("host"):
            if not packet.haslayer(scapy.IP) or (packet[scapy.IP].src != filters["host"] and packet[scapy.IP].dst != filters["host"]):
                match = False

        # Filter by port
        if filters.get("port"):
            if not (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):
                match = False
            elif packet.haslayer(scapy.TCP) and (packet[scapy.TCP].sport != filters["port"] and packet[scapy.TCP].dport != filters["port"]):
                match = False
            elif packet.haslayer(scapy.UDP) and (packet[scapy.UDP].sport != filters["port"] and packet[scapy.UDP].dport != filters["port"]):
                match = False

        # Filter by protocol
        if filters.get("tcp") and not packet.haslayer(scapy.TCP):
            match = False
        if filters.get("udp") and not packet.haslayer(scapy.UDP):
            match = False
        if filters.get("icmp") and not packet.haslayer(scapy.ICMP):
            match = False

        # Filter by network
        if filters.get("net"):
            if not packet.haslayer(scapy.IP):
                match = False
            else:
                ip_addr = packet[scapy.IP].src
                if not ip_addr.startswith(filters["net"]):
                    match = False

        if match:
            filtered_packets.append(packet)

    return filtered_packets


def main():
    """
    Main function that handle command-line arguments.
    """
    # Initialize argument parser
    parser = argparse.ArgumentParser(description="Packet Sniffer - Analyze packets from a .pcap file")

    # Required arg: input pcap file
    parser.add_argument("-r", "--read", required=True, help="Path to pcap file")
    
    # Optional arg: limit number of packets analyzed
    parser.add_argument("-c", "--count", type=int, help="Limit number of packets analyzed")

    # Filtering options
    parser.add_argument("--host", help="Filter packets by host IP")
    parser.add_argument("--port", type=int, help="Filter packets by port number")
    parser.add_argument("--tcp", action="store_true", help="Filter packets by TCP protocol")
    parser.add_argument("--udp", action="store_true", help="Filter packets by UDP protocol")
    parser.add_argument("--icmp", action="store_true", help="Filter packets by ICMP protocol")
    parser.add_argument("--net", help="Filter packets by network address (e.g., 192.168.1)")

    # parse the command-line arguments
    args = parser.parse_args()

    # read packets from .pcap file
    try:
        packets = scapy.rdpcap(args.read)  # load packets from pcap file
    except FileNotFoundError:
        print(f"Error: File '{args.read}' not found.")
        return

    # keep filter options in a dictionary
    filters = {
        "host": args.host,
        "port": args.port,
        "tcp": args.tcp,
        "udp": args.udp,
        "icmp": args.icmp,
        "net": args.net
    }

    # apply filtering
    filtered_packets = filter_packets(packets, filters)

    # determine how many packets to process
    count = args.count if args.count else len(filtered_packets)

    print(f"\nAnalyzing {count} packets from {args.read}...\n")

    # loop and process packets
    for packet in filtered_packets[:count]:
        parse_packet(packet)

if __name__ == "__main__":
    main()