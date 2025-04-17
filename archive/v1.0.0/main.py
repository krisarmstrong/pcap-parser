from scapy.all import *
import sys

from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP


def parse_pcap(input_file, output_file):
    """
    Reads a pcap file, filters packets with a source MAC address that starts
    with 00:c0:17, and writes packet details to an output text file.
    :type input_file: object
    :type output_file: object
    """
    try:
        # Read the pcap file
        packets = rdpcap(input_file)
        print(f"Loaded {len(packets)} packets from {input_file}")

        with open(output_file, "w") as f:
            f.write("Filtered Packet Details:\n")
            f.write("=" * 30 + "\n")

            for pkt in packets:
                # Check if the packet has an Ethernet layer
                if pkt.haslayer(Ether):
                    src_mac = pkt[Ether].src
                    # Check if source MAC matches the specified prefix
                    if src_mac.startswith("00:c0:17"):
                        # Check if packet has TCP or UDP layer
                        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                            # Extract common information
                            src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                            protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
                            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (
                                pkt[UDP].sport if pkt.haslayer(UDP) else "N/A")
                            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (
                                pkt[UDP].dport if pkt.haslayer(UDP) else "N/A")
                            payload = pkt[Raw].load if pkt.haslayer(Raw) else b""

                            # Filter by port 3842 if present
                            if src_port == 3842 or dst_port == 3842 or not (src_port or dst_port):
                                # Write packet information to the output file
                                f.write(f"Source MAC: {src_mac}\n")
                                f.write(f"Source IP: {src_ip}\n")
                                f.write(f"Destination IP: {dst_ip}\n")
                                f.write(f"Protocol: {protocol}\n")
                                f.write(f"Source Port: {src_port}\n")
                                f.write(f"Destination Port: {dst_port}\n")
                                f.write(f"Payload (hex): {payload.hex()}\n")
                                f.write("-" * 30 + "\n")

        print(f"Parsing complete. Output written to {output_file}")

    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
    except Exception as e:
        print(f"An error occurred while parsing the pcap file: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parse_pcap.py <input_pcap_file> <output_text_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    parse_pcap(input_file, output_file)


# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
