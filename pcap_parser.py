#!/usr/bin/env python3
"""
Project Title: PcapParser

Parses PCAP files, filters packets by source MAC address (00:c0:17) and port 3842,
and writes details to an output file.

Author: Kris Armstrong
"""
import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional
from scapy.all import rdpcap, Ether, IP, TCP, UDP, Raw, Packet

__version__ = "1.0.1"

class Config:
    """Global constants for PcapParser."""
    LOG_FILE: str = "pcap_parser.log"
    ENCODING: str = "utf-8"
    MAC_PREFIX: str = "00:c0:17"
    TARGET_PORT: int = 3842

def setup_logging(verbose: bool, logfile: str = Config.LOG_FILE) -> None:
    """Configure logging with rotating file handler.

    Args:
        verbose: Enable DEBUG level logging if True.
        logfile: Path to log file.

    Raises:
        PermissionError: If log file cannot be written.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            RotatingFileHandler(logfile, maxBytes=1048576, backupCount=3),
            logging.StreamHandler(),
        ],
    )

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Parse PCAP files, filter by MAC (00:c0:17) and port 3842.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input_file", help="Input PCAP file")
    parser.add_argument("output_file", help="Output text file for packet details")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--logfile", default=Config.LOG_FILE, help="Log file path")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()

def parse_pcap(input_file: str, output_file: str) -> None:
    """Parse PCAP file, filter packets, and write details to output file.

    Args:
        input_file: Path to PCAP file.
        output_file: Path to output text file.

    Raises:
        FileNotFoundError: If input file doesn't exist.
        PermissionError: If output file cannot be written.
    """
    logging.info("Parsing PCAP file: %s", input_file)
    try:
        packets: list[Packet] = rdpcap(input_file)
        logging.info("Loaded %d packets", len(packets))
    except FileNotFoundError as e:
        logging.error("Input file not found: %s", input_file)
        raise
    except Exception as e:
        logging.error("Error reading PCAP file: %s", e)
        raise

    try:
        with open(output_file, "w", encoding=Config.ENCODING) as f:
            f.write("Filtered Packet Details:\n")
            f.write("=" * 30 + "\n")

            for pkt in packets:
                if not pkt.haslayer(Ether):
                    continue
                src_mac = pkt[Ether].src
                if not src_mac.startswith(Config.MAC_PREFIX):
                    continue
                if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                    continue

                src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
                src_port: Optional[int] = (
                    pkt[TCP].sport if pkt.haslayer(TCP)
                    else pkt[UDP].sport if pkt.haslayer(UDP)
                    else None
                )
                dst_port: Optional[int] = (
                    pkt[TCP].dport if pkt.haslayer(TCP)
                    else pkt[UDP].dport if pkt.haslayer(UDP)
                    else None
                )
                payload = pkt[Raw].load if pkt.haslayer(Raw) else b""

                if src_port == Config.TARGET_PORT or dst_port == Config.TARGET_PORT or (src_port is None and dst_port is None):
                    f.write(f"Source MAC: {src_mac}\n")
                    f.write(f"Source IP: {src_ip}\n")
                    f.write(f"Destination IP: {dst_ip}\n")
                    f.write(f"Protocol: {protocol}\n")
                    f.write(f"Source Port: {src_port if src_port is not None else 'N/A'}\n")
                    f.write(f"Destination Port: {dst_port if dst_port is not None else 'N/A'}\n")
                    f.write(f"Payload (hex): {payload.hex()}\n")
                    f.write("-" * 30 + "\n")

        logging.info("Output written to %s", output_file)
    except PermissionError as e:
        logging.error("Cannot write to output file %s: %s", output_file, e)
        raise

def main() -> int:
    """Main entry point for PcapParser.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    args = parse_args()
    setup_logging(args.verbose, args.logfile)
    try:
        parse_pcap(args.input_file, args.output_file)
        return 0
    except KeyboardInterrupt:
        logging.info("Cancelled by user")
        return 0
    except Exception as e:
        logging.error("Error: %s", e)
        return 1

if __name__ == "__main__":
    sys.exit(main())