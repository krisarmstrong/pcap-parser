#!/usr/bin/env python3
"""
Tests for PcapParser.
"""
import os
import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap
from pcap_parser import __version__, parse_pcap

@pytest.fixture
def pcap_file(tmp_path):
    """Create a temporary PCAP file with a test packet."""
    pcap_path = tmp_path / "test.pcap"
    output_path = tmp_path / "output.txt"
    packet = (
        Ether(src="00:c0:17:aa:bb:cc", dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.1.1", dst="192.168.1.2") /
        TCP(sport=12345, dport=3842) /
        Raw(load=b"test payload")
    )
    wrpcap(pcap_path, [packet])
    return pcap_path, output_path

def test_version() -> None:
    """Test version format."""
    assert __version__ == "1.0.1"

def test_parse_pcap(pcap_file) -> None:
    """Test PCAP parsing and filtering."""
    pcap_path, output_path = pcap_file
    parse_pcap(str(pcap_path), str(output_path))

    with open(output_path, "r") as f:
        content = f.read()
    assert "Source MAC: 00:c0:17:aa:bb:cc" in content
    assert "Source IP: 192.168.1.1" in content
    assert "Destination IP: 192.168.1.2" in content
    assert "Protocol: TCP" in content
    assert "Source Port: 12345" in content
    assert "Destination Port: 3842" in content
    assert "Payload (hex): 74657374207061796c6f6164" in content

def test_parse_pcap_invalid_file() -> None:
    """Test parsing an invalid PCAP file."""
    with pytest.raises(FileNotFoundError):
        parse_pcap("nonexistent.pcap", "output.txt")