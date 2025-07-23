# backend/api/live_capture.py

# This file will contain the logic for live packet sniffing using Scapy.
# It will involve:
# - Functions to list available network interfaces.
# - A function to start capturing packets on a selected interface.
# - A mechanism to send captured packet data (e.g., via WebSockets) to the frontend.
# - Parsing of packet layers (IP, TCP, UDP, HTTP, etc.) to extract relevant information.
# - A function for active device discovery (ARP scan).

import sys
import os
import time
import random
# Added srp and get_if_addr for ARP scanning
from scapy.all import get_if_list, sniff, IP, TCP, UDP, Raw, Ether, ARP, srp, get_if_addr # Import necessary Scapy components
from scapy.layers.http import HTTPRequest, HTTPResponse # For HTTP parsing if available
import psutil # Import psutil for more descriptive interface names

# Corrected import: Use relative import to access the 'analysis' module
from ..analysis.phishing import analyze_url_for_phishing # Import the correct function name

# Global flag to signal the sniffing thread to stop
stop_capture_signal = False

def list_interfaces():
    """
    Lists available network interfaces using Scapy and enhances with psutil descriptions.
    Returns a list of dictionaries with 'name' (Scapy name) and 'description' (user-friendly).
    """
    interfaces = []
    scapy_ifaces = []
    try:
        scapy_ifaces = get_if_list()
    except Exception as e:
        print(f"Error listing interfaces with Scapy: {e}")
        # Fallback if Scapy fails to list interfaces
        return [
            {"name": "eth0", "description": "Ethernet Interface (Scapy Error Fallback)"},
            {"name": "wlan0", "description": "Wireless Interface (Scapy Error Fallback)"},
            {"name": "lo", "description": "Loopback Interface (Scapy Error Fallback)"}
        ]

    # Get psutil network interface stats for more descriptive names
    psutil_if_stats = psutil.net_if_stats()
    psutil_if_addrs = psutil.net_if_addrs()

    for scapy_iface_name in scapy_ifaces:
        description = scapy_iface_name # Default to Scapy name

        # Try to find a more user-friendly name using psutil
        # This mapping can be tricky on Windows due to NPF names
        # psutil.net_if_addrs() usually has the friendly name as the key
        # and the NPF name might be part of the address info or description
        
        # Best effort mapping: iterate through psutil interfaces
        found_description = False
        for ps_iface_name, ps_addrs in psutil_if_addrs.items():
            for addr in ps_addrs:
                # On Windows, the Scapy name (e.g., \Device\NPF_{GUID}) often appears
                # in the description field of psutil's addresses for that interface.
                if sys.platform.startswith('win'):
                    # For Windows, try to match the GUID part of the NPF name
                    # Scapy name: \Device\NPF_{GUID}
                    # psutil name: "Local Area Connection" or "Wi-Fi"
                    # We need to find the psutil interface that corresponds to the Scapy NPF GUID.
                    # This is a heuristic and might not be perfect for all systems.
                    if scapy_iface_name.startswith("\\Device\\NPF_"):
                        scapy_guid = scapy_iface_name.split('{')[-1].rstrip('}')
                        # Check if the GUID is present in any of the psutil interface's addresses' descriptions
                        if hasattr(addr, 'description') and scapy_guid in addr.description:
                            description = ps_iface_name
                            found_description = True
                            break
                        # Also check if the psutil interface name itself contains the GUID (less common)
                        if scapy_guid in ps_iface_name:
                            description = ps_iface_name
                            found_description = True
                            break
                # For Linux/macOS, Scapy names are usually already friendly or match psutil names
                else:
                    if scapy_iface_name == ps_iface_name:
                        description = ps_iface_name # psutil name is already friendly
                        found_description = True
                        break
            if found_description:
                break
        
        # If still not found, try to use psutil.net_if_stats() for a general description
        if not found_description and scapy_iface_name in psutil_if_stats:
            # psutil_if_stats doesn't directly provide a better name, but confirms existence
            pass # Keep default Scapy name if no better match

        interfaces.append({"name": scapy_iface_name, "description": description})
    
    # Sort interfaces for better readability (e.g., loopback last)
    interfaces.sort(key=lambda x: x['description'])

    return interfaces


def _process_packet(packet, packet_callback):
    """
    Processes a single captured packet and extracts relevant information.
    Calls packet_callback with the extracted data.
    """
    global stop_capture_signal
    if stop_capture_signal:
        raise StopIteration

    packet_data = {
        "timestamp": time.strftime("%H:%M:%S"),
        "source_ip": "N/A",
        "dest_ip": "N/A",
        "source_mac": "N/A",
        "dest_mac": "N/A",
        "source_port": "N/A",
        "dest_port": "N/A",
        "protocol": "N/A",
        "url": "N/A",
        "size": len(packet),
        "risk_level": "Low" # Default, will be updated by phishing module
    }

    # Extract MAC addresses from the Ethernet layer
    if Ether in packet:
        packet_data["source_mac"] = packet[Ether].src
        packet_data["dest_mac"] = packet[Ether].dst

    if IP in packet:
        packet_data["source_ip"] = packet[IP].src
        packet_data["dest_ip"] = packet[IP].dst

        if TCP in packet:
            packet_data["protocol"] = "TCP"
            packet_data["source_port"] = packet[TCP].sport
            packet_data["dest_port"] = packet[TCP].dport
            if HTTPRequest in packet:
                packet_data["protocol"] = "HTTP"
                try:
                    host = packet[HTTPRequest].Host.decode()
                    path = packet[HTTPRequest].Path.decode()
                    packet_data["url"] = f"http://{host}{path}"
                except Exception:
                    packet_data["url"] = "HTTP_URL_Parse_Error"
            elif HTTPResponse in packet:
                packet_data["protocol"] = "HTTP"
                packet_data["url"] = "HTTP_Response"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                packet_data["protocol"] = "HTTPS"
                packet_data["url"] = "HTTPS (Encrypted)"
        elif UDP in packet:
            packet_data["protocol"] = "UDP"
            packet_data["source_port"] = packet[UDP].sport
            packet_data["dest_port"] = packet[UDP].dport
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                packet_data["protocol"] = "DNS"
                if packet.haslayer('DNSQR'):
                    try:
                        packet_data["url"] = packet.qd.qname.decode().rstrip('.')
                    except Exception:
                        packet_data["url"] = "DNS_Query_Error"
        elif packet.haslayer('ICMP'):
            packet_data["protocol"] = "ICMP"
        elif packet.haslayer('ARP'):
            packet_data["protocol"] = "ARP"
            packet_data["source_ip"] = packet.psrc if packet.haslayer('ARP') else "N/A"
            packet_data["dest_ip"] = packet.pdst if packet.haslayer('ARP') else "N/A"
            packet_data["url"] = "ARP_Packet"

    packet_callback(packet_data)


def start_capture(interface, packet_callback):
    """
    Starts live packet capture on the specified interface using Scapy.
    Calls packet_callback for each captured packet.
    This function runs in a separate thread.
    """
    global stop_capture_signal
    stop_capture_signal = False
    print(f"Attempting to start capture on interface: {interface}")
    try:
        sniff(iface=interface, prn=lambda pkt: _process_packet(pkt, packet_callback), store=0, stop_filter=lambda pkt: stop_capture_signal)
        print(f"Scapy sniffing stopped on {interface}.")
    except PermissionError:
        print(f"Permission denied to sniff on interface {interface}. Please run with root/administrator privileges (e.g., sudo python app.py).")
    except Exception as e:
        print(f"Error during packet capture on {interface}: {e}")
    finally:
        print("Capture thread finished.")

def arp_scan(interface, ip_range):
    """
    Performs an ARP scan on the specified interface for the given IP range.
    Returns a list of discovered devices (IP, MAC).
    Requires administrative/root privileges.
    """
    print(f"Starting ARP scan on interface {interface} for IP range {ip_range}...")
    discovered_devices = []
    try:
        # Create an ARP request packet
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
        
        # Send the packet and receive responses
        # timeout ensures it doesn't wait forever
        # verbose=False suppresses Scapy's default output
        ans, unans = srp(arp_request, timeout=2, iface=interface, verbose=False)

        for sent, received in ans:
            discovered_devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
        print(f"ARP scan complete. Found {len(discovered_devices)} devices.")
    except PermissionError:
        print(f"Permission denied for ARP scan on interface {interface}. Run with root/administrator privileges.")
    except Exception as e:
        print(f"Error during ARP scan: {e}")
    return discovered_devices


# Example usage (for testing this module independently)
if __name__ == "__main__":
    def print_packet(packet):
        print(f"Captured: {packet['timestamp']} - {packet['source_ip']} -> {packet['dest_ip']} ({packet['protocol']}) - URL: {packet['url']} - Size: {packet['size']}")

    print("Available Interfaces:")
    for iface in list_interfaces():
        print(f"- {iface['name']}: {iface['description']}")

    # Example of how to get local IP for ARP scan
    # You'll need to know your subnet (e.g., 192.168.1.0/24)
    # For a real system, you'd get this dynamically
    # local_ip = get_if_addr("eth0") # Replace "eth0" with your active interface
    # if local_ip != "0.0.0.0":
    #     subnet = ".".join(local_ip.split('.')[:-1]) + ".0/24"
    #     print(f"\nPerforming ARP scan on {subnet} via eth0 (requires root/admin):")
    #     devices = arp_scan("eth0", subnet) # Replace "eth0" with your active interface
    #     for dev in devices:
    #         print(f"  Found: IP={dev['ip']}, MAC={dev['mac']}")
