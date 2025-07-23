# backend/utils/oui_lookup.py

# This file will contain functions for looking up MAC address vendors
# using an OUI (Organizationally Unique Identifier) database.
# A common approach is to download the IEEE OUI file and parse it.

import os
import requests
import re # Added for regex in parsing OUI file

# Path to store the OUI database file
OUI_FILE = "oui.txt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

def download_oui_file():
    """
    Downloads the latest IEEE OUI database file.
    """
    print(f"Downloading OUI file from {OUI_URL}...")
    try:
        response = requests.get(OUI_URL, stream=True, timeout=10)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        with open(OUI_FILE, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"OUI file downloaded successfully to {OUI_FILE}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading OUI file: {e}")
        return False

def load_oui_database():
    """
    Loads the OUI database from the local file into a dictionary for quick lookup.
    The OUI file format typically looks like:
    00-00-00   (hex)           XEROX CORPORATION
    00-00-01   (hex)           XEROX CORPORATION
    ...
    """
    oui_db = {}
    # Check if OUI file exists, if not, try to download
    if not os.path.exists(OUI_FILE):
        print(f"OUI file '{OUI_FILE}' not found. Attempting to download...")
        if not download_oui_file():
            print("Failed to load OUI database. OUI lookup will not be available.")
            return {}

    try:
        with open(OUI_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                # Look for lines containing MAC prefixes and vendor names
                match = re.match(r'^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.*)', line)
                if match:
                    # Format OUI as 00:00:00 or 00-00-00
                    oui_prefix = f"{match.group(1)}:{match.group(2)}:{match.group(3)}".upper()
                    vendor_name = match.group(4).strip()
                    oui_db[oui_prefix] = vendor_name
        print(f"Loaded {len(oui_db)} OUI entries.")
    except Exception as e:
        print(f"Error loading OUI database from {OUI_FILE}: {e}")
        return {}
    return oui_db

# Load the OUI database once when the module is imported
OUI_DATABASE = load_oui_database()

def lookup_mac_vendor(mac_address):
    """
    Looks up the vendor of a given MAC address using the OUI database.
    MAC address can be in formats like "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF".
    """
    if not OUI_DATABASE:
        return "Unknown (OUI DB not loaded)"

    # Normalize MAC address to "AA:BB:CC" format for OUI lookup
    mac_parts = mac_address.replace('-', ':').split(':')
    if len(mac_parts) < 3:
        return "Invalid MAC format"

    oui_prefix = ":".join(mac_parts[:3]).upper()
    return OUI_DATABASE.get(oui_prefix, "Unknown Vendor")

# Example usage (for testing this module independently)
if __name__ == "__main__":
    print("--- OUI Lookup Test ---")
    # This will trigger a download if oui.txt is not present
    # Then it will perform lookups
    print(f"Vendor for 00:1A:2B:3C:4D:5E: {lookup_mac_vendor('00:1A:2B:3C:4D:5E')}") # Example Cisco
    print(f"Vendor for 00-0C-29-12-34-56: {lookup_mac_vendor('00-0C-29-12-34-56')}") # Example VMware
    print(f"Vendor for AA:BB:CC:DD:EE:FF: {lookup_mac_vendor('AA:BB:CC:DD:EE:FF')}") # Should be unknown
    print(f"Vendor for 00:00:00:00:00:00: {lookup_mac_vendor('00:00:00:00:00:00')}") # Should be XEROX
