# app.py
from flask import Flask, render_template, jsonify, request, url_for
from flask_socketio import SocketIO, emit
import os
import time
import random
import json
from collections import deque # For a fixed-size queue to simulate sliding window
import threading # For running packet capture in a separate thread
import ipaddress # For calculating subnet from IP
import socket # For getting AF_INET for psutil
import psutil # <--- ADDED: Import psutil globally in app.py
import sys # For platform-specific checks

# Import your backend modules
from backend.api import live_capture
from backend.analysis import phishing
from backend.utils import oui_lookup

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here' # IMPORTANT: Change this to a strong, random key in production!
socketio = SocketIO(app, cors_allowed_origins="*") # Allow all origins for development

# --- Global variables to simulate real-time data ---
live_packets_captured = 0
live_phishing_attempts = 0

MAX_CHART_DATA_POINTS = 15
threat_chart_labels = deque(maxlen=MAX_CHART_DATA_POINTS)
threat_chart_data = deque(maxlen=MAX_CHART_DATA_POINTS)

for i in range(MAX_CHART_DATA_POINTS):
    threat_chart_labels.append(time.strftime("%H:%M:%S", time.localtime(time.time() - (MAX_CHART_DATA_POINTS - 1 - i) * 5)))
    threat_chart_data.append(random.randint(0, 5))

recent_events_history = deque(maxlen=20)

# --- Live Capture State ---
capture_thread = None
is_capturing = False
current_interface = None

# --- Discovered Devices State ---
# Store discovered devices with IP as key for quick lookup and update
discovered_devices = {} # {ip: {mac: "...", vendor: "...", last_seen: "...", type: "..."}}

# --- Settings Management ---
SETTINGS_FILE = 'settings.json'

def load_app_settings():
    """Loads application settings from a JSON file."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {
        "enable_logging": False,
        "phishtank_api_key": "",
        "google_safe_browsing_api_key": ""
    }

def save_app_settings(settings):
    """Saves application settings to a JSON file."""
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)
    # After saving, update the phishing module with the new API keys
    phishing.set_api_keys(
        settings.get("phishtank_api_key", ""),
        settings.get("google_safe_browsing_api_key", "")
    )

# Load settings on application startup
app_settings = load_app_settings()
# Initialize phishing module with loaded settings
phishing.set_api_keys(
    app_settings.get("phishtank_api_key", ""),
    app_settings.get("google_safe_browsing_api_key", "")
)


# --- Flask Routes ---

@app.route('/')
def dashboard():
    """Renders the main dashboard page."""
    return render_template('dashboard.html')

@app.route('/live_monitor')
def live_monitor():
    """Renders the live monitor page."""
    return render_template('live_monitor.html')

@app.route('/phishing_logs')
def phishing_logs():
    """Renders the phishing logs page."""
    return render_template('phishing_logs.html')

@app.route('/pcap_analysis')
def pcap_analysis():
    """Renders the PCAP analysis page."""
    return render_template('pcap_analysis.html')

@app.route('/devices')
def devices():
    """Renders the devices on network page."""
    return render_template('devices.html')

@app.route('/settings') # This route is now only for rendering the HTML page
def settings_page():
    """Renders the settings page."""
    return render_template('settings.html')

@app.route('/api/dashboard_data')
def get_dashboard_data():
    """
    API endpoint to provide dynamic dashboard data.
    This function simulates real-time updates by incrementally changing global variables
    and maintaining a sliding window for the chart data.
    """
    global live_packets_captured, live_phishing_attempts
    global threat_chart_labels, threat_chart_data, recent_events_history

    # Update threat summary data for the chart (sliding window)
    current_time_label = time.strftime("%H:%M:%S")

    # Append new data point and label, deque handles popping old ones automatically
    # Only append if the last label is different (to avoid too many identical points)
    if not threat_chart_labels or threat_chart_labels[-1] != current_time_label:
        threat_chart_labels.append(current_time_label)
        threat_chart_data.append(live_phishing_attempts)


    # Prepare data for JSON response
    data = {
        "packets_captured": live_packets_captured,
        "phishing_attempts": live_phishing_attempts,
        "devices_found": len(discovered_devices), # Use actual count of discovered devices
        "threat_summary": {
            "labels": list(threat_chart_labels), # Convert deque to list for JSON serialization
            "data": list(threat_chart_data)
        },
        "recent_events": list(recent_events_history) # Convert deque to list
    }
    return jsonify(data)

@app.route('/api/settings', methods=['GET', 'POST']) # Allow both GET and POST for the API endpoint
def handle_api_settings():
    """
    API endpoint to handle loading and saving application settings.
    GET: Provides current application settings.
    POST: Receives and saves settings from the frontend.
    """
    global app_settings
    if request.method == 'GET':
        return jsonify(app_settings)
    elif request.method == 'POST':
        new_settings = request.get_json()
        if new_settings:
            app_settings.update(new_settings)
            save_app_settings(app_settings) # Call save_app_settings which now updates phishing module
            return jsonify({"status": "success", "message": "Settings saved"}), 200
        return jsonify({"status": "error", "message": "Invalid data"}), 400

@app.route('/api/interfaces', methods=['GET'])
def get_network_interfaces():
    """
    API endpoint to list available network interfaces.
    Uses the live_capture module.
    """
    interfaces = live_capture.list_interfaces()
    return jsonify(interfaces)

@app.route('/api/scan_devices', methods=['POST'])
def scan_devices():
    """
    API endpoint to trigger an ARP scan and return discovered devices.
    Requires interface and optionally an IP range.
    """
    data = request.get_json()
    interface_scapy_name = data.get('interface') # This is the \Device\NPF_{GUID} name
    ip_range = data.get('ip_range') # e.g., "192.168.1.0/24"

    if not interface_scapy_name:
        return jsonify({"status": "error", "message": "No interface selected for scan."}), 400

    # If no IP range provided, try to determine it from the interface's IP
    if not ip_range:
        try:
            local_ip = None
            subnet_mask = None
            
            # Iterate through all psutil interfaces to find the one matching the Scapy name
            # or at least a valid IPv4 address and netmask from any active interface.
            for ps_iface_name, ps_addrs in psutil.net_if_addrs().items():
                # On Windows, try to match the GUID part of the NPF name
                if sys.platform.startswith('win') and interface_scapy_name.startswith("\\Device\\NPF_"):
                    scapy_guid = interface_scapy_name.split('{')[-1].rstrip('}')
                    if scapy_guid in ps_iface_name: # ps_iface_name might contain GUID on some systems
                        # Found a potential match, now get its IP and netmask
                        for addr_info in ps_addrs:
                            if addr_info.family == socket.AF_INET: # IPv4 address
                                local_ip = addr_info.address
                                subnet_mask = addr_info.netmask
                                break
                        if local_ip and subnet_mask:
                            break # Found for Windows NPF match
                # For Linux/macOS or if Windows NPF match failed, try direct name match
                elif interface_scapy_name == ps_iface_name:
                    for addr_info in ps_addrs:
                        if addr_info.family == socket.AF_INET: # IPv4 address
                            local_ip = addr_info.address
                            subnet_mask = addr_info.netmask
                            break
                    if local_ip and subnet_mask:
                        break # Found for direct name match
            
            if not local_ip or not subnet_mask:
                # Fallback if no specific match found, try to find any active IPv4 interface
                # This ensures we at least have a subnet to scan if the primary interface lookup fails
                for ps_iface_name, ps_addrs in psutil.net_if_addrs().items():
                    for addr_info in ps_addrs:
                        if addr_info.family == socket.AF_INET and addr_info.address != '127.0.0.1':
                            local_ip = addr_info.address
                            subnet_mask = addr_info.netmask
                            print(f"Warning: Specific interface subnet not found, using general active IP: {local_ip}")
                            break
                    if local_ip and subnet_mask:
                        break

            if not local_ip or not subnet_mask:
                # If still no valid IP or subnet mask found, return error
                return jsonify({"status": "error", "message": f"Could not determine a valid IP or subnet mask for interface {interface_scapy_name}. Please ensure the interface is active and has a valid IPv4 address, or provide a manual IP range (e.g., 192.168.1.0/24)."}), 400
            
            # Calculate the network address from IP and netmask
            network = ipaddress.ip_network(f"{local_ip}/{subnet_mask}", strict=False)
            ip_range = str(network.with_prefixlen) # e.g., 192.168.1.0/24

            print(f"Determined IP range for scan: {ip_range}")

        except Exception as e:
            print(f"Error determining IP range: {e}")
            return jsonify({"status": "error", "message": f"Error determining IP range: {e}. Please specify an IP range manually."}), 400


    # Run ARP scan in a separate thread to avoid blocking the UI
    def run_arp_scan_thread():
        # Use 'global' here because discovered_devices is a global variable
        global discovered_devices 
        
        # Perform the ARP scan
        devices = live_capture.arp_scan(interface_scapy_name, ip_range) # Use the scapy name for sniffing
        
        # Update the global discovered_devices dictionary
        for dev in devices:
            mac_vendor = oui_lookup.lookup_mac_vendor(dev['mac'])
            discovered_devices[dev['ip']] = {
                "ip": dev['ip'],
                "mac": dev['mac'],
                "vendor": mac_vendor,
                "last_seen": time.strftime("%H:%M:%S"),
                "type": "Active Scan" # Indicate discovery method
            }
        
        # Emit updated device list to connected clients
        socketio.emit('devices_updated', list(discovered_devices.values()))
        print("ARP scan thread finished and devices updated.")

    # Start the ARP scan thread
    scan_thread = threading.Thread(target=run_arp_scan_thread)
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({"status": "success", "message": "ARP scan initiated."}), 200

@app.route('/api/devices_data', methods=['GET'])
def get_devices_data():
    """
    API endpoint to provide current discovered devices.
    """
    # Return the values from the dictionary as a list
    return jsonify(list(discovered_devices.values()))


# --- SocketIO Events for Live Capture ---

def _packet_handler(packet_data):
    """
    Callback function to handle each captured packet.
    Integrates with phishing detection, updates discovered devices,
    and emits the packet data to SocketIO clients.
    """
    global live_packets_captured, live_phishing_attempts, recent_events_history, discovered_devices

    # Increment total packets captured
    live_packets_captured += 1

    # Update discovered devices from passive sniffing
    src_ip = packet_data.get('source_ip')
    src_mac = packet_data.get('source_mac')
    dest_ip = packet_data.get('dest_ip')
    dest_mac = packet_data.get('dest_mac')
    
    current_time = time.strftime("%H:%M:%S")

    # Update source device
    if src_ip and src_ip != "N/A" and src_mac and src_mac != "N/A":
        if src_ip not in discovered_devices:
            vendor = oui_lookup.lookup_mac_vendor(src_mac)
            discovered_devices[src_ip] = {
                "ip": src_ip,
                "mac": src_mac,
                "vendor": vendor,
                "last_seen": current_time,
                "type": "Passive Sniff"
            }
            socketio.emit('devices_updated', list(discovered_devices.values())) # Notify frontend of new device
        else:
            # Update last seen time for existing device
            discovered_devices[src_ip]["last_seen"] = current_time
            # You might want to emit a partial update or update less frequently for existing devices

    # Update destination device (if different from source and not broadcast)
    if dest_ip and dest_ip != "N/A" and dest_mac and dest_mac != "N/A" and dest_ip != "255.255.255.255" and dest_mac.lower() != "ff:ff:ff:ff:ff:ff":
        if dest_ip not in discovered_devices:
            vendor = oui_lookup.lookup_mac_vendor(dest_mac)
            discovered_devices[dest_ip] = {
                "ip": dest_ip,
                "mac": dest_mac,
                "vendor": vendor,
                "last_seen": current_time,
                "type": "Passive Sniff"
            }
            socketio.emit('devices_updated', list(discovered_devices.values())) # Notify frontend of new device
        else:
            discovered_devices[dest_ip]["last_seen"] = current_time


    # Integrate with phishing detection logic
    if packet_data.get('url') and packet_data['url'] not in ["N/A", "HTTP_URL_Parse_Error", "HTTPS (Encrypted)", "DNS_Query_Error", "ARP_Packet", "HTTP_Response"]:
        phishing_result = phishing.analyze_url_for_phishing(packet_data['url'])
        packet_data['risk_level'] = phishing_result['threat_level']
        packet_data['detection_methods'] = phishing_result['detection_methods']

        if packet_data['risk_level'] in ["High", "Medium"]:
            live_phishing_attempts += 1
            # Add to recent events history if it's a detected threat
            recent_events_history.appendleft({
                "time": packet_data['timestamp'],
                "source_ip": packet_data['source_ip'],
                "dest_ip": packet_data['dest_ip'],
                "protocol": packet_data['protocol'],
                "url": packet_data['url'],
                "risk_level": packet_data['risk_level'],
                "detection_methods": packet_data['detection_methods']
            })
    else:
        # For packets without a URL or non-HTTP/S, assign a default low risk
        packet_data['risk_level'] = "Low"
        packet_data['detection_methods'] = ["N/A (No URL or non-HTTP/S)"]

    socketio.emit('new_packet', packet_data)

@socketio.on('start_capture')
def start_capture_socket(data):
    """
    Handles the 'start_capture' SocketIO event from the client.
    Starts the packet capture in a new thread.
    """
    global capture_thread, is_capturing, current_interface
    interface = data.get('interface')

    if is_capturing:
        emit('capture_status', {'status': 'already_running', 'message': 'Capture is already running.'})
        return

    if not interface:
        emit('capture_status', {'status': 'error', 'message': 'No interface selected.'})
        return

    current_interface = interface
    is_capturing = True
    emit('capture_status', {'status': 'started', 'message': f'Starting capture on {interface}...'}), 200

    capture_thread = threading.Thread(target=live_capture.start_capture, args=(interface, _packet_handler))
    capture_thread.daemon = True
    capture_thread.start()

@socketio.on('stop_capture')
def stop_capture_socket():
    """
    Handles the 'stop_capture' SocketIO event from the client.
    Stops the packet capture.
    """
    global is_capturing
    if is_capturing:
        live_capture.stop_capture_signal = True
        is_capturing = False
        emit('capture_status', {'status': 'stopped', 'message': 'Capture stopped.'}), 200
    else:
        emit('capture_status', {'status': 'not_running', 'message': 'Capture is not running.'}), 200

from backend.attacks import arp_spoof

@app.route('/start_mitm', methods=['POST'])
def start_mitm():
    data = request.get_json()
    target_ip = data['target_ip']
    gateway_ip = data['gateway_ip']
    interface = data['interface']
    arp_spoof.start_arp_spoof(target_ip, gateway_ip, interface)
    return jsonify({"status": "MITM started"})

@app.route('/stop_mitm', methods=['POST'])
def stop_mitm():
    try:
        # If your stop function doesn't need parameters, don't fetch from request
        # arp_spoof.stop_arp_spoof()  # Update this based on your implementation
        return jsonify({"message": "MITM attack stopped successfully."})
    except Exception as e:
        print(f"Error stopping MITM: {e}")
        return jsonify({"message": f"Failed to stop MITM: {str(e)}"}), 500


from backend.utils.network_interface import get_default_wifi_interface

@app.route('/get_default_interface')
def get_default_interface():
    return jsonify({"interface": get_default_wifi_interface()})

from flask import request, jsonify
import scapy.all as scapy
import socket

@app.route('/scan_network', methods=['POST'])
def scan_network():
    try:
        data = request.get_json()
        interface = data.get('interface')

        # Get local IP address of the selected interface
        local_ip = scapy.get_if_addr(interface)
        subnet = local_ip.rsplit('.', 1)[0] + '.1/24'

        # Perform ARP scan
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=2, iface=interface, verbose=False)[0]

        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = None
            devices.append({"ip": ip, "mac": mac, "hostname": hostname})

        return jsonify({"devices": devices})

    except Exception as e:
        print("Error in scan_network:", e)
        return jsonify({"error": "Failed to scan network"}), 500

# --- Application Entry Point ---
if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)

    # Run the Flask app with SocketIO
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
