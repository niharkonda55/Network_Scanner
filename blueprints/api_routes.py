from flask import Blueprint, jsonify, request, current_app
from backend.api import live_capture
from backend.attacks import arp_spoof
from backend.utils.network_interface import get_default_wifi_interface
from backend.analysis import phishing
import ipaddress
import psutil
import sys
import socket
import threading
import time
from backend.utils import oui_lookup
import scapy.all as scapy
from settings_manager import save_app_settings

api_routes = Blueprint('api', __name__)

@api_routes.route('/api/dashboard_data')
def get_dashboard_data():
    """
    API endpoint to provide dynamic dashboard data.
    """
    data = {
        "packets_captured": current_app.live_packets_captured,
        "phishing_attempts": current_app.live_phishing_attempts,
        "devices_found": len(current_app.discovered_devices),
        "threat_summary": {
            "labels": list(current_app.threat_chart_labels),
            "data": list(current_app.threat_chart_data)
        },
        "recent_events": list(current_app.recent_events_history)
    }
    return jsonify(data)

@api_routes.route('/api/settings', methods=['GET', 'POST'])
def handle_api_settings():
    """
    API endpoint to handle loading and saving application settings.
    """
    if request.method == 'GET':
        return jsonify(current_app.app_settings)
    elif request.method == 'POST':
        new_settings = request.get_json()
        if new_settings:
            current_app.app_settings.update(new_settings)
            save_app_settings(current_app.app_settings)
            return jsonify({"status": "success", "message": "Settings saved"}), 200
        return jsonify({"status": "error", "message": "Invalid data"}), 400

@api_routes.route('/api/interfaces', methods=['GET'])
def get_network_interfaces():
    """
    API endpoint to list available network interfaces.
    """
    interfaces = live_capture.list_interfaces()
    return jsonify(interfaces)

@api_routes.route('/api/scan_devices', methods=['POST'])
def scan_devices():
    """
    API endpoint to trigger an ARP scan and return discovered devices.
    """
    data = request.get_json()
    interface_scapy_name = data.get('interface')
    ip_range = data.get('ip_range')

    if not interface_scapy_name:
        return jsonify({"status": "error", "message": "No interface selected for scan."}), 400

    if not ip_range:
        try:
            local_ip = scapy.get_if_addr(interface_scapy_name)
            subnet = local_ip.rsplit('.', 1)[0] + '.1/24'
            ip_range = subnet
        except Exception as e:
            try:
                local_ip = None
                subnet_mask = None
                for ps_iface_name, ps_addrs in psutil.net_if_addrs().items():
                    if interface_scapy_name == ps_iface_name:
                        for addr_info in ps_addrs:
                            if addr_info.family == socket.AF_INET:
                                local_ip = addr_info.address
                                subnet_mask = addr_info.netmask
                                break
                        if local_ip and subnet_mask:
                            break
                if not local_ip or not subnet_mask:
                    return jsonify({"status": "error", "message": f"Could not determine a valid IP or subnet mask for interface {interface_scapy_name}."}), 400

                network = ipaddress.ip_network(f"{local_ip}/{subnet_mask}", strict=False)
                ip_range = str(network.with_prefixlen)
            except Exception as e2:
                return jsonify({"status": "error", "message": f"Error determining IP range: {e2}."}), 400

    def run_arp_scan_thread(app):
        with app.app_context():
            devices = live_capture.arp_scan(interface_scapy_name, ip_range)
            for dev in devices:
                mac_vendor = oui_lookup.lookup_mac_vendor(dev['mac'])
                current_app.discovered_devices[dev['ip']] = {
                    "ip": dev['ip'],
                    "mac": dev['mac'],
                    "vendor": mac_vendor,
                    "last_seen": time.strftime("%H:%M:%S"),
                    "type": "Active Scan"
                }
            current_app.socketio.emit('devices_updated', list(current_app.discovered_devices.values()))

    scan_thread = threading.Thread(target=run_arp_scan_thread, args=(current_app._get_current_object(),))
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({"status": "success", "message": "ARP scan initiated."}), 200

@api_routes.route('/api/devices_data', methods=['GET'])
def get_devices_data():
    """
    API endpoint to provide current discovered devices.
    """
    return jsonify(list(current_app.discovered_devices.values()))

@api_routes.route('/start_mitm', methods=['POST'])
def start_mitm():
    data = request.get_json()
    target_ip = data['target_ip']
    gateway_ip = data['gateway_ip']
    interface = data['interface']
    arp_spoof.start_arp_spoof(target_ip, gateway_ip, interface)
    return jsonify({"status": "MITM started"})

@api_routes.route('/stop_mitm', methods=['POST'])
def stop_mitm():
    try:
        # If your stop function doesn't need parameters, don't fetch from request
        # arp_spoof.stop_arp_spoof()  # Update this based on your implementation
        return jsonify({"message": "MITM attack stopped successfully."})
    except Exception as e:
        print(f"Error stopping MITM: {e}")
        return jsonify({"message": f"Failed to stop MITM: {str(e)}"}), 500

@api_routes.route('/get_default_interface')
def get_default_interface():
    return jsonify({"interface": get_default_wifi_interface()})

@api_routes.route('/scan_network', methods=['POST'])
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

@api_routes.route('/api/recent_events')
def get_recent_events():
    return jsonify(list(current_app.recent_events_history))

@api_routes.route('/api/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'pcap_file' not in request.files:
        return jsonify({"error": "No PCAP file provided"}), 400

    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        # Use a temporary file to handle the upload
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            packets = scapy.rdpcap(tmp.name)

        analyzed_packets = []
        phishing_detected = 0

        for packet in packets:
            packet_data = live_capture.parse_packet(packet)
            if packet_data.get('url') and packet_data['url'] not in ["N/A", "HTTP_URL_Parse_Error", "HTTPS (Encrypted)", "DNS_Query_Error", "ARP_Packet", "HTTP_Response"]:
                phishing_result = phishing.analyze_url_for_phishing(packet_data['url'])
                packet_data['risk_level'] = phishing_result['threat_level']
                if phishing_result['threat_level'] in ['High', 'Medium']:
                    phishing_detected += 1
            else:
                packet_data['risk_level'] = 'Low'

            analyzed_packets.append(packet_data)

        return jsonify({
            "packets_analyzed": len(packets),
            "phishing_detected": phishing_detected,
            "analyzed_packets": analyzed_packets
        })
    except Exception as e:
        return jsonify({"error": f"Error processing PCAP file: {e}"}), 500
    finally:
        # Clean up the temporary file
        if 'tmp' in locals() and tmp.name:
            import os
            os.unlink(tmp.name)
