from flask import Flask
from flask_socketio import SocketIO
from config import Config
from blueprints.main_routes import main_routes
from blueprints.api_routes import api_routes
from blueprints.socketio_events import register_socketio_events
import os
import json
from collections import deque
import time
from backend.analysis import phishing
from backend.utils import oui_lookup

# --- App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app)
app.socketio = socketio

# --- Global Shared State ---
# These variables will be accessible to the blueprints
app.live_packets_captured = 0
app.live_phishing_attempts = 0
app.threat_chart_labels = deque(maxlen=15)
app.threat_chart_data = deque(maxlen=15)
app.recent_events_history = deque(maxlen=20)
app.discovered_devices = {}
app.app_settings = {}

from settings_manager import load_app_settings, save_app_settings

app.app_settings = load_app_settings()
phishing.set_api_keys(
    app.app_settings.get("phishtank_api_key", ""),
    app.app_settings.get("google_safe_browsing_api_key", "")
)

# --- Register Blueprints ---
app.register_blueprint(main_routes)
app.register_blueprint(api_routes)

# --- Packet Handler ---
def _packet_handler(packet_data):
    """
    Callback function to handle each captured packet.
    This function will be passed to the packet capture thread.
    """
    app.live_packets_captured += 1

    src_ip = packet_data.get('source_ip')
    src_mac = packet_data.get('source_mac')
    dest_ip = packet_data.get('dest_ip')
    dest_mac = packet_data.get('dest_mac')
    
    current_time = time.strftime("%H:%M:%S")

    if src_ip and src_ip != "N/A" and src_mac and src_mac != "N/A":
        if src_ip not in app.discovered_devices:
            vendor = oui_lookup.lookup_mac_vendor(src_mac)
            app.discovered_devices[src_ip] = {
                "ip": src_ip,
                "mac": src_mac,
                "vendor": vendor,
                "last_seen": current_time,
                "type": "Passive Sniff"
            }
            socketio.emit('devices_updated', list(app.discovered_devices.values()))
        else:
            app.discovered_devices[src_ip]["last_seen"] = current_time

    if dest_ip and dest_ip != "N/A" and dest_mac and dest_mac != "N/A" and dest_ip != "255.255.255.255" and dest_mac.lower() != "ff:ff:ff:ff:ff:ff":
        if dest_ip not in app.discovered_devices:
            vendor = oui_lookup.lookup_mac_vendor(dest_mac)
            app.discovered_devices[dest_ip] = {
                "ip": dest_ip,
                "mac": dest_mac,
                "vendor": vendor,
                "last_seen": current_time,
                "type": "Passive Sniff"
            }
            socketio.emit('devices_updated', list(app.discovered_devices.values()))
        else:
            app.discovered_devices[dest_ip]["last_seen"] = current_time

    if packet_data.get('url') and packet_data['url'] not in ["N/A", "HTTP_URL_Parse_Error", "HTTPS (Encrypted)", "DNS_Query_Error", "ARP_Packet", "HTTP_Response"]:
        phishing_result = phishing.analyze_url_for_phishing(packet_data['url'])
        packet_data['risk_level'] = phishing_result['threat_level']
        packet_data['detection_methods'] = phishing_result['detection_methods']

        if packet_data['risk_level'] in ["High", "Medium"]:
            app.live_phishing_attempts += 1
            app.recent_events_history.appendleft({
                "time": packet_data['timestamp'],
                "source_ip": packet_data['source_ip'],
                "dest_ip": packet_data['dest_ip'],
                "protocol": packet_data['protocol'],
                "url": packet_data['url'],
                "risk_level": packet_data['risk_level'],
                "detection_methods": packet_data['detection_methods']
            })
    else:
        packet_data['risk_level'] = "Low"
        packet_data['detection_methods'] = ["N/A (No URL or non-HTTP/S)"]

    socketio.emit('new_packet', packet_data)

# --- Register SocketIO Events ---
register_socketio_events(socketio, _packet_handler)

# --- Application Entry Point ---
if __name__ == '__main__':
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
