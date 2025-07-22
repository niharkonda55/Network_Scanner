from flask import Flask
from flask import render_template
from flask_socketio import SocketIO, emit
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'api'))
from live_capture import LiveCaptureThread
from flask import request, jsonify
import tempfile
import threading
import os
import pyshark
from analysis.phishing import analyze_url
from utils.oui_lookup import lookup_vendor

app = Flask(__name__)
socketio = SocketIO(app)

capture_thread = None

@socketio.on('start_capture')
def handle_start_capture(data):
    global capture_thread
    if capture_thread and capture_thread.is_alive():
        return
    interface = data.get('interface', 'Wi-Fi')
    capture_thread = LiveCaptureThread(socketio, interface=interface)
    capture_thread.start()

@socketio.on('stop_capture')
def handle_stop_capture():
    global capture_thread
    if capture_thread and capture_thread.is_alive():
        capture_thread.stop()
        capture_thread = None

def pcap_packet_to_dict(pkt):
    try:
        url = pkt.http.host + pkt.http.request_uri if hasattr(pkt, 'http') and hasattr(pkt.http, 'host') and hasattr(pkt.http, 'request_uri') else ''
        return {
            'timestamp': pkt.sniff_time.strftime('%H:%M:%S'),
            'src_ip': pkt.ip.src if hasattr(pkt, 'ip') else '',
            'dst_ip': pkt.ip.dst if hasattr(pkt, 'ip') else '',
            'src_mac': pkt.eth.src if hasattr(pkt, 'eth') and hasattr(pkt.eth, 'src') else '',
            'dst_mac': pkt.eth.dst if hasattr(pkt, 'eth') and hasattr(pkt.eth, 'dst') else '',
            'src_port': pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') and hasattr(pkt[pkt.transport_layer], 'srcport') else '',
            'dst_port': pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') and hasattr(pkt[pkt.transport_layer], 'dstport') else '',
            'protocol': pkt.highest_layer,
            'length': int(pkt.length) if hasattr(pkt, 'length') else 0,
            'url': url
        }
    except Exception:
        return {}

def analyze_pcap_file(file_path, socketio):
    devices = {}
    capture = pyshark.FileCapture(file_path, use_json=True, include_raw=False)
    for pkt in capture:
        pkt_data = pcap_packet_to_dict(pkt)
        if pkt_data:
            socketio.emit('pcap_packet', pkt_data)
            # Device tracking
            for direction in [('src', 'src_ip', 'src_mac'), ('dst', 'dst_ip', 'dst_mac')]:
                ip = pkt_data.get(direction[1])
                mac = pkt_data.get(direction[2])
                if ip and mac:
                    key = (ip, mac)
                    now = pkt_data['timestamp']
                    if key not in devices:
                        devices[key] = {
                            'ip': ip,
                            'mac': mac,
                            'vendor': lookup_vendor(mac),
                            'first_seen': now,
                            'last_seen': now,
                            'packets': 1
                        }
                    else:
                        devices[key]['last_seen'] = now
                        devices[key]['packets'] += 1
                    socketio.emit('pcap_device_update', devices[key])
            # Phishing detection
            if pkt_data.get('url'):
                result = analyze_url('http://' + pkt_data['url'] if not pkt_data['url'].startswith('http') else pkt_data['url'])
                if result['level'] != 'None':
                    alert = {
                        'timestamp': pkt_data['timestamp'],
                        'src_ip': pkt_data['src_ip'],
                        'dst_ip': pkt_data['dst_ip'],
                        'protocol': pkt_data['protocol'],
                        'url': result['url'],
                        'risk': result['level'],
                        'score': result['score']
                    }
                    socketio.emit('pcap_phishing_alert', alert)
    socketio.emit('pcap_analysis_done')
    capture.close()
    os.remove(file_path)

@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    if 'pcap' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    file = request.files['pcap']
    if not file.filename.endswith(('.pcap', '.pcapng')):
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    temp = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
    file.save(temp.name)
    temp.close()
    thread = threading.Thread(target=analyze_pcap_file, args=(temp.name, socketio))
    thread.start()
    return jsonify({'success': True})

@app.route('/')
def home():
    return 'Backend is running!'

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/live-monitor')
def live_monitor():
    return render_template('live_monitor.html')

@app.route('/phishing-logs')
def phishing_logs():
    return render_template('phishing_logs.html')

@app.route('/pcap-analysis')
def pcap_analysis():
    return render_template('pcap_analysis.html')

@app.route('/devices')
def devices():
    return render_template('devices.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

if __name__ == '__main__':
    socketio.run(app, debug=True) 