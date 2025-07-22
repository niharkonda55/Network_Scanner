import pyshark
from flask_socketio import emit
import threading
import time
from analysis.phishing import analyze_url
from utils.oui_lookup import lookup_vendor

def packet_to_dict(pkt):
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

class LiveCaptureThread(threading.Thread):
    def __init__(self, socketio, interface='Wi-Fi'):
        super().__init__()
        self.socketio = socketio
        self.interface = interface
        self.running = False
        self.devices = {}

    def run(self):
        self.running = True
        capture = pyshark.LiveCapture(interface=self.interface)
        for pkt in capture.sniff_continuously():
            if not self.running:
                break
            pkt_data = packet_to_dict(pkt)
            if pkt_data:
                self.socketio.emit('packet', pkt_data)
                # Device tracking
                for direction in [('src', 'src_ip', 'src_mac'), ('dst', 'dst_ip', 'dst_mac')]:
                    ip = pkt_data.get(direction[1])
                    mac = pkt_data.get(direction[2])
                    if ip and mac:
                        key = (ip, mac)
                        now = time.strftime('%H:%M:%S')
                        if key not in self.devices:
                            self.devices[key] = {
                                'ip': ip,
                                'mac': mac,
                                'vendor': lookup_vendor(mac),
                                'first_seen': now,
                                'last_seen': now,
                                'packets': 1
                            }
                        else:
                            self.devices[key]['last_seen'] = now
                            self.devices[key]['packets'] += 1
                        self.socketio.emit('device_update', self.devices[key])
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
                        self.socketio.emit('phishing_alert', alert)

    def stop(self):
        self.running = False 