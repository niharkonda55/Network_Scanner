import pyshark
from flask_socketio import emit
import threading
import time

def packet_to_dict(pkt):
    try:
        return {
            'timestamp': pkt.sniff_time.strftime('%H:%M:%S'),
            'src_ip': pkt.ip.src if hasattr(pkt, 'ip') else '',
            'dst_ip': pkt.ip.dst if hasattr(pkt, 'ip') else '',
            'protocol': pkt.highest_layer,
            'length': int(pkt.length) if hasattr(pkt, 'length') else 0,
            'url': pkt.http.host + pkt.http.request_uri if hasattr(pkt, 'http') and hasattr(pkt.http, 'host') and hasattr(pkt.http, 'request_uri') else ''
        }
    except Exception:
        return {}

class LiveCaptureThread(threading.Thread):
    def __init__(self, socketio, interface='Wi-Fi'):
        super().__init__()
        self.socketio = socketio
        self.interface = interface
        self.running = False

    def run(self):
        self.running = True
        capture = pyshark.LiveCapture(interface=self.interface)
        for pkt in capture.sniff_continuously():
            if not self.running:
                break
            pkt_data = packet_to_dict(pkt)
            if pkt_data:
                self.socketio.emit('packet', pkt_data)

    def stop(self):
        self.running = False 