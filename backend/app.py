from flask import Flask
from flask import render_template
from flask_socketio import SocketIO, emit
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'api'))
from live_capture import LiveCaptureThread

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