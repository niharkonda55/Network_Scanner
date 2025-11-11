from flask_socketio import emit
from backend.api import live_capture
import threading

# --- Live Capture State ---
is_capturing = False
capture_thread = None

def register_socketio_events(socketio, packet_handler):
    @socketio.on('start_capture')
    def start_capture_socket(data):
        """
        Handles the 'start_capture' SocketIO event from the client.
        Starts the packet capture in a new thread.
        """
        global capture_thread, is_capturing
        interface = data.get('interface')

        if is_capturing:
            emit('capture_status', {'status': 'already_running', 'message': 'Capture is already running.'})
            return

        if not interface:
            emit('capture_status', {'status': 'error', 'message': 'No interface selected.'})
            return

        is_capturing = True
        emit('capture_status', {'status': 'started', 'message': f'Starting capture on {interface}...'}), 200

        capture_thread = threading.Thread(target=live_capture.start_capture, args=(interface, packet_handler))
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
