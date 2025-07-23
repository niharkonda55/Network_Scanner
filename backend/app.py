# app.py
from flask import Flask, render_template, jsonify, url_for
import os
import time
import random
from collections import deque # For a fixed-size queue to simulate sliding window

app = Flask(__name__)

# --- Global variables to simulate real-time data ---
# In a real application, these would be populated by your network sniffing and analysis logic.
live_packets_captured = 0
live_phishing_attempts = 0
live_devices_found = 0

# For the threat summary chart, simulate a sliding window of data points.
# This ensures the graph doesn't grow indefinitely on the x-axis.
MAX_CHART_DATA_POINTS = 15 # Display the last 15 intervals/data points on the chart
threat_chart_labels = deque(maxlen=MAX_CHART_DATA_POINTS)
threat_chart_data = deque(maxlen=MAX_CHART_DATA_POINTS)

# Initialize with some dummy data to avoid an empty graph on first load
for i in range(MAX_CHART_DATA_POINTS):
    # Generate labels for the past intervals
    threat_chart_labels.append(time.strftime("%H:%M:%S", time.localtime(time.time() - (MAX_CHART_DATA_POINTS - 1 - i) * 5)))
    # Generate random initial data points
    threat_chart_data.append(random.randint(0, 5))

# Simulate a history of recent events for the table
recent_events_history = deque(maxlen=20) # Keep a history of the last 20 events

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

@app.route('/settings')
def settings():
    """Renders the settings page."""
    return render_template('settings.html')

@app.route('/api/dashboard_data')
def get_dashboard_data():
    """
    API endpoint to provide dynamic dashboard data.
    This function simulates real-time updates by incrementally changing global variables
    and maintaining a sliding window for the chart data.
    """
    global live_packets_captured, live_phishing_attempts, live_devices_found
    global threat_chart_labels, threat_chart_data, recent_events_history

    # --- Simulate new network activity ---
    new_packets = random.randint(50, 200)
    live_packets_captured += new_packets

    # Simulate a new phishing attempt occasionally
    current_risk = "Low"
    if random.random() < 0.2: # 20% chance of a new phishing attempt per update
        live_phishing_attempts += 1
        current_risk = random.choice(["High", "High", "Medium"]) # Higher chance of high risk for new phishing
    else:
        current_risk = random.choice(["Low", "Low", "Low", "Medium"]) # More chance of low risk for general traffic

    # Simulate new device discovery occasionally
    if random.random() < 0.05: # 5% chance of a new device per update
        live_devices_found += 1

    # --- Update threat summary data for the chart (sliding window) ---
    current_time_label = time.strftime("%H:%M:%S")

    # Append new data point and label, deque handles popping old ones automatically
    threat_chart_labels.append(current_time_label)
    # The new data point for the chart can reflect current phishing attempts or a random value
    threat_chart_data.append(live_phishing_attempts) # Using cumulative attempts for a growing trend

    # --- Simulate recent events data for the table ---
    new_event = {
        "time": current_time_label,
        "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(10, 200)}",
        "dest_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "protocol": random.choice(["HTTP", "HTTPS", "TCP", "UDP", "ICMP", "DNS", "ARP"]),
        "url": random.choice([
            "example.com/login", "safe-site.com/index", "malicious.phish/link",
            "google.com", "github.com", "docs.python.org", "bad-domain.xyz/verify",
            "bank-secure-login.net", "facebook-support.info", "legit-app.com/dashboard"
        ]),
        "risk_level": current_risk
    }
    recent_events_history.appendleft(new_event) # Add to the beginning for most recent first

    # Prepare data for JSON response
    data = {
        "packets_captured": live_packets_captured,
        "phishing_attempts": live_phishing_attempts,
        "devices_found": live_devices_found,
        "threat_summary": {
            "labels": list(threat_chart_labels), # Convert deque to list for JSON serialization
            "data": list(threat_chart_data)
        },
        "recent_events": list(recent_events_history) # Convert deque to list
    }
    return jsonify(data)

# --- Application Entry Point ---
if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)

    # For development, run with Flask's built-in server.
    # debug=True allows for automatic reloading on code changes.
    # host='0.0.0.0' makes the server accessible from other devices on the network.
    app.run(debug=True, host='0.0.0.0', port=5000)
