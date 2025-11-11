from flask import Blueprint, render_template

main_routes = Blueprint('main', __name__)

@main_routes.route('/')
def dashboard():
    """Renders the main dashboard page."""
    return render_template('dashboard.html')

@main_routes.route('/live_monitor')
def live_monitor():
    """Renders the live monitor page."""
    return render_template('live_monitor.html')

@main_routes.route('/phishing_logs')
def phishing_logs():
    """Renders the phishing logs page."""
    return render_template('phishing_logs.html')

@main_routes.route('/pcap_analysis')
def pcap_analysis():
    """Renders the PCAP analysis page."""
    return render_template('pcap_analysis.html')

@main_routes.route('/devices')
def devices():
    """Renders the devices on network page."""
    return render_template('devices.html')

@main_routes.route('/settings')
def settings_page():
    """Renders the settings page."""
    return render_template('settings.html')
