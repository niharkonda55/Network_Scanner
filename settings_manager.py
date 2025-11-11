import os
import json
from backend.analysis import phishing

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
    phishing.set_api_keys(
        settings.get("phishtank_api_key", ""),
        settings.get("google_safe_browsing_api_key", "")
    )
