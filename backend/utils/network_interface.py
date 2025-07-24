import psutil

def get_default_wifi_interface():
    interfaces = psutil.net_if_addrs()
    for iface in interfaces:
        if "wl" in iface or "wifi" in iface.lower():
            return iface
    return "eth0"  # fallback
