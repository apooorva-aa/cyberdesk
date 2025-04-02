import os
import sys
import scapy.all as scapy
import netifaces, socket, requests
import ctypes

def ensure_admin():
    if os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " " + " ".join(sys.argv), None, 1)
            sys.exit()
    else:
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)

def check_promiscuous_mode():
    ensure_admin()
    interface = get_active_interface()
    if not interface:
        return {"error": "No active network interface detected"}
    
    cmd = f"ip link show {interface} | grep PROMISC"
    output = os.popen(cmd).read()

    return {"promiscuous_mode" : bool(output.strip())}

def get_active_interface():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        adds = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in adds:
            return iface
    return None

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
        s.close()

        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                if ip_info['addr'] == active_ip:
                    netmask = ip_info['netmask']
                    cidr = sum(bin(int(octet)).count('1') for octet in netmask.split('.'))
                    return f"{active_ip}/{cidr}"
    except Exception as e:
        return str(e)
    return None

def check_arp_spoofing():
    ensure_admin()
    subnet = get_local_subnet()
    if not subnet:
        return {"error" : "Failed to determine local subnet"}
    
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)

    mac_list = {}
    for sent, received in answered:
        if received.hwsrc in mac_list:
            return {"arp_spoofing_detected": True, "suspect_mac": received.hwsrc}
        mac_list[received.hwsrc] = received.psrc

    return {"arp_spoofing_detected": False}

def check_dns_spoofing():
    try:
        trusted_dns_ip = "8.8.8.8"
        resolved_ip = socket.gethostbyname("google.com")
        subnet = get_local_subnet()
        return {
            "dns_spoofing_detected": resolved_ip != trusted_dns_ip,
            "resolved_ip": resolved_ip,
            "expected_ip": trusted_dns_ip,
            "local_subnet": subnet
        }
    except Exception as e:
        return {"error": str(e)}

def detect_unknown_devices():
    ensure_admin()
    known_devices = ["YourRouterMAC", "YourDeviceMAC"]
    scan_result = scapy.arping("192.168.1.1/24", verbose=False)[0]

    unknown_devices = []
    for _, received in scan_result:
        if received.hwsrc not in known_devices:
            unknown_devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return {"unknown_devices": unknown_devices}