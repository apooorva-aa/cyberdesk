import os
import sys
import scapy.all as scapy
import netifaces
import socket
import ctypes
import dns.resolver

def ensure_admin():
    if os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " " + " ".join(sys.argv), None, 1)
            sys.exit()
    else:
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)

def get_active_interface():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        adds = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in adds:
            return iface
    return None

def check_promiscuous_mode(skip_admin = False):
    if not skip_admin:
        ensure_admin()
    interface = get_active_interface()
    if not interface:
        return {"error": "No active network interface detected"}
    
    cmd = f"ip link show {interface} | grep PROMISC"
    output = os.popen(cmd).read()
    return {"promiscuous_mode": bool(output.strip())}

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

def check_arp_spoofing(skip_admin = False):
    if not skip_admin:
        ensure_admin()
    subnet = get_local_subnet()
    if not subnet:
        return {"error": "Failed to determine local subnet"}

    try:
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)

        mac_to_ip = {}
        suspects = []

        for _, received in answered:
            if received.hwsrc in mac_to_ip and mac_to_ip[received.hwsrc] != received.psrc:
                suspects.append({
                    "mac": received.hwsrc,
                    "ip1": mac_to_ip[received.hwsrc],
                    "ip2": received.psrc
                })
            mac_to_ip[received.hwsrc] = received.psrc

        return {
            "arp_spoofing_detected": len(suspects) > 0,
            "suspects": suspects
        }
    except Exception as e:
        return {"error": str(e)}

def check_dns_spoofing():
    domain = "google.com"
    trusted_dns_servers = {
        "Google DNS": "8.8.8.8",
        "Cloudflare DNS": "1.1.1.1",
        "Quad9 DNS": "9.9.9.9",
        "OpenDNS": "208.67.222.222"
    }

    try:
        system_ip = socket.gethostbyname(domain)

        trusted_ips = {}
        for name, server in trusted_dns_servers.items():
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            try:
                ip = resolver.resolve(domain)[0].to_text()
                trusted_ips[name] = ip
            except Exception as e:
                trusted_ips[name] = f"Error: {str(e)}"

        is_spoofed = system_ip not in trusted_ips.values()

        return {
            "dns_spoofing_detected": is_spoofed,
            "system_ip": system_ip,
            "trusted_dns_results": trusted_ips
        }

    except Exception as e:
        return {"error": str(e)}

def detect_unknown_devices(skip_admin = False):
    if not skip_admin:
        ensure_admin()
    subnet = get_local_subnet()
    if not subnet:
        return {"error": "Could not get local subnet"}

    known_devices = ["YourRouterMAC", "YourDeviceMAC"]
    try:
        answered, _ = scapy.arping(subnet, timeout=2, verbose=False)

        unknown_devices = []
        for _, received in answered:
            if received.hwsrc not in known_devices:
                unknown_devices.append({"ip": received.psrc, "mac": received.hwsrc})

        return {"unknown_devices": unknown_devices}
    except Exception as e:
        return {"error": str(e)}