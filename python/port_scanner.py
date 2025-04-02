
import socket
import requests

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]

def get_ip():
    try:
        public_ip = requests.get("https://api64.ipify.org?format=json").json()["ip"]
    except:
        public_ip = "Unknown"

    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except:
        local_ip = "Unknown"

    return {"public_ip": public_ip, "local_ip": local_ip}


def scan_ports(target_ip):
    open_ports = []

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((target_ip, port)) == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

if __name__ == "__main__":
    ip_info = get_ip()
    print(f"Local IP: {ip_info['local_ip']}")
    print(f"Public IP: {ip_info['public_ip']}")
    print(f"Open Local Ports: {scan_ports(ip_info['local_ip'])}")
    if ip_info['public_ip'] != "Unknown":
        print(f"Open Public Ports: {scan_ports(ip_info['public_ip'])}")