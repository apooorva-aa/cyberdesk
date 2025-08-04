from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
from python import password_checker, port_scanner, mic_cam_monitor, browser_check, network_sniffer, process_monitor

app = Flask(__name__)
CORS(app)


@app.route("/check_password", methods=["POST"])
def check_password():
    data = request.json
    password = data.get("password", "")
    strength = password_checker.check_password_strength(password)
    return jsonify({"password_strength": strength})

@app.route("/check_mic_cam", methods=["GET"])
def check_mic_cam():
    result = mic_cam_monitor.check_mic_cam_usage()
    print("Mic Cam Detection Output:", result)
    return jsonify(json.loads(result)) 


@app.route("/check_browser", methods=["GET"])
def check_browser():
    privacy_data = browser_check.check_browser_privacy()
    return jsonify(privacy_data)

@app.route("/detect_sniffing", methods=["GET", "POST"])
def detect_sniffing():
    if request.method == "POST":
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        data = request.get_json()
        admin = data.get("admin", False)
    else:
        admin = False

    if admin:
        promisc = network_sniffer.check_promiscuous_mode(skip_admin=True)
        arp_spoof = network_sniffer.check_arp_spoofing(skip_admin=True)
        unknown_devices = network_sniffer.detect_unknown_devices(skip_admin=True)
    else:
        promisc = {"error": "Admin privileges required"}
        arp_spoof = {"error": "Admin privileges required"}
        unknown_devices = {"error": "Admin privileges required"}

    dns_spoof = network_sniffer.check_dns_spoofing()

    return jsonify({
        "promiscuous_mode": promisc,
        "arp_spoofing": arp_spoof,
        "dns_spoofing": dns_spoof,
        "unknown_devices": unknown_devices
    })

@app.route("/scan_ports", methods=["GET"])
def scan_ports():
    ip_info = port_scanner.get_ip()
    open_ports = port_scanner.scan_ports(ip_info["local_ip"])
    return jsonify({"local_ip": ip_info["local_ip"], "open_ports": open_ports})

@app.route('/check_process_anomalies')
def check_process_anomalies():
    try:
        results = process_monitor.get_anomalous_processes()
        return jsonify({"anomalies": results})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
