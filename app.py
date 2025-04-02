from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
from python import password_checker, port_scanner, mic_cam_monitor, password_checker, browser_check

app = Flask(__name__)
CORS(app)

# Password Strength Checker
@app.route("/check_password", methods=["POST"])
def check_password():
    data = request.json
    password = data.get("password", "")
    strength = password_checker.check_password_strength(password)
    return jsonify({"password_strength": strength})

# Microphone & Camera Hijack Detection
@app.route("/check_mic_cam", methods=["GET"])
def check_mic_cam():
    result = mic_cam_monitor.check_mic_cam_usage()
    print("Mic Cam Detection Output:", result)  # Debugging
    return jsonify(json.loads(result))  # Ensure JSON response



# Browser Privacy Scanner
@app.route("/check_browser", methods=["GET"])
def check_browser():
    privacy_data = browser_check.check_browser_privacy()
    return jsonify(privacy_data)

# Home Route
@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
