import psutil
import pandas as pd
import joblib

model = joblib.load("model.joblib")
baseline = pd.read_csv("baseline_whitelist.csv")

def is_whitelisted(proc_info):
    return ((baseline['name'] == proc_info['name']) &
            (baseline['exe'] == proc_info['exe'])).any()

def extract_features(proc):
    return {
        'pid': proc.pid,
        'name': proc.name(),
        'cpu': round(proc.cpu_percent(interval=0.1), 3),
        'memory': round(proc.memory_percent(), 3),
        'username': proc.username(),
        'exe': proc.exe(),
        'ppid': proc.ppid(),
        'name_len': len(proc.name()),
    }

def detect_anomaly():
    anomalies = []

    for proc in psutil.process_iter(['pid']):
        try:
            info = extract_features(proc)

            if is_whitelisted(info):
                continue

            features = [[info['cpu'], info['memory'], info['name_len']]]
            prediction = model.predict(features)

            if prediction[0] == -1:
                anomalies.append(info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return anomalies

def get_anomalous_processes():
    detected = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            cpu = round(info['cpu_percent'], 3)
            mem = round(info['memory_percent'], 3)
            name_len = len(info['name']) if info['name'] else 0

            features = [[cpu, mem, name_len]]
            prediction = model.predict(features)

            if prediction[0] == -1:
                detected.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "cpu": cpu,
                    "mem": mem
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return detected

if __name__ == "__main__":
    results = detect_anomaly()
    for a in results:
        print(f"[!] Suspicious: {a['name']} (PID {a['pid']}) | EXE: {a['exe']} | CPU: {a['cpu']}% | MEM: {a['memory']}% | User: {a['username']}")
