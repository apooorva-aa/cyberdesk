import psutil
import time
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

def collect_baseline_samples(duration=60, interval=5):
    data = []

    for _ in range(int(duration / interval)):
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'exe', 'ppid']):
            try:
                info = proc.info
                cpu = round(float(info['cpu_percent'] or 0), 3)
                mem = round(float(info['memory_percent'] or 0), 3)

                data.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu': cpu,
                    'memory': mem,
                    'username': info['username'],
                    'exe': info['exe'],
                    'ppid': info['ppid'],
                    'name_len': len(info['name']) if info['name'] else 0,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
                continue
        time.sleep(interval)

    return pd.DataFrame(data)

if __name__ == "__main__":
    df = collect_baseline_samples(duration=120, interval=5)
    df = df.dropna()

    feature_cols = ['cpu', 'memory', 'name_len']
    model = IsolationForest(contamination=0.05)
    model.fit(df[feature_cols])

    joblib.dump(model, 'model.joblib')
    df[['pid', 'name', 'exe']].drop_duplicates().to_csv('baseline_whitelist.csv', index=False)
    print("[+] Baseline model trained and saved.")
