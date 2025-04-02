import psutil, subprocess, platform, json

def check_mic_usage():
    sus_processes = []

    system = platform.system()

    if system == "Windows":
        try:
            output = subprocess.check_output(
                'wevtutil qe Security /c:5 /rd:true /f:text',
                shell = True, text = True, errors = 'ignore'
            )
            if "Microphone access" in output:
                sus_processes.append("Recent microphone access detected in logs")
        except Exception as e:
            sus_processes.append(f"Error checking logs: {str(e)}")

    elif system in ["Linux", "Darwin"]:
        mic_keywords = ["arecord", "parecord", "sox", "ffmpeg", "zoom", "teams", "skype"]
        for process in psutil.process_iter(attrs=['pid', 'name']):
            process_name = process.info['name'].lower()
            if any(keyword in process_name for keyword in mic_keywords):
                sus_processes.append(f"Microphone usage: {process.info['name']} (PID {process.info['pid']})")


    return sus_processes

def check_camera_usage():
    sus_processes = []
    system = platform.system()

    if system == "Windows":
        try:
            output = subprocess.check_output(
                'wevtutil qe Security /c:5 /rd:true /f:text',
                shell=True, text=True, errors='ignore'
            )
            if "Camera access" in output:
                sus_processes.append("Recent camera access detected in logs")
        except Exception as e:
            sus_processes.append(f"Error checking logs: {str(e)}")

    elif system in ["Linux", "Darwin"]:
        cam_keywords = ["ffmpeg", "obs", "zoom", "teams", "skype", "cheese", "v4l2"]
        for process in psutil.process_iter(attrs=['pid', 'name']):
            process_name = process.info['name'].lower()
            if any(keyword in process_name for keyword in cam_keywords):
                sus_processes.append(f"Camera usage: {process.info['name']} (PID {process.info['pid']})")
    
    return sus_processes

def check_mic_cam_usage():
    mic_alerts = check_mic_usage()
    cam_alerts = check_camera_usage()

    return json.dumps({
        "status": "success",
        "microphone_alerts": mic_alerts,
        "camera_alerts": cam_alerts
    }, indent=4)


if __name__ == "__main__":
    print(check_mic_cam_usage())