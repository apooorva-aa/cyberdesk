import os

def check_browser_privacy():
    privacy_issues = []

    chrome_history = os.path.expanduser("~/.config/google-chrome/Default/History")
    chrome_cookies = os.path.expanduser("~/.config/google-chrome/Default/Cookies")

    firefox_profile = os.path.expanduser("~/.mozilla/firefox")

    if os.path.exists(chrome_history):
        privacy_issues.append("Chrome history detected")

    if os.path.exists(chrome_cookies):
        privacy_issues.append("Chrome cookies detected")

    if os.path.exists(firefox_profile):
        privacy_issues.append("Firefox profile detected")

    return {"privacy_warnings": privacy_issues}