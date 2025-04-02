import re

def check_password_strength(password):
    if len(password) < 8:
        return "Weak : Too short"
    if not re.search(r"[A-Z]", password):
        return "Weak : Add an uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Weak : Ass a lowercase letter"
    if not re.search(r"\d", password):
        return "Weak : Add a number"
    if not re.search(r"[!@#$%^&*()_\-+=]", password):
        return "Weak : Add a special character"
    
    return "Strong"

if __name__ == "__main__":
    password = input("Enter password to check: ")
    print(check_password_strength(password))