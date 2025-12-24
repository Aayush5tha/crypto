# app.py
"""Vulnerable PKI tool for security demo."""
# app.py
import pickle
import subprocess
import hashlib
PASSWORD = "12345" # Hardcoded secret
def dangerous_eval(user_input):
return eval(user_input) # RCE risk
def load_data(data):

return pickle.loads(data) # RCE risk
def clean_cache():
subprocess.call("rm -rf /tmp", shell=True)
# Command injection
def weak_hash(data):
return hashlib.md5(data.encode()).
hexdigest() # Broken crypto
if __name__ == "__main__":
print("PKI Tool Running...")
