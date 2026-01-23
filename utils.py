"""
Utility functions with security vulnerabilities
"""

import hashlib
import random
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Vulnerability: Weak cryptographic hash
def hash_password(password):
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability: Predictable random number generation
def generate_token():
    # VULNERABLE: random module not suitable for security
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])

# Vulnerability: Insecure SSL verification
def fetch_data(url):
    # VULNERABLE: SSL verification disabled
    response = requests.get(url, verify=False)
    return response.text

# Vulnerability: Weak encryption
def encrypt_data(data, key):
    # VULNERABLE: ECB mode is insecure
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Vulnerability: XML External Entity (XXE)
def parse_xml(xml_string):
    import xml.etree.ElementTree as ET
    # VULNERABLE: No protection against XXE
    root = ET.fromstring(xml_string)
    return root

# Vulnerability: Unvalidated redirects
def redirect_user(url):
    # VULNERABLE: Open redirect
    return f"Redirecting to: {url}"

# Vulnerability: Information disclosure
def get_error_details(error):
    # VULNERABLE: Exposing stack traces
    import traceback
    return {
        "error": str(error),
        "traceback": traceback.format_exc(),
        "locals": str(locals())
    }
