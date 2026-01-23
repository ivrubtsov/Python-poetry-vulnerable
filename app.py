"""
Vulnerable Flask Application for Testing
This application intentionally contains security vulnerabilities for testing purposes.
DO NOT use in production!
"""

from flask import Flask, request, render_template_string
import yaml
import pickle
import os
import subprocess

app = Flask(__name__)

# Vulnerability 1: SQL Injection (using raw string formatting)
@app.route('/user/<username>')
def get_user(username):
    # VULNERABLE: SQL injection possible
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return {"query": query, "warning": "SQL Injection vulnerability"}

# Vulnerability 2: YAML deserialization (arbitrary code execution)
@app.route('/config', methods=['POST'])
def load_config():
    # VULNERABLE: Arbitrary code execution via YAML
    config_data = request.data
    config = yaml.load(config_data, Loader=yaml.Loader)  # Unsafe!
    return {"config": str(config)}

# Vulnerability 3: Server-Side Template Injection (SSTI)
@app.route('/greet')
def greet():
    # VULNERABLE: Template injection
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Vulnerability 4: Command Injection
@app.route('/ping')
def ping():
    # VULNERABLE: Command injection
    host = request.args.get('host', 'localhost')
    result = os.system(f'ping -c 1 {host}')
    return {"result": result}

# Vulnerability 5: Insecure Deserialization
@app.route('/load', methods=['POST'])
def load_data():
    # VULNERABLE: Pickle deserialization
    data = request.data
    obj = pickle.loads(data)
    return {"loaded": str(obj)}

# Vulnerability 6: Path Traversal
@app.route('/read')
def read_file():
    # VULNERABLE: Path traversal
    filename = request.args.get('file', 'default.txt')
    with open(f'/tmp/{filename}', 'r') as f:
        content = f.read()
    return {"content": content}

# Vulnerability 7: Hardcoded Secrets
SECRET_KEY = "hardcoded-secret-key-12345"
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

# Vulnerability 8: Debug mode enabled
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # VULNERABLE: Debug mode in production
