from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json
import hashlib
import os
import platform
import time
from pathlib import Path
import uuid
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"  # intentionally weak

def sanitize_input(user_input):
    """
    Basic input sanitization - filters common command injection characters
    BYPASSABLE: Can be bypassed using:
    - $(command) instead of backticks
    - Newline characters %0a
    - URL encoding
    - ${IFS} instead of spaces
    - Base64 encoding with eval
    """
    if not user_input:
        return user_input
    
    # Blacklist of dangerous characters
    blacklist = [';', '|', '&', '`', '$', '>', '<', '!', '\\']
    
    sanitized = user_input
    for char in blacklist:
        sanitized = sanitized.replace(char, '')
    
    return sanitized

def load_users():
    with open('users.json', 'r') as f:
        return json.load(f)['users']

def md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def authenticate(username, password):
    users = load_users()
    hashed_pw = md5(password)

    for user in users:
        if user['username'] == username and user['password'] == hashed_pw:
            return user
    return None

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump({"users": users}, f, indent=2)

def user_exists(username):
    users = load_users()
    return any(u['username'] == username for u in users)

def get_user_id(username):
    """Get user ID (index) by username"""
    users = load_users()
    for idx, user in enumerate(users):
        if user['username'] == username:
            return idx
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = authenticate(username, password)

        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            session['user_id'] = get_user_id(user['username'])

            return redirect(url_for('dashboard'))

        return redirect('/login')

    return render_template('login.html')

CACHE_DIR = Path("./cache")
CACHE_DIR.mkdir(exist_ok=True)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template(
        'dashboard.html',
        username=session['username'],
        role=session['role']
    )

# ==================== BAC VULNERABLE ENDPOINTS ====================

@app.route('/profile')
def profile():
    """
    Profile page - UI only shows own profile
    VULNERABLE: The backend still accepts user_id parameter without proper validation
    This can be exploited via Burp Suite by intercepting and modifying requests
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # UI always shows the logged-in user's own profile
    user_id = session.get('user_id')
    
    users = load_users()
    
    if user_id is None or user_id < 0 or user_id >= len(users):
        return "User not found", 404
    
    target_user = users[user_id]
    
    return render_template(
        'profile.html',
        user=target_user,
        user_id=user_id
    )

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    """
    Profile update endpoint
    VULNERABLE: user_id from form data is not validated against session
    VULNERABLE: role value is not restricted - backend accepts 'admin' even though UI only shows 'user'
    Exploit via Burp Suite: intercept POST request, change user_id and/or role to 'admin'
    """
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    # VULNERABILITY: user_id from form data, not validated against session
    user_id = request.form.get('user_id', type=int)
    new_role = request.form.get('role')
    new_username = request.form.get('new_username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if user_id is None:
        return jsonify({"error": "Missing user_id"}), 400
    
    users = load_users()
    
    if user_id < 0 or user_id >= len(users):
        return jsonify({"error": "User not found"}), 404
    
    target_user = users[user_id]
    changes_made = []
    
    # VULNERABILITY: No authorization check - any logged-in user can modify any profile
    # VULNERABILITY: Accepts 'admin' role even though UI only offers 'user'
    
    # Handle role change (BAC vulnerable)
    if new_role and new_role in ['user', 'admin']:
        if target_user['role'] != new_role:
            users[user_id]['role'] = new_role
            changes_made.append(f"role changed to {new_role}")
            
            # Update session if user modified their own profile
            if user_id == session.get('user_id'):
                session['role'] = new_role
    
    # Handle username change
    if new_username and new_username != target_user['username']:
        # Check if username already exists
        if any(u['username'] == new_username for u in users):
            return jsonify({"error": "Username already taken"}), 400
        
        users[user_id]['username'] = new_username
        changes_made.append("username updated")
        
        # Update session if user modified their own profile
        if user_id == session.get('user_id'):
            session['username'] = new_username
    
    # Handle password change
    if new_password:
        if not current_password:
            return jsonify({"error": "Current password is required"}), 400
        
        # Verify current password
        if md5(current_password) != target_user['password']:
            return jsonify({"error": "Current password is incorrect"}), 400
        
        if new_password != confirm_password:
            return jsonify({"error": "New passwords do not match"}), 400
        
        if len(new_password) < 4:
            return jsonify({"error": "Password must be at least 4 characters"}), 400
        
        users[user_id]['password'] = md5(new_password)
        changes_made.append("password updated")
    
    if changes_made:
        save_users(users)
        return jsonify({"success": True, "message": "Profile updated: " + ", ".join(changes_made)})
    
    return jsonify({"success": True, "message": "No changes made"})

# ==================== END BAC VULNERABLE ENDPOINT ====================

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        return "Access denied", 403

    users = load_users()
    return render_template('admin.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if session.get('role') != 'admin':
        return "Access denied", 403

    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    if not username or not password or not role:
        return "Missing fields"

    if user_exists(username):
        return "User already exists"

    users = load_users()
    users.append({
        "username": username,
        "password": md5(password),  # still intentionally weak
        "role": role
    })

    save_users(users)
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<username>')
def delete_user(username):
    if session.get('role') != 'admin':
        return "Access denied", 403

    users = load_users()
    users = [u for u in users if u['username'] != username]

    save_users(users)
    return redirect(url_for('admin'))

@app.route('/admin/system/diagnostics', methods=['GET', 'POST'])
def system_diagnostics():
    """Network diagnostic tools - ping, dns, traceroute"""
    if session.get('role') != 'admin':
        return "Access denied", 403

    output = None
    tool_name = None

    if request.method == 'POST':
        tool = request.form.get('tool')
        target = request.form.get('target')
        
        # Apply "sanitization" - can be bypassed!
        target = sanitize_input(target)

        # Command injection vulnerability in all tools
        if tool == 'ping':
            tool_name = "Ping Test"
            if platform.system().lower() == "windows":
                command = f"ping -n 2 {target}"
            else:
                command = f"ping -c 2 {target}"
        elif tool == 'dns':
            tool_name = "DNS Lookup"
            command = f"nslookup {target}"
        elif tool == 'traceroute':
            tool_name = "Traceroute"
            if platform.system().lower() == "windows":
                command = f"tracert {target}"
            else:
                command = f"traceroute {target}"
        else:
            return "Invalid tool", 400

        output = os.popen(command).read()

        # Log the command
        timestamp = datetime.utcnow().isoformat()
        cache_file = CACHE_DIR / f"diag_{int(time.time())}.log"
        with open(cache_file, "w") as f:
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"User: {session.get('username')}\n")
            f.write(f"Tool: {tool_name}\n")
            f.write(f"Command: {command}\n")
            f.write("Output:\n")
            f.write(output)

    return render_template('diagnostics.html', output=output, tool_name=tool_name)


@app.route('/admin/system/logs', methods=['GET'])
def system_logs():
    """
    Log viewer - COMMAND INJECTION via filename and filter parameters
    This is a more realistic vulnerability hidden in a log viewer feature
    Sanitization applied but can be bypassed!
    """
    if session.get('role') != 'admin':
        return "Access denied", 403

    output = None
    error = None
    current_file = request.args.get('file', '')
    lines = request.args.get('lines', 50, type=int)
    filter_text = request.args.get('filter', '')
    
    # Apply "sanitization" - can be bypassed!
    current_file = sanitize_input(current_file)
    filter_text = sanitize_input(filter_text)

    if current_file:
        # VULNERABILITY: Still exploitable via bypass techniques
        # - Newline injection: %0a
        # - Using quotes to break out
        
        if filter_text:
            # Vulnerable: grep filter can be exploited
            command = f"tail -n {lines} {current_file} 2>&1 | grep '{filter_text}'"
        else:
            command = f"tail -n {lines} {current_file} 2>&1"
        
        try:
            output = os.popen(command).read()
            if not output:
                output = "(No output or empty file)"
        except Exception as e:
            error = str(e)

    return render_template('logs.html', 
                          output=output, 
                          error=error,
                          current_file=current_file,
                          lines=lines,
                          filter=filter_text)


@app.route('/admin/system/backup', methods=['GET', 'POST'])
def system_backup():
    """
    Backup manager - COMMAND INJECTION via backup_name and source_path
    Sanitization applied but can be bypassed!
    """
    if session.get('role') != 'admin':
        return "Access denied", 403

    output = None
    message = None
    backups = []
    backup_dir = Path("./backups")
    backup_dir.mkdir(exist_ok=True)

    # List existing backups
    for f in backup_dir.glob("*.tar.gz"):
        stat = f.stat()
        backups.append({
            "name": f.name,
            "size": f"{stat.st_size // 1024} KB",
            "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        })

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create':
            backup_name = request.form.get('backup_name')
            source_path = request.form.get('source_path', '.')
            
            # Apply "sanitization" - can be bypassed!
            backup_name = sanitize_input(backup_name)
            source_path = sanitize_input(source_path)
            
            # VULNERABILITY: Still exploitable via bypass techniques
            command = f"tar -czf ./backups/{backup_name}.tar.gz {source_path} 2>&1"
            output = os.popen(command).read()
            message = f"Backup '{backup_name}.tar.gz' created successfully"

        elif action == 'delete':
            filename = request.form.get('filename')
            # Apply "sanitization" - can be bypassed!
            filename = sanitize_input(filename)
            command = f"rm -f ./backups/{filename} 2>&1"
            os.popen(command).read()
            message = f"Backup '{filename}' deleted"
            return redirect(url_for('system_backup'))

    return render_template('backup.html', 
                          backups=backups, 
                          output=output,
                          message=message)


@app.route('/admin/system/services', methods=['GET', 'POST'])
def system_services():
    """
    Service manager - shows service status and allows control
    COMMAND INJECTION via service name parameter
    Sanitization applied but can be bypassed!
    """
    if session.get('role') != 'admin':
        return "Access denied", 403

    output = None
    message = None
    
    # Mock service list (in real scenario, would parse systemctl output)
    services = [
        {"name": "nginx", "status": "running", "pid": "1234", "uptime": "2d 5h"},
        {"name": "mysql", "status": "running", "pid": "1235", "uptime": "2d 5h"},
        {"name": "ssh", "status": "running", "pid": "892", "uptime": "2d 5h"},
        {"name": "redis", "status": "stopped", "pid": None, "uptime": None},
        {"name": "webapp", "status": "running", "pid": "4521", "uptime": "1d 2h"},
    ]

    if request.method == 'POST':
        service = request.form.get('service')
        action = request.form.get('action')
        
        # Apply "sanitization" - can be bypassed!
        service = sanitize_input(service)

        if service and action:
            # VULNERABILITY: Still exploitable via bypass techniques
            if action == 'status':
                command = f"systemctl status {service} 2>&1"
            elif action in ['start', 'stop', 'restart']:
                command = f"systemctl {action} {service} 2>&1"
            else:
                return "Invalid action", 400
            
            output = os.popen(command).read()
            if not output:
                output = f"Command executed: systemctl {action} {service}"

    return render_template('services.html', 
                          services=services, 
                          output=output,
                          message=message)


# Keep old route for backwards compatibility
@app.route('/admin/system', methods=['GET', 'POST'])
def system_utility():
    """Legacy system utility - redirects to new diagnostics page"""
    return redirect(url_for('system_diagnostics'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8888)
