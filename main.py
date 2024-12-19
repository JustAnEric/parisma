"""

Parisma Router program.
Initialization expected on boot.

"""

from base64 import b16decode, b16encode
from settings import settings
from socket import socket
from hbdns import main
from flask import render_template, redirect, request, session
from werkzeug.routing import Rule
from datetime import datetime, timezone
from getpass import getpass
import os, flask, threading, ssl, subprocess, platform, getmac, time, uuid, json, bcrypt, smtplib

sessions = []
cportal_sessions = []

def configure_hostapd(setting, value):
    command = ["sudo", "hostapd_cli", "set", f"{setting}", f"{value}"]
    result = subprocess.run(command, shell=True, text=True, capture_output=True)

    if result.returncode == 0:
        print(f"successfully set hostapd {setting} to {value}")
    else:
        print(f"error setting {setting} to {value}: {result.stderr}")
        
def restart_hostapd():
    # Restart hostapd service to apply the changes
    result = subprocess.run(["sudo", "systemctl", "restart", "hostapd"], text=True, capture_output=True)
    
    if result.returncode == 0:
        print("hostapd successfully restarted!")
    else:
        print(f"error restarting hostapd: {result.stderr}")
        
def get_hostapd_value(setting):
    command = ["sudo", "hostapd_cli", "get", f"{setting}"]
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    
    if result.returncode == 0:
        return result.stdout.strip()  # Return the value
    else:
        print(f"error getting {setting}: {result.stderr}")
        return None
    
def get_active_connections():
    # Run the hostapd_cli command to get information about all connected stations
    command = ["sudo", "hostapd_cli", "all_sta"]
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    
    if result.returncode == 0:
        # Split the output into lines and count the number of connected devices
        connections = result.stdout.strip().splitlines()
        # Each line corresponds to one connected station, so the length is the number of connections
        return len(connections)
    else:
        print(f"error getting active connections: {result.stderr}")
        return 0
    
def get_connected_clients_info():
    # Run the hostapd_cli command to get information about all connected stations
    command = ["sudo", "hostapd_cli", "all_sta"]
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    
    if result.returncode == 0:
        # Split the output into lines
        client_info = result.stdout.strip().splitlines()
        
        clients = []
        for client in client_info:
            # Each line contains a station's info, like MAC address and more.
            if client.startswith("STA"):
                mac_address = client.split()[1]  # Extracting the MAC address from the line
                ip_addresses = main.STATS['clients_mac_address']
                ip_address = None
                
                for ip in ip_addresses:
                    if ip_addresses[ip].lower() == mac_address.lower():
                        ip_address = ip
                        break
                
                if not ip_address:
                    print(f"computer {mac_address} has not communicated with the DNS")
                    clients.append({'mac': mac_address, 'ip': "0.0.0.0"})
                else:
                    # Now, append the IP address and other information to the list
                    clients.append({'mac': mac_address, 'ip': ip_address})
        
        return clients
    else:
        print(f"Error getting active connections: {result.stderr}")
        return []
    
def deauth_client(mac_address, interface="wlan0"):
    """Send a deauthentication packet to the client."""
    try:
        command = ["sudo", "iw", "dev", f"{interface}", "station", "del", f"{mac_address}"]
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        
        if result.returncode == 0:
            print(f"Deauthentication packet sent to {mac_address}.")
        else:
            print(f"Failed to send deauthentication packet to {mac_address}: {result.stderr}")
    except Exception as e:
        print(f"Error sending deauthentication packet: {e}")

#c = settings()
#c.load_to_env()

def setup():
    print("----------------------------------------------------------------")
    print("PARISMA ROUTER CONFIGURATION | START")
    a = input("Do you want to configure the router now? [Y/n] ")
    setup_allowed = False
    
    if a.lower().strip() == "y" or a.lower().strip() == "":
        print("Entering setup mode...")
        setup_allowed = True
    else: 
        print("Exiting setup mode...")
        setup_allowed = False
    print("----------------------------------------------------------------")
    
    if not setup_allowed:
        return "NOT_ALLOWED"
    
    print("INPUT::setup.ROUTER NAME")
    router_name = input("Enter your router name: ").strip()
    main.BUFFERS['ROUTER_NAME'] = router_name
    print("INPUT::setup.ADMIN PASSWORD")
    admin_password = getpass("Enter your admin password: ")
    main.BUFFERS['ADMIN_PASSWORD'] = admin_password
    print("INPUT::setup.WIFI SSID")
    ssid = input("Enter your Wi-Fi SSID: ")
    main.BUFFERS['SSID'] = ssid
    print("INPUT::setup.WIFI PASSWORD")
    wifi_password = getpass("Enter your Wi-Fi password: ")
    main.BUFFERS['PASSWORD'] = wifi_password
    
    print("SETUP FINISH")
    print("SETUP WRITE")
    with open('./settings.json', 'w') as fp:
        json.dump(main.BUFFERS, fp, indent=4)
    print("SETUP FINAL")
    print("SETUP DONE")
    print("----------------------------------------------------------------")
    return "ALLOWED"

def startup():
    if main.BUFFERS.get('ROUTER_NAME', None) == None:
        # Go through Setup
        print('startup()- starting setup')
        setup()
    
    if platform.system().lower() == "linux":
        print('startup()- starting iptables rules')
        
        try:
            r = subprocess.Popen(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    "OUTPUT",
                    "-d",
                    "1.1.1.1",
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
            )
            stdout, stderr = r.communicate(timeout=10)
            if r.returncode == 0:
                print('startup()- rule 1 provisioned')
            else:
                print(f'Error in rule 1: {stderr.decode()}')
            
            r = subprocess.Popen(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-d",
                    "1.1.1.1",
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "REJECT"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
            )
            stdout, stderr = r.communicate(timeout=10)
            if r.returncode == 0:
                print('startup()- rule 2 provisioned')
            else:
                print(f'Error in rule 2: {stderr.decode()}')
            r = subprocess.Popen(
                [
                    "sudo", 
                    "iptables", 
                    "-A", 
                    "FORWARD", 
                    "-p", 
                    "udp", 
                    "--dport", 
                    "53", 
                    "-j", 
                    "REJECT"
                ], 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
            )
            
            stdout, stderr = r.communicate(timeout=10)
            if r.returncode == 0:
                print('startup()- rule 3 provisioned')
            else:
                print(f'Error in rule 3: {stderr.decode()}')
            
            r = subprocess.Popen(
                [
                    "sudo", 
                    "iptables", 
                    "-A", 
                    "FORWARD", 
                    "-s", 
                    "192.168.4.0/24", 
                    "-d", 
                    "192.168.4.1", 
                    "-p", 
                    "udp", 
                    "--dport", 
                    "53", 
                    "-j", 
                    "ACCEPT"
                ], 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
            )
            stdout, stderr = r.communicate(timeout=10)
            if r.returncode == 0:
                print('startup()- rule 4 provisioned')
            else:
                print(f'Error in rule 4: {stderr.decode()}')
            
            print('server successfully configured rules')
        except subprocess.TimeoutExpired:
            print("startup()- Error: Timeout while executing iptables command")
        except Exception as e:
            print(f"startup()- Error: {str(e)}")
    else:
        print("startup()- can't execute preconfig, not on linux")

def safe_check():
    """Perform a safety check on the network."""
    # track known mac-ip bindings
    mac_ip_mapping = {}  # mac: ip
    
    if not platform.system().lower() == "linux":
        return "Not on Linux"

    while True:
        connected_clients = get_connected_clients_info()
        checked_mac_addresses = []
        kicked_from_network = []

        for client in connected_clients:
            mac = client['mac'].lower()
            ip = client['ip']

            # detect mac address duplication
            if mac in checked_mac_addresses:
                print(f"duplicate mac detected: {mac}")
                deauth_client(mac)
                kicked_from_network.append({'mac_address': mac, 'ip_address': ip})
                continue

            # detect mac-ip spoofing
            if mac in mac_ip_mapping and mac_ip_mapping[mac] != ip:
                print(f"mac-ip mismatch detected: {mac} -> {ip}")
                deauth_client(mac)
                kicked_from_network.append({'mac_address': mac, 'ip_address': ip})
                continue

            # update mapping and mark mac as checked
            mac_ip_mapping[mac] = ip
            checked_mac_addresses.append(mac)

        print(f'clients: {checked_mac_addresses}')
        print(f'kicked: {kicked_from_network}')

        time.sleep(10)  # wait before checking again

startup()

threading.Thread(target=main.run_dns_server, daemon=True).start()
threading.Thread(target=main.check_and_switch_dns, daemon=True).start()
threading.Thread(target=safe_check, daemon=True).start()

print('started hostbase router')

server = flask.Flask('hostbaserouter')
server.secret_key = b'secret key'

@server.endpoint('/p')
def blocked(path):
    # https://github.com/NickSto/uptest/blob/master/captive-portals.md
    
    if path == "generate_204" and (request.host == "gstatic.com" or request.host == "www.gstatic.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    if path == "generate_204" and (request.host == "google.com" or request.host == "www.google.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    if path == "generate_204" and (request.host == "clients3.google.com" or request.host == "www.clients3.google.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    if path == "generate_204" and (request.host == "connectivitycheck.android.com" or request.host == "www.connectivitycheck.android.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    if path == "generate_204" and (request.host == "connectivitycheck.gstatic.com" or request.host == "www.connectivitycheck.gstatic.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    
    if path == "success.txt" and (request.host == "detectportal.firefox.com" or request.host == "www.detectportal.firefox.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    
    if path == "ncsi.txt" and (request.host == "msftncsi.com" or request.host == "www.msftncsi.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    
    if path == "library/test/success.html" and (request.host == "apple.com" or request.host == "www.apple.com"):
        return redirect('https://fw.hbn.rf.gd/login')
    
    if path == "connecttest.txt":
        return redirect('http://fw.hbn.rf.gd/login')
    if request.host == "www.msftconnecttest.com" or request.host == "msftconnecttest.com" or request.host == "www.msftconnecttest.com:80" or request.host == "msftconnecttest.com:80" or request.host == "www.msftconnecttest.com:443" or request.host == "msftconnecttest.com:443":
        return redirect('http://fw.hbn.rf.gd/login')
    
    if not request.host.startswith('localhost') and not request.host.startswith('127.0.0.1') and not request.host.startswith('router.local') and not request.host.startswith('www.router.local') and not request.host.startswith('fw.hbn.rf.gd') and not request.host.startswith('www.fw.hbn.rf.gd'):
        return "This website is blocked by HostBase DNS. <a href='/fwb'>More info</a>"
    return "404 Not Found"

@server.endpoint('/')
def home():
    if not request.host.startswith('localhost') and not request.host.startswith('127.0.0.1') and not request.host.startswith('router.local') and not request.host.startswith('www.router.local') and not request.host.startswith('fw.hbn.rf.gd') and not request.host.startswith('www.fw.hbn.rf.gd'):
        return "This website is blocked by HostBase DNS. <a href='/fwb'>More info</a>"
    elif request.host.startswith('router.local') or request.host.startswith('www.router.local'):
        return redirect('/router')
    elif request.host.startswith('fw.hbn.rf.gd') or request.host.startswith('www.fw.hbn.rf.gd'):
        return redirect('/fw')
    else: return redirect('/dns')
    
server.url_map.add(Rule('/', endpoint="/"))
server.url_map.add(Rule('/<path:path>', endpoint="/p"))

@server.route('/fw')
def hbfw():
    resp = "✋❌ HostBase Firewall V1"
    
    if main.BUFFERS.get("CAPTIVE_PORTAL_ENABLED", False) == True:
        resp += "<br>Captive Portal is enabled"
        
        global mac
        mac = None
        if request.remote_addr in main.STATS['clients_mac_address']:
            mac = main.STATS['clients_mac_address'][request.remote_addr]
        
        for user in main.BUFFERS.get("CAPTIVE_PORTAL_USERS", []):
            if user.get("mac_assigned", None) == mac:
                resp += f"<br>User: {user['name']} ({user['mac_assigned']})"
    
    return resp

@server.route('/fwb')
def hbfwblock():
    url = request.args.get('url',request.host)
    mac = request.args.get('mac',request.remote_addr)
    email_message = f"Hello. Please review the information of a violation of the firewall. \nThe website that was blocked was: {url}\nThe MAC address that was blocked was: {mac}\n\nOnce again, please double-check that this person is supposed to be on the network. You can manage users on the network via your <a href='https://router.local/'>router page</a>.\n[{datetime.now()}]"
    
    # IMPLEMENT A SEND_EMAIL FUNCTION YOURSELF.
    # main.send_email("admin@server.com", "Blocked Website Accessed", email_message.replace('\n','<br/>'))
    
    if "://" in url:
        if url.split("://",1)[1].split("/",1)[0] == "block.test":
            return render_template('fw/blocked.html', reason = f"Block test.", mac_address = mac)
        else:
            return render_template('fw/blocked.html', reason = f"❌Stop! This website ({url.split('://',1)[1].split('/')[0] if len(url.split('://',1)[1].split('/')) > 0 else url.split('://',1)[1]}) was blocked by the firewall because it was in predefined rules. This violation has been stored in logs and reported to the administrator.", mac_address = mac)
    else:
        return "Invalid FW URL"

@server.route('/dns')
def dns():
    if not request.host.startswith('router.local') and not request.host.startswith('www.router.local') and not request.host.startswith('localhost'):
        return redirect('/')
    return render_template('dns.html', dns={'latency': main.STATS['latency'], 'total_reqs': main.STATS['total_requests'], 'server': main.STATS['selected_dns'], 'bytes_transferred': main.STATS['bytes_transferred'], 'clients_contacted': list(main.STATS['clients'])})

@server.route('/router')
def router():
    if not request.host.startswith('router.local') and not request.host.startswith('www.router.local'):
        return redirect('/')
    return redirect('/router/home')

@server.route('/router/<page>')
def router_page(page):
    if not request.host.startswith('router.local') and not request.host.startswith('www.router.local') and not request.host.startswith('fw.hbn.rf.gd') and not request.host.startswith('www.fw.hbn.rf.gd'):
        return redirect('/')
    
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return redirect('/router/login')
    
    if page.lower() == 'home':
        return render_template('router/home.html')
    elif page.lower() == 'devices':
        return render_template('router/devices.html', devices = main.STATS['clients_mac_address'])
    elif page.lower() == 'network':
        return render_template('router/network.html')
    elif page.lower() == 'statistics':
        return render_template('router/statistics.html', latencies = main.STATS['latest_dns_latencies'])
    elif page.lower() == 'settings':
        return render_template('router/settings.html', data = main.BUFFERS)
    elif page.lower() == 'content-blocking':
        return render_template('router/content-blocking.html', blocks = main.BLOCKED_WEBSITES)
    elif page.lower() == 'captive-portal':
        return render_template('router/captive-portal.html', captive_portal_enabled = main.BUFFERS.get('CAPTIVE_PORTAL_ENABLED', False), captive_portal_users = main.BUFFERS.get('CAPTIVE_PORTAL_USERS', []))
    else:
        return "Page not found"
    
@server.route('/router/login/finish', methods=['POST'])
def login_finish():
    username = request.form['username']
    password = request.form['password']
    
    if username == 'admin' and password == 'password':
        sid = str(uuid.uuid4())
        session["TOKEN"] = sid
        sessions.append(sid)
        return redirect('/router')
    else:
        return "Invalid username or password"
    
@server.route('/router/login')
def login():
    if "TOKEN" in session and session.get("TOKEN") in sessions:
        return redirect('/router')
    return render_template('login.html')

@server.route('/router/api/save_settings/<page>/<section>', methods=['POST'])
def save_settings(page, section):
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return {'error': 'Authorization Required'}
    
    changes = json.loads(request.headers.get("SETTINGS","[]"))
    
    if len(changes) == 0:
        return {'error': 'No changes provided'}
    
    if page == 'settings':
        POSSIBLE_IDS = []
        if section == "1":
            POSSIBLE_IDS = ["ROUTER_NAME", "ADMIN_PASSWORD"]
        elif section == "2":
            POSSIBLE_IDS = ["SSID", "SECURITY", "PASSWORD"]
        elif section == "3":
            POSSIBLE_IDS = ["LAN_IP_ADDRESS", "DHCP_RANGE_1", "DHCP_RANGE_2"]
        
        if len(POSSIBLE_IDS) == 0:
            return {'error': 'Invalid section'}

    else:
        return {'error': 'Invalid page'}
        
    for change in changes:
        if not change['type'] in POSSIBLE_IDS:
            return {'error': 'Invalid setting/change type'}
    
    # commit changes
    with open('./settings.json', 'w') as fp:
        for change in changes:
            main.BUFFERS[change['type']] = change['value']
        
        json.dump(main.BUFFERS, fp, indent=4)
    
    # return success message
    return {'status': 'success', 'message': 'Changes saved successfully'}

@server.route('/router/api/buffers/<id>/<method>', methods=['GET', 'POST'])
def get_buffers(id, method):
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return {'error': 'Authorization Required'}
    
    if id.lower() == "content_blocks":
        if method == "get":
            return {'buffers': main.BUFFERS.get(id.upper(),{})}
        elif method == "add":
            buffer = request.headers.get('buffer',None)
            if not buffer:
                return {'error': 'No buffer selection specified'}
            
            b = json.loads(buffer)
            b['ID'] = str(uuid.uuid4())
            
            if main.BUFFERS.get(id.upper(),None) == None:
                main.BUFFERS[id.upper()] = []
            
            main.BUFFERS[id.upper()].append(b)
            # write
            with open('./settings.json', 'w') as fp:
                json.dump(main.BUFFERS, fp, indent=4)
                
            main.parse_new_blocked_websites_from_buffers()
            
            return {'opcode': 'BUFFERS:/action/success','status': 'Buffer updated successfully','buffer': main.BUFFERS[id.upper()], 'id': b['ID']}
        elif method == "remove":
            buffer = request.headers.get('buffer-id',None)
            if not buffer:
                return {'error': 'No buffer selection specified'}
            
            if main.BUFFERS.get(id.upper(),None) == None:
                return {'error': 'No buffer'}
            
            for index,buf in enumerate(main.BUFFERS[id.upper()]):
                if buf['ID'] == buffer:
                    main.BUFFERS[id.upper()].pop(index)
                    break
            
            # write
            with open('./settings.json', 'w') as fp:
                json.dump(main.BUFFERS, fp, indent=4)
                
            main.parse_new_blocked_websites_from_buffers()
            
            return {'opcode': 'BUFFERS:/action/success','status': 'Buffer updated successfully','buffer': main.BUFFERS[id.upper()]}
        else:
            return {'error': 'Invalid method'}
        
def Convertable(to_object, from_object):
    if isinstance(from_object, to_object):
        return True
    else:
        try:
            to_object(from_object)
            return True
        except ValueError:
            return False
        
@server.route('/router/api/captive-portal/users')
def captive_portal_users():
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return {'error': 'Authorization Required'}
    
    filter = request.headers.get('filter', None)
    max = request.headers.get('max', None)
    requesting_passwords = request.headers.get('Passwords-Needed', True)
    
    filter_queries = ['username=','password=','mac_used=','mac_is_using=','status=']
    
    users = []
    
    if filter:
        pass
    
    else:
        for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
            if max is not None and Convertable(int, max):
                if len(users) >= int(max):
                    break
            
            users.append({
                'name': user.get('name', 'NOUSERNAME'),
                'password': user.get('password', 'NOPASSWORD') if requesting_passwords == True else None,
                'mac_history': user.get('mac_history', []),
                'mac_assigned': user.get('mac_assigned','NOMACASSIGN'),
                'status': user.get('status','NOSTATUS'),
                'ID': user.get('ID','NOID_CRITICALERROR')
            })

    return users, 200

@server.route('/router/api/captive-portal/user/delete', methods=['POST'])
def delete_captive_portal_user():
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return {'error': 'Authorization Required'}
        
    id = request.headers.get('Id', None)
    
    if id is None or Convertable(str, id) is False:
        return {'error': 'No user ID specified'}
    
    for index, user in enumerate(main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[])):
        if user['ID'] == id:
            main.BUFFERS['CAPTIVE_PORTAL_USERS'].pop(index)
            break
        
    with open('./settings.json', 'w') as fp:
        json.dump(main.BUFFERS, fp, indent=4)
    
    return {'opcode': 'CAPTIVE_PORTAL_USERS:/action/success','status': 'User deleted successfully'}

@server.route('/router/api/captive-portal/user/add', methods=['POST'])
def add_captive_portal_user():
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return {'error': 'Authorization Required'}
        
    username = request.headers.get('Name', None)
    password = request.headers.get('Password', None)
    
    if id is None or Convertable(str, id) is False:
        return {'error': 'No user ID specified'}
    
    if not username or not password:
        return {'error': 'No username and password specified'}
    
    for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
        if user['name'].lower() == username.lower():
            return {'error': 'Username already exists'}
    
    id = str(uuid.uuid4())
    
    if main.BUFFERS.get('CAPTIVE_PORTAL_USERS', None) == None:
        main.BUFFERS['CAPTIVE_PORTAL_USERS'] = []
    
    main.BUFFERS['CAPTIVE_PORTAL_USERS'].append({
        'name': str(username),
        'password': str(password),
        'mac_history': [],
        'mac_assigned': None,
        'status': True,
        'ID': id
    })
    
    with open('./settings.json', 'w') as fp:
        json.dump(main.BUFFERS, fp, indent=4)
    
    return {'opcode': 'CAPTIVE_PORTAL_USERS:/action/success','status': 'User added successfully','id': id}

@server.route('/router/api/captive-portal/user/banks/mac_history/delete', methods=['POST'])
def update_captive_portal_user():
    if not "TOKEN" in session or not session.get("TOKEN") in sessions:
        return {'error': 'Authorization Required'}
        
    id = request.headers.get('Id', None)
    
    if id is None or Convertable(str, id) is False:
        return {'error': 'No user ID specified'}
    
    for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
        if user['ID'] == id:
            user['mac_history'] = []
            break
        
    with open('./settings.json', 'w') as fp:
        json.dump(main.BUFFERS, fp, indent=4)
    
    return {'opcode': 'CAPTIVE_PORTAL_USERS:/action/success','status': 'User MAC history deleted successfully','id': id}
    
@server.route('/login')
def loginpage():
    if not main.BUFFERS.get('CAPTIVE_PORTAL_ENABLED', False):
        return "ERROR: Captive portal is not enabled."
    
    if not request.remote_addr in main.STATS['clients_mac_address']:
        return "ERROR: No MAC address found. Are you connected to the DNS?<br>If you are receiving this message unexpectedly, please retry."
    
    mac = main.STATS['clients_mac_address'].get(request.remote_addr, None)
    
    for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
        if user['mac_assigned'] == mac:
            print(f"user '{user['name']}' is already assigned to this MAC address")
            return "ERROR: You are already logged in with the same identifier."
    
    # if they get past all the checks, then you can show the authentication screen
    return render_template('cportal-login.html', redirect_uri = "/login/finish" if main.BUFFERS.get('CAPTIVE_PORTAL_REQUIRES_AGREEMENT', False) == False else "/login/agreement")

@server.route('/login/agreement', methods=['POST'])
def loginagreement():
    if not main.BUFFERS.get('CAPTIVE_PORTAL_ENABLED', False):
        return "ERROR: Captive portal is not enabled."
    
    if not request.remote_addr in main.STATS['clients_mac_address']:
        return "ERROR: No MAC address found. Are you connected to the DNS?<br>If you are receiving this message unexpectedly, please retry."
    
    mac = main.STATS['clients_mac_address'].get(request.remote_addr, None)
    
    for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
        if user['mac_assigned'] == mac:
            print(f"user '{user['name']}' is already assigned to this MAC address")
            return "ERROR: You are already logged in with the same identifier."
    
    username = request.form['username']
    password = request.form['password']
    
    user_exists = False
    login_correct = False
    user = None
    
    for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
        if user['name'] == username.lower():
            user_exists = True
            if user['password'] == password:
                login_correct = True
                user = user
                break
            break
    
    if user_exists and login_correct and user:
        # associate the user with their MAC address
        
        if not mac in user['mac_history']:
            if len(user['mac_history']) > 0:
                if main.BUFFERS['CAPTIVE_PORTAL_MODE'].lower() == 'strict':
                    return "ERROR: Logging in from an unknown device. Please contact your network administrator."
                
        # register the user's details
        id = str(uuid.uuid4())
        session['CPORTAL_SESS_ID'] = id
        cportal_sessions.append({ 'id': id, 'username': username, 'password': password })
        
        #return "You have successfully logged into the captive portal. Welcome to the internet."
        return render_template('cportal-agreement.html', tos_content = main.BUFFERS.get('CAPTIVE_PORTAL_NETWORK_AGREEMENT'))
    else:
        return "Invalid username or password. <a href='/login'>Click me to login again</a>."

@server.route('/login/finish', methods=['POST'])
def loginfinish():
    if not main.BUFFERS.get('CAPTIVE_PORTAL_ENABLED', False):
        return "ERROR: Captive portal is not enabled."
    
    if not request.remote_addr in main.STATS['clients_mac_address']:
        return "ERROR: No MAC address found. Are you connected to the DNS?<br>If you are receiving this message unexpectedly, please retry."
    
    mac = main.STATS['clients_mac_address'].get(request.remote_addr, None)
    
    for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
        if user['mac_assigned'] == mac:
            print(f"user '{user['name']}' is already assigned to this MAC address")
            return "ERROR: You are already logged in with the same identifier."
    
    if not main.BUFFERS.get('CAPTIVE_PORTAL_REQUIRES_AGREEMENT', False):
        username = request.form.get('username','')
        password = request.form.get('password','')
        
        user_exists = False
        login_correct = False
        user = None
        
        for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
            if user['name'] == username.lower():
                user_exists = True
                if user['password'] == password:
                    login_correct = True
                    user = user
                    break
                break
        
        if user_exists and login_correct and user:
            # associate the user with their MAC address
            
            if not mac in user['mac_history']:
                if len(user['mac_history']) > 0:
                    if main.BUFFERS['CAPTIVE_PORTAL_MODE'].lower() == 'strict':
                        return "ERROR: Logging in from an unknown device. Please contact your network administrator."
                    
                user['mac_history'].append(mac)
                user['mac_assigned'] = mac
            
            with open('./settings.json', 'w') as fp:
                json.dump(main.BUFFERS, fp, indent=4)
            
            return "You have successfully logged into the captive portal. Welcome to the internet."
        
        else:
            return "Invalid username or password. <a href='/login'>Click me to login again</a>."
    
    else:
        # requires an agreement and a login session from the agreement page
        agreed = request.form['agreed']
        if not agreed:
            return "You must agree to the terms and conditions to continue logging in and to have access to the internet."
        
        username = None
        password = None
        
        # check if the session exists
        if not 'CPORTAL_SESS_ID' in session:
            return "ERROR: No login session found. Please try again here: <a href='/login'>Retry</a>"
        else:
            for sess in cportal_sessions:
                if session['CPORTAL_SESS_ID'] == sess['id']:
                    username = sess['username']
                    password = sess['password']
                    break
                
            if not username or not password:
                return "ERROR: Login session corrupted. Please try again here: <a href='/login'>Retry</a>"
        
        user_exists = False
        login_correct = False
        user = None
        
        for user in main.BUFFERS.get('CAPTIVE_PORTAL_USERS',[]):
            if user['name'] == username.lower():
                user_exists = True
                if user['password'] == password:
                    login_correct = True
                    user = user
                    break
                break
        
        if user_exists and login_correct and user:
            # associate the user with their MAC address
            
            if not mac in user['mac_history']:
                if len(user['mac_history']) > 0:
                    if main.BUFFERS.get('CAPTIVE_PORTAL_MODE','Standard').lower() == 'strict':
                        return "ERROR: Logging in from an unknown device. Please contact your network administrator."
                    
                user['mac_history'].append(mac)
                user['mac_assigned'] = mac
            
            with open('./settings.json', 'w') as fp:
                json.dump(main.BUFFERS, fp, indent=4)
            
            return "You have successfully logged into the captive portal. Welcome to the internet."
        
        else:
            return "Invalid username or password. <a href='/login'>Click me to login again</a>."
        
    
    """if username == 'admin' and password == 'password':
        return redirect('/fwb')
    else:
        return "Invalid username or password"""

@server.route('/api/info/statistics/dns')
def stats():
    return {'latency': main.STATS['latency'], 'total_reqs': main.STATS['total_requests'], 'server': main.STATS['selected_dns'], 'bytes_transferred': main.STATS['bytes_transferred'], 'clients_contacted': list(main.STATS['clients'])}

@server.route('/api/info/dns/disable_requests', methods=['POST'])
def disable_dns_requests():
    main.STATS['disable_dns_requests'] = not main.STATS['disable_dns_requests']
    return {'opcode': 'DNS:/action/success', 'status': main.STATS['disable_dns_requests']}

@server.route('/api/info/dns/disable_dns_switching', methods=['POST'])
def disable_dns_switching():
    main.STATS['disable_dns_switching'] = not main.STATS['disable_dns_switching']
    return {'opcode': 'DNS:/action/success', 'status': main.STATS['disable_dns_switching']}

@server.before_request
def redirect_to_http():
    if "/fwb" in request.full_path:
        if request.host+"." in main.BLOCKED_WEBSITES:
            info = main.BLOCKED_WEBSITES[request.host+"."]
            blocked_macs = info['mac_addresses']
            if request.remote_addr in main.STATS['clients_mac_address']:
                mac_address = main.STATS['clients_mac_address'][request.remote_addr]
                if mac_address.lower() in blocked_macs or "all" in blocked_macs:
                    return redirect(f"https://fw.hbn.rf.gd{request.full_path}{'?' if not '?' in request.full_path else '&'}url={request.url.split('/fwb',1)[0]}&mac={mac_address or request.remote_addr}")
            return "An error has occurred while loading this page. Please try again.<footer>HostBase Firewall</footer>"
        if request.host == "block.test" or request.host == "www.block.test":
            mac_address = None
            if request.remote_addr in main.STATS['clients_mac_address']:
                mac_address = main.STATS['clients_mac_address'][request.remote_addr]
            return redirect(f"https://fw.hbn.rf.gd{request.full_path}{'?' if not '?' in request.full_path else '&'}url={request.url.split('/fwb',1)[0]}&mac={mac_address or request.remote_addr}")
    
    if request.is_secure and request.host != "router.local" and request.host != "www.router.local" and request.host != "fw.hbn.rf.gd" and request.host != "www.fw.hbn.rf.gd":
        # check if the incoming request has invalid binary data (likely an https request on http)
        if request.headers.get('Content-Type') is None and b'\x16\x03' in request.data[:2]:
            return "invalid request: https sent to http endpoint", 400

        return redirect(request.url.replace("https://", "http://"), code=301)
    
# DNS OVER HTTPS

@server.endpoint('/dns-query')
def doh_query():
    #if request.scheme != "https":
    #    return "ERROR: DoH requests must be made over HTTPS.", 400
    # receive dns query from doh client
    print(request.method)
    query_data = request.data
    
    try:
        query = main.message.from_wire(query_data)
        
        print("Query made through DoH.")

        # forward the query to your local dns resolver
        response = main.query.udp(query, '127.0.0.1')  # assuming your dns server is on localhost

        # return the dns response to the client
        return response.to_wire(), 200, {'Content-Type': 'application/dns-message'}

    except Exception as e:
        print(f"Error handling DNS query: {e}")
        return "Error processing the DNS query", 500
    
server.url_map.add(Rule('/dns-query', endpoint="/dns-query"))

@server.after_request
def remove_hsts(response):
    if 'Strict-Transport-Security' in response.headers:
        del response.headers['Strict-Transport-Security']
    return response

def run_http():
    # http server (port 80)
    server.run(host='0.0.0.0', port=80)

def run_https():
    # https server (port 443)
    server.run(ssl_context=('certificate.crt', 'private.key'), host='0.0.0.0', port=443, threaded=True)
    #server.run(ssl_context='adhoc', host='0.0.0.0', port=443, threaded=True)

#server.run(port=443, ssl_context=('cert.pem', 'key.pem'))

if __name__ == '__main__':
    # run both http and https in parallel
    threading.Thread(target=run_http).start()
    run_https()
