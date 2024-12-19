from dns import message, opcode, query, rrset, rdatatype, rcode, rdataclass, rdata, name
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF
from concurrent.futures import ThreadPoolExecutor
from getmac import get_mac_address
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket as sock, threading, time, platform, subprocess, re, json, smtplib, base64, os.path

DNS_HOST = "127.0.0.1"
DNS_PORT = 53  # DNS default port

if os.path.exists("settings.json"):
    BUFFERS = json.load(open('./settings.json'))
else:
    BUFFERS = {}

# Custom DNS mapping
# Add custom records here, for example add a custom record which blocks a request.
# Must be an A record.
CUSTOM_RECORDS = {
    "block.test.": { "name": "block.test.", "value": "127.0.0.1", "type": "A" },
    "www.block.test.": { "name": "www.block.test.", "value": "127.0.0.1", "type": "A" },
    "router.local.": { "name": "router.local.", "value": "127.0.0.1", "type": "A" },
    "www.router.local.": { "name": "www.router.local.", "value": "127.0.0.1", "type": "A" },
    "fw.hb.rf.gd.": { "name": "fw.hb.rf.gd.", "value": "127.0.0.1", "type": "A" },
    "fw.hbn.rf.gd.": { "name": "fw.hbn.rf.gd.", "value": "127.0.0.1", "type": "A" },
}
BLOCKED_WEBSITES = {
    "www.reddit.co.": { "mac_addresses": ["4c:03:4f:a4:71:4e"], "status": True },
    "reddit.co.": { "mac_addresses": ["4c:03:4f:a4:71:4e"], "status": True },
}
RECORD_TYPES = {
    "CNAME": rdatatype.CNAME,
    "A": rdatatype.A,
    "AAAA": rdatatype.AAAA,
    "MX": rdatatype.MX,
    "TXT": rdatatype.TXT,
    "NS": rdatatype.NS
}
# Add custom DNS servers here, for which the primary will switch between.
# DNS switching is automatically enabled for the best performance.
DNS_SERVERS = [
    "8.8.8.8", # Google Public DNS
    #"208.67.222.222",  # OpenDNS
    "1.1.1.1",  # Cloudflare
    #"1.0.0.1", # Cloudflare
    #"8.8.4.4", # Google Public DNS
    #"9.9.9.9", # Quad 9
    #"94.140.14.14", # AdGuard DNS
    # "185.228.168.9", # CleanBrowsing DNS
]
# Add custom settings here.
# Will be referenced by the router web server.
STATS = {
    'total_requests': 0,
    'latency': '0ms',
    'real_latency': 0,
    'custom_records': len(CUSTOM_RECORDS),
    'selected_dns': DNS_SERVERS[0],
    'disable_dns_requests': False,
    'disable_dns_switching': False,
    'bytes_transferred': 0,
    'clients': set(),
    'clients_mac_address': {},
    'latest_dns_latencies': {},
    "identities": {}
}

def parse_new_blocked_websites_from_buffers():
    # Update blocked websites from buffers.json
    global BLOCKED_WEBSITES, BUFFERS
    BLOCKED_WEBSITES = {}
    for b1 in BUFFERS.get('CONTENT_BLOCKS',[]):
        BLOCKED_WEBSITES[f"{b1['query']}{'.'if(not b1['query'].endswith('.'))else''}"] = {
            "name": f"{b1['query']}",
            "mac_addresses": b1['macs'],
            "status": b1['status'],
            "ID": b1['ID']
        }
    print('dns: updated block list')
    return BLOCKED_WEBSITES

parse_new_blocked_websites_from_buffers()

def get_mac(ip):
    if ip.startswith('127.'):
        return get_mac_address()
    return get_mac_address(ip=ip)
    """# execute arp command and parse the output to find the mac address
    if platform.system().lower() == "windows":
        # for windows
        print('init')
        result = subprocess.run(["arp", "-a", ip], stdout=subprocess.PIPE, text=True)
        print(result.stdout)
        match = re.search(r"([a-f0-9]{2}-){5}[a-f0-9]{2}", result.stdout)
    else:
        # for linux/mac
        print('init2')
        result = subprocess.run(["arp", "-n", ip], stdout=subprocess.PIPE, text=True)
        match = re.search(r"([a-f0-9]{2}[:]){5}[a-f0-9]{2}", result.stdout)
    
    if match:
        return match.group(0)
    return None"""


def update_dns(latency, selection):
    STATS['latency'] = f"{latency:.2f}ms"
    STATS['real_latency'] = latency
    STATS['selected_dns'] = selection

def get_dns_latency(dns_server, q="www.google.com"):
    """
    Measure the latency to a DNS server by sending a query.
    """
    try:
        dns_query = message.make_query(q, rdatatype.A)

        start_time = time.time()
        
        response = query.udp(dns_query, dns_server, timeout=5)

        end_time = time.time()

        latency = (end_time - start_time) * 1000
        return latency

    except Exception as e:
        print(f"Error checking latency to {dns_server}: {e}")
        return None
    
def check_and_switch_dns():
    while True:
        if STATS['disable_dns_switching'] == True:
            print(f"DNS switching disabled. Skipping DNS switch.")
            time.sleep(60)
            continue
        
        latencies = {}
        for server in DNS_SERVERS:
            latency = get_dns_latency(server)
            if latency is not None:
                latencies[server] = latency
                
        STATS['latest_dns_latencies'] = latencies

        if latencies:
            best_server = min(latencies, key=latencies.get)
            print(f"Switching to DNS server: {best_server} with {latencies[best_server]:.2f} ms latency")
            update_dns(latencies[best_server], best_server)

        time.sleep(60)
        
def mac_addr_manager(caddr):
    global STATS
    if not caddr in list(STATS['clients_mac_address']):
        mac = get_mac(caddr)
        STATS['clients_mac_address'][caddr] = mac
        print(STATS['clients_mac_address'])

def handle_dns_query(data:bytes, caddr, sock:socket, *args):
    request = message.from_wire(data)
    return_msg = message.make_response(request)
    
    if STATS['disable_dns_requests'] == True:
        print(f"DNS request disabled. Skipping query: {request.question[0].name}")
        return_msg.set_rcode(rcode.REFUSED)
        sock.sendto(return_msg.to_wire(), caddr)
        return
    
    for qw in request.question:
        qw_name = str(qw.name)
        
        if BUFFERS.get('CAPTIVE_PORTAL_ENABLED', False) == True:
            user_allowed_to_pass = False
            
            if caddr[0] in STATS['clients_mac_address']:
                for user in BUFFERS['CAPTIVE_PORTAL_USERS']:
                    if user['mac_assigned'] == STATS['clients_mac_address'].get(caddr[0], None):
                        user_allowed_to_pass = True
                        break
            
            if user_allowed_to_pass == False:
                ip_address = "127.0.0.1"
                
                domain_name = name.from_text(qw_name)
                
                a_record = rrset.RRset(domain_name, rdtype=rdatatype.A, rdclass=rdataclass.INTERNET)
                a_record.update_ttl(60)

                ip_rdata = rdata.from_text(rdataclass.INTERNET, rdatatype.A, ip_address)
                a_record.add(ip_rdata)
                
                return_msg.answer.append(a_record)
                sock.sendto(return_msg.to_wire(), caddr)
                
                bytestream = return_msg.to_wire()
                STATS['bytes_transferred'] += len(bytestream)
                STATS['clients'].add(caddr[0])
                
                threading.Thread(target=mac_addr_manager, args=[caddr[0]]).start()
                return
            else: pass

        if qw_name in CUSTOM_RECORDS:
            print('handled request', CUSTOM_RECORDS[qw_name])
            record_data = CUSTOM_RECORDS[qw_name]
            ip_address = record_data['value']
            
            domain_name = name.from_text(qw_name)
            
            a_record = rrset.RRset(domain_name, rdtype=RECORD_TYPES[record_data['type']], rdclass=rdataclass.INTERNET)
            a_record.update_ttl(60)
            
            ip_rdata = rdata.from_text(rdataclass.INTERNET, RECORD_TYPES[record_data['type']], ip_address)
            a_record.add(ip_rdata)
            
            return_msg.answer.append(a_record)
            sock.sendto(return_msg.to_wire(), caddr)
            return
        elif qw_name in BLOCKED_WEBSITES:
            print('handled request, website is blocked', BLOCKED_WEBSITES[qw_name])
            record_data = BLOCKED_WEBSITES[qw_name]
            if "all" in record_data['mac_addresses']:
                ip_address = "127.0.0.1"
                
                #response2 = query.udp(request, STATS['selected_dns'])
                domain_name = name.from_text(qw_name)
                
                a_record = rrset.RRset(domain_name, rdtype=RECORD_TYPES["A"], rdclass=rdataclass.INTERNET)
                a_record.update_ttl(60)
                
                ip_rdata = rdata.from_text(rdataclass.INTERNET, RECORD_TYPES["A"], ip_address)
                a_record.add(ip_rdata)
                
                #return_msg.authority.extend(response2.authority)
                return_msg.answer.append(a_record)
                sock.sendto(return_msg.to_wire(), caddr)
                return
            else:
                website_is_blocked_for_user = False
                if caddr[0] in STATS['clients_mac_address']:
                    print('inside')
                    for mac in record_data['mac_addresses']:
                        print('inside2')
                        if STATS['clients_mac_address'][caddr[0]].lower() == mac.lower():
                            print('inside3-end')
                            website_is_blocked_for_user = True
                            break
                
                if website_is_blocked_for_user:
                    print('website is blocked for user')
                    ip_address = "127.0.0.1"
                    
                    #response2 = query.udp(request, STATS['selected_dns'])
                    domain_name = name.from_text(qw_name)
                    
                    a_record = rrset.RRset(domain_name, rdtype=RECORD_TYPES["A"], rdclass=rdataclass.INTERNET)
                    a_record.update_ttl(60)
                    
                    ip_rdata = rdata.from_text(rdataclass.INTERNET, RECORD_TYPES["A"], ip_address)
                    a_record.add(ip_rdata)
                    
                    #return_msg.authority.extend(response2.authority)
                    return_msg.answer.append(a_record)
                    sock.sendto(return_msg.to_wire(), caddr)
                    return
                else:
                    print('website is not blocked for user')
                    print(f"Record not found for {qw_name}, forwarding query to outside DNS ({STATS['selected_dns']})...")
                    
                    start_time = time.time()
                    
                    response = query.udp(request, STATS['selected_dns'])
                    
                    end_time = time.time()
                    latency = (end_time - start_time) * 1000
                    
                    update_dns(latency, STATS['selected_dns'])
                    
                    return_msg.answer.extend(response.answer)
                    return_msg.additional.extend(response.additional)
                    return_msg.authority.extend(response.authority)
        else:
            outside_dns = STATS['selected_dns']
            print(f"Record not found for {qw_name}, forwarding query to outside DNS ({STATS['selected_dns']})...")
            
            start_time = time.time()
            
            response = query.udp(request, outside_dns)
            
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            
            update_dns(latency, STATS['selected_dns'])
            
            return_msg.answer.extend(response.answer)
            return_msg.additional.extend(response.additional)
            return_msg.authority.extend(response.authority)
            
            #return_msg.set_rcode(rcode.REFUSED)
            
    bytestream = response.to_wire()
    STATS['bytes_transferred'] += len(bytestream)
    STATS['clients'].add(caddr[0])
    
    sock.sendto(bytestream, caddr)
    threading.Thread(target=mac_addr_manager, args=[caddr[0]]).start()
    del caddr, data, bytestream
    return

# DNS server
# Using ThreadPoolExecutor to handle incoming requests with threading
def run_dns_server():
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 65535)
    server_socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 65535)
    server_socket.bind((DNS_HOST, DNS_PORT))
    print(f"DNS server is up on {DNS_HOST}:{DNS_PORT} (￣m￣）")
    with ThreadPoolExecutor(max_workers=224) as executor:
        while True:
            try:
                data, client_address = server_socket.recvfrom(65535)
                STATS['total_requests'] += 1
                executor.submit(handle_dns_query, data, client_address, server_socket)
            except Exception as e:
                print(f"server error: {e}")

if __name__ == "__main__":
    try:
        threading.Thread(target=check_and_switch_dns, daemon=True).start()
        run_dns_server()
    except KeyboardInterrupt:
        print("\nDNS server stopped >w<")
