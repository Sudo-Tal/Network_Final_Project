import socket
import ssl
import threading
import os
import hashlib
import uuid
import json
import logging
import sys
from shared import send_msg, recv_msg, TCPDataConnection, RUDPDataConnection, CONTROL_PORT, DATA_PORT_RANGE, BUFFER_SIZE

SERVER_DATA_DIR = "./server_data"
DB_FILE = "users.json"
DEFAULT_QUOTA = 1024 * 1024 * 1024  # 1 GB default quota

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log")
    ]
)

def load_users():
    """Loads users from the JSON database or creates a default one."""
    if not os.path.exists(DB_FILE):
        default_data = {
            "admin": {"password": "password123", "quota": DEFAULT_QUOTA},
            "user1": {"password": "password123", "quota": 500 * 1024 * 1024}, # 500 MB
            "dor_cohen": {"password": "pleasegiveus100", "quota": 500 * 1024 * 1024}, # 500 MB
            "amit_dvir": {"password": "ilovethisserver", "quota": 500 * 1024 * 1024} # 500 MB

        }
        with open(DB_FILE, 'w') as f:
            json.dump(default_data, f, indent=4)
        logging.info(f"Created new user database at {DB_FILE}")
        return default_data
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def get_directory_size(path):
    """Recursively calculates the total size of a directory in bytes."""
    total_size = 0
    if not os.path.exists(path):
        return total_size
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size

class BackupServer:
    def __init__(self):
        self.active_sessions = {}
        self.session_lock = threading.Lock()
        self.users = load_users()
        self.pending_quota_requests = {}
        self.running = True

        if not os.path.exists(SERVER_DATA_DIR):
            os.makedirs(SERVER_DATA_DIR)

    def announce_presence(self):
        """Broadcasts server presence to the DNS server to register backup.com"""
        print("\n[*] Broadcasting presence to DNS server for record creation...")
        discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discovery_socket.settimeout(2.0)

        secret_msg = b"I am alive"
        expected_reply = b"I see you"

        for attempt in range(1, 4):
            print(f"    [~] Attempt {attempt}/3 to announce presence to DNS on port 9999...")
            try:
                discovery_socket.sendto(secret_msg, ('255.255.255.255', 9999))
                data, addr = discovery_socket.recvfrom(1024)
                if data == expected_reply:
                    print(f"    [+] DNS Server acknowledged us from {addr[0]}! 'backup.com' is now linked.\n")
                    break
            except socket.timeout:
                continue
            except Exception as e:
                print(f"    [-] Socket error during announcement: {e}")

        discovery_socket.close()

    def shutdown(self):
        print("\n[SHUTDOWN] Initiating forced server shutdown...")
        logging.info("Server manually stopped via CLI.")
        self.running = False
        os._exit(0)

    def get_file_hash(self, filepath):
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def generate_manifest(self, username):
        user_dir = os.path.join(SERVER_DATA_DIR, username)
        manifest = {}
        if not os.path.exists(user_dir):
            return manifest

        # FIX : Subdirectory Support
        for dirpath, _, filenames in os.walk(user_dir):
            for f in filenames:
                filepath = os.path.join(dirpath, f)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)

                    #force relative paths to lowercase and standard network slashes
                    rel_path = os.path.relpath(filepath, user_dir).lower().replace('\\', '/')
                    manifest[rel_path] = {
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "hash": self.get_file_hash(filepath)
                    }
        return manifest

    def get_secure_filepath(self, username, raw_filename):
        """Sanitizes filename, checks for path traversal, and returns absolute path."""
        # Lowercase
        clean_name = raw_filename.lower().replace('\\', '/')
        if ".." in clean_name or clean_name.startswith("/"):
            return None

        base_dir = os.path.abspath(os.path.join(SERVER_DATA_DIR, username))
        target_path = os.path.abspath(os.path.join(base_dir, clean_name))

        # Verify target is actually inside the user's directory boundary (prevent path manipulation!!!)
        if not target_path.startswith(base_dir):
            return None

        return target_path

    def handle_data_transfer(self, token, filepath, file_size, protocol, action):
        sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
        data_sock = socket.socket(socket.AF_INET, sock_type)
        data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_port = None

        for port in range(DATA_PORT_RANGE[0], DATA_PORT_RANGE[1] + 1):
            try:
                data_sock.bind(('0.0.0.0', port))
                data_port = port
                break
            except OSError:
                continue

        if not data_port:
            logging.error("CRITICAL: No available data ports in the specified range.")
            data_sock.close()
            return None

        if protocol == "TCP":
            data_sock.listen(1)

        data_sock.settimeout(15.0)

        def transfer_worker():
            try:
                if protocol == "TCP":
                    conn, addr = data_sock.accept()
                    data_conn = TCPDataConnection(conn)
                    client_token = data_conn.recv_data(36).decode('utf-8')
                elif protocol == "RUDP":
                    data_conn = RUDPDataConnection(data_sock, is_server=True)
                    client_token, addr = data_conn.accept_connection()
                else:
                    logging.warning(f"Unknown protocol requested: {protocol}")
                    data_sock.close()
                    return

                if client_token != token:
                    logging.warning(f"Auth failed on data channel from {addr}")
                    if hasattr(data_conn, 'close'):
                        data_conn.close()
                    return

                with self.session_lock:
                    if token not in self.active_sessions:
                        return
                    username = self.active_sessions[token]

                if action == "UPLOAD":
                    logging.info(f"[{username}] Receiving {os.path.basename(filepath)} via {protocol}...")

                    # Ensure intermediates
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)

                    with open(filepath, "wb") as f:
                        received = 0
                        while received < file_size:
                            chunk = data_conn.recv_data(min(BUFFER_SIZE, file_size - received))
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)
                    logging.info(f"[{username}] Finished receiving {os.path.basename(filepath)}")

                elif action == "DOWNLOAD":
                    logging.info(f"[{username}] Sending {os.path.basename(filepath)} via {protocol}...")
                    with open(filepath, "rb") as f:
                        while True:
                            chunk = f.read(BUFFER_SIZE)
                            if not chunk:
                                break
                            data_conn.send_data(chunk)
                    logging.info(f"[{username}] Finished sending {os.path.basename(filepath)}")

                if hasattr(data_conn, 'close'):
                    data_conn.close()

            except socket.timeout:
                logging.error(f"Data transfer timed out on port {data_port}")
            except Exception as e:
                logging.error(f"Data transfer error: {e}")
            finally:
                data_sock.close()

        threading.Thread(target=transfer_worker, daemon=True).start()
        return data_port

    def handle_client(self, conn, addr):
        logging.info(f"[NEW CONNECTION] {addr} connected.")
        current_token = None

        try:
            while self.running:
                msg = recv_msg(conn)
                if not msg:
                    break

                cmd = msg.get("cmd")

                if cmd == "AUTH":
                    username = msg.get("username")
                    password = msg.get("password")

                    if username in self.users and self.users[username]["password"] == password:
                        current_token = str(uuid.uuid4())
                        with self.session_lock:
                            self.active_sessions[current_token] = username

                        user_dir = os.path.join(SERVER_DATA_DIR, username)
                        if not os.path.exists(user_dir):
                            os.makedirs(user_dir)

                        send_msg(conn, {"status": "success", "token": current_token})
                        logging.info(f"User '{username}' authenticated successfully.")
                    else:
                        send_msg(conn, {"status": "error", "msg": "Invalid credentials"})
                        logging.warning(f"Failed authentication attempt for user '{username}' from {addr}")

                elif not current_token:
                    send_msg(conn, {"status": "error", "msg": "Unauthorized."})
                    continue

                elif cmd == "GET_MANIFEST":
                    with self.session_lock:
                        username = self.active_sessions[current_token]
                    manifest = self.generate_manifest(username)
                    send_msg(conn, {"status": "success", "manifest": manifest})

                elif cmd == "CHECK_USAGE":
                    with self.session_lock:
                        username = self.active_sessions[current_token]
                    user_dir = os.path.join(SERVER_DATA_DIR, username)
                    used_bytes = get_directory_size(user_dir)
                    quota_bytes = self.users[username].get("quota", DEFAULT_QUOTA)
                    send_msg(conn, {"status": "success", "used": used_bytes, "quota": quota_bytes})

                elif cmd == "QUOTA_REQUEST":
                    with self.session_lock:
                        username = self.active_sessions[current_token]
                    amount = msg.get("amount_mb", "unknown")
                    with self.session_lock:
                        self.pending_quota_requests[username] = amount
                    logging.info(f"[QUOTA REQUEST] User '{username}' is requesting {amount} MB of additional storage.")
                    send_msg(conn, {"status": "success", "msg": f"Your request for {amount} MB has been logged for admin review."})

                elif cmd == "UPLOAD_INIT":
                    with self.session_lock:
                        username = self.active_sessions[current_token]

                    raw_filename = msg.get("filename", "")
                    file_size = msg.get("file_size", 0)
                    protocol = msg.get("protocol", "TCP")

                    filepath = self.get_secure_filepath(username, raw_filename)
                    if not filepath:
                        send_msg(conn, {"status": "error", "msg": "Invalid file path."})
                        continue

                    # Enforce Quota
                    user_dir = os.path.join(SERVER_DATA_DIR, username)
                    current_usage = get_directory_size(user_dir)
                    user_quota = self.users[username].get("quota", DEFAULT_QUOTA)

                    if current_usage + file_size > user_quota:
                        logging.warning(f"[{username}] Upload rejected: Quota Exceeded. Used: {current_usage}, Requested: {file_size}, Limit: {user_quota}")
                        send_msg(conn, {"status": "error", "msg": "Quota exceeded. Contact admin for more storage."})
                        continue

                    data_port = self.handle_data_transfer(current_token, filepath, file_size, protocol, action="UPLOAD")
                    if data_port:
                        send_msg(conn, {"status": "ready", "data_port": data_port})
                    else:
                        send_msg(conn, {"status": "error", "msg": "Server ports exhausted."})

                elif cmd == "DOWNLOAD_INIT":
                    with self.session_lock:
                        username = self.active_sessions[current_token]

                    raw_filename = msg.get("filename", "")
                    protocol = msg.get("protocol", "TCP")

                    filepath = self.get_secure_filepath(username, raw_filename)
                    if not filepath or not os.path.exists(filepath):
                        send_msg(conn, {"status": "error", "msg": "File not found"})
                        continue

                    file_size = os.path.getsize(filepath)
                    data_port = self.handle_data_transfer(current_token, filepath, file_size, protocol, action="DOWNLOAD")

                    if data_port:
                        send_msg(conn, {"status": "ready", "data_port": data_port, "file_size": file_size})
                    else:
                        send_msg(conn, {"status": "error", "msg": "Server ports exhausted."})

                elif cmd == "VERIFY_HASH":
                    with self.session_lock:
                        username = self.active_sessions[current_token]

                    raw_filename = msg.get("filename", "")
                    filepath = self.get_secure_filepath(username, raw_filename)

                    file_hash = self.get_file_hash(filepath) if filepath else None
                    if file_hash:
                        send_msg(conn, {"status": "success", "hash": file_hash})
                    else:
                        send_msg(conn, {"status": "error", "msg": "File not found"})

                # Implementation of Deletions
                elif cmd == "DELETE":
                    with self.session_lock:
                        username = self.active_sessions[current_token]

                    raw_filename = msg.get("filename", "")
                    filepath = self.get_secure_filepath(username, raw_filename)

                    if not filepath:
                        send_msg(conn, {"status": "error", "msg": "Invalid file path."})
                        continue

                    if os.path.exists(filepath):
                        try:
                            os.remove(filepath)
                            logging.info(f"[{username}] Deleted {raw_filename}")
                            send_msg(conn, {"status": "success", "msg": f"Deleted {raw_filename}"})
                        except Exception as e:
                            send_msg(conn, {"status": "error", "msg": str(e)})
                    else:
                        send_msg(conn, {"status": "error", "msg": "File not found"})

        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            with self.session_lock:
                if current_token and current_token in self.active_sessions:
                    del self.active_sessions[current_token]
            conn.close()
            logging.info(f"[DISCONNECTED] {addr} disconnected.")

    def start(self):
        #trigger pulse to the DNS Server before fully booting up the listeners
        self.announce_presence()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', CONTROL_PORT))
        server.listen(5)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        secure_server = context.wrap_socket(server, server_side=True)

        self.print_startup_instructions()
        logging.info(f"Server started on port {CONTROL_PORT}")

        threading.Thread(target=self.management_cli, daemon=True).start()

        try:
            while self.running:
                secure_server.settimeout(1.0)
                try:
                    conn, addr = secure_server.accept()
                    conn.settimeout(None)
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                    thread.start()
                except socket.timeout:
                    continue
        except Exception as e:
            if self.running:
                logging.error(f"Server error: {e}")
                print(f"Server error: {e}")
        finally:
            secure_server.close()

    def print_startup_instructions(self):
        print(f"[*] Server listening on port {CONTROL_PORT} with TLS")
        print("[*] Logs are being written to server.log")
        print("[*] Management CLI Ready. Type 'status', 'users', 'requests', 'setquota <user> <mb>', 'clear', or 'exit'")

    def management_cli(self):
        while self.running:
            try:
                cmd = input("CLI> ").strip().lower()
                if not cmd:
                    continue

                if cmd == "status":
                    with self.session_lock:
                        active = len(self.active_sessions)
                    print(f"\n--- SERVER STATUS ---")
                    print(f"Active Sessions: {active}")
                    print(f"Registered Users: {len(self.users)}\n")

                elif cmd == "users":
                    print("\n--- REGISTERED USERS ---")
                    for user, data in self.users.items():
                        user_dir = os.path.join(SERVER_DATA_DIR, user)
                        used_mb = get_directory_size(user_dir) / (1024*1024)
                        quota_mb = data['quota'] / (1024*1024)
                        print(f"User: {user:<10} | Usage: {used_mb:>7.2f} MB / {quota_mb:>7.2f} MB")
                    print()

                elif cmd == "requests":
                    with self.session_lock:
                        reqs = dict(self.pending_quota_requests)
                    if not reqs:
                        print("\n[-] No pending quota requests.\n")
                    else:
                        print("\n--- PENDING QUOTA REQUESTS ---")
                        for usr, amt in reqs.items():
                            print(f"User: {usr:<10} | Requested Extra: {amt} MB")
                        print("Use 'setquota <user> <mb>' to approve.\n")

                elif cmd.startswith("setquota"):
                    parts = cmd.split()
                    if len(parts) == 3:
                        user = parts[1]
                        try:
                            new_quota_mb = int(parts[2])
                            if user in self.users:
                                self.users[user]["quota"] = new_quota_mb * 1024 * 1024
                                with open(DB_FILE, 'w') as f:
                                    json.dump(self.users, f, indent=4)

                                with self.session_lock:
                                    if user in self.pending_quota_requests:
                                        del self.pending_quota_requests[user]

                                print(f"[+] Updated quota for {user} to {new_quota_mb} MB.")
                                logging.info(f"Admin updated quota for {user} to {new_quota_mb} MB.")
                            else:
                                print(f"[-] User {user} not found.")
                        except ValueError:
                            print("[-] Usage: setquota <username> <megabytes>")
                    else:
                        print("[-] Usage: setquota <username> <megabytes>")

                elif cmd == "clear":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_startup_instructions()

                elif cmd in ["exit", "quit", "stop"]:
                    self.shutdown()

                else:
                    print("[-] Unknown command. Available: status, users, requests, setquota, clear, exit")
            except EOFError:
                break

if __name__ == "__main__":
    BackupServer().start()
