import socket
import ssl
import os
import time
import hashlib
import sys
import signal
import getpass
import logging
from tqdm import tqdm
from shared import send_msg, recv_msg, TCPDataConnection, RUDPDataConnection, CONTROL_PORT, BUFFER_SIZE


logging.basicConfig(
    filename='rudp_transfer.log',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

SERVER_IP = 'backup.com' # Change to your live server's IP when deploying MR TESTER! (UNLESS DNS SERVER IS LIVE!!)

class SyncClient:
    def __init__(self):
        self.secure_client = None
        self.token = None
        self.username = None
        self.sync_dir = os.path.abspath("./client_data")
        self.protocol = "TCP" # Default, can be toggled to RUDP
        self.running = True

        signal.signal(signal.SIGINT, self.shutdown_handler)

    def shutdown_handler(self, signum, frame):
        print("\n[!] Shutting down client safely...")
        self.running = False
        if self.secure_client:
            self.secure_client.close()
        sys.exit(0)

    def connect(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_client = context.wrap_socket(client, server_hostname=SERVER_IP)

        try:
            print(f"[*] Connecting to server at {SERVER_IP}:{CONTROL_PORT}...")
            self.secure_client.connect((SERVER_IP, CONTROL_PORT))
            return True
        except Exception as e:
            print(f"[!] CRITICAL: Could not connect to server. {e}")
            return False

    def authenticate(self):
        while not self.token:
            print("\n--- SERVER AUTHENTICATION ---")
            user = input("Username: ").strip()
            pwd = getpass.getpass("Password: ").strip()

            send_msg(self.secure_client, {"cmd": "AUTH", "username": user, "password": pwd})
            resp = recv_msg(self.secure_client)

            if resp and resp.get("status") == "success":
                self.token = resp.get("token")
                self.username = user
                print("[+] Authentication successful!")
            else:
                print(f"[-] Login failed: {resp.get('msg') if resp else 'No response'}")

    def get_file_hash(self, filepath):
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_local_manifest(self):
        if not os.path.exists(self.sync_dir):
            os.makedirs(self.sync_dir)
        manifest = {}

        for dirpath, _, filenames in os.walk(self.sync_dir):
            for f in filenames:
                filepath = os.path.join(dirpath, f)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)

                    rel_path = os.path.relpath(filepath, self.sync_dir).lower().replace('\\', '/')

                    manifest[rel_path] = {
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "hash": self.get_file_hash(filepath),
                        "local_path": filepath
                    }
        return manifest

    def upload_file(self, net_path, file_size, local_path):
        send_msg(self.secure_client, {
            "cmd": "UPLOAD_INIT",
            "filename": net_path,
            "file_size": file_size,
            "protocol": self.protocol
        })
        init_resp = recv_msg(self.secure_client)

        if init_resp.get("status") != "ready":
            print(f"[-] Server rejected upload for {net_path}: {init_resp.get('msg')}")
            return False

        data_port = init_resp.get("data_port")
        sock_type = socket.SOCK_STREAM if self.protocol == "TCP" else socket.SOCK_DGRAM
        data_sock = socket.socket(socket.AF_INET, sock_type)

        try:
            if self.protocol == "TCP":
                data_sock.connect((SERVER_IP, data_port))
                data_conn = TCPDataConnection(data_sock)
                data_conn.send_data(self.token.encode('utf-8'))
            elif self.protocol == "RUDP":
                data_conn = RUDPDataConnection(data_sock)
                data_conn.connect(self.token, (SERVER_IP, data_port))
            else:
                return False

            with open(local_path, "rb") as f, tqdm(
                desc=f"Uploading {net_path}", total=file_size, unit="B", unit_scale=True, unit_divisor=1024
            ) as pbar:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    data_conn.send_data(chunk)
                    pbar.update(len(chunk))

        except Exception as e:
            print(f"[-] Failed to upload {net_path}: {e}")
            return False
        finally:
            if 'data_conn' in locals() and hasattr(data_conn, 'close'):
                data_conn.close()

        time.sleep(0.5)

        send_msg(self.secure_client, {"cmd": "VERIFY_HASH", "filename": net_path})
        verify_resp = recv_msg(self.secure_client)

        if verify_resp.get("status") == "success":
            if verify_resp.get("hash") == self.get_file_hash(local_path):
                return True
        print(f"[-] ERROR: Hash mismatch for '{net_path}'! Data corrupted during transfer.")
        return False

    def download_file(self, net_path, expected_hash, expected_size):
        filepath = os.path.normpath(os.path.join(self.sync_dir, net_path))
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        send_msg(self.secure_client, {
            "cmd": "DOWNLOAD_INIT",
            "filename": net_path,
            "protocol": self.protocol
        })
        init_resp = recv_msg(self.secure_client)

        if init_resp.get("status") != "ready":
            print(f"[-] Server rejected download for {net_path}: {init_resp.get('msg')}")
            return False

        data_port = init_resp.get("data_port")
        sock_type = socket.SOCK_STREAM if self.protocol == "TCP" else socket.SOCK_DGRAM
        data_sock = socket.socket(socket.AF_INET, sock_type)

        try:
            if self.protocol == "TCP":
                data_sock.connect((SERVER_IP, data_port))
                data_conn = TCPDataConnection(data_sock)
                data_conn.send_data(self.token.encode('utf-8'))
            elif self.protocol == "RUDP":
                data_conn = RUDPDataConnection(data_sock)
                data_conn.connect(self.token, (SERVER_IP, data_port))
            else:
                return False

            with open(filepath, "wb") as f, tqdm(
                desc=f"Downloading {net_path}", total=expected_size, unit="B", unit_scale=True, unit_divisor=1024
            ) as pbar:
                received = 0
                while received < expected_size:
                    chunk = data_conn.recv_data(min(BUFFER_SIZE, expected_size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    pbar.update(len(chunk))

        except Exception as e:
            print(f"[-] Failed to download {net_path}: {e}")
            return False
        finally:
            if 'data_conn' in locals() and hasattr(data_conn, 'close'):
                data_conn.close()

        if self.get_file_hash(filepath) == expected_hash:
            return True
        print(f"[-] ERROR: Hash mismatch for '{net_path}'! Data corrupted during transfer.")
        return False

    def print_menu(self):
        print("\n" + "="*45)
        print(f" BACKUP CLIENT | User: {self.username}")
        print(f" Directory: {self.sync_dir}")
        print(f" Protocol:  {self.protocol}")
        print("="*45)
        print("1. Sync Local Folder to Server (Upload Only)")
        print("2. Restore All Files from Server (Download All)")
        print("3. Deep Manifest Verification (Check Integrity)")
        print("4. Change Target Directory")
        print("5. Toggle Protocol (TCP/RUDP)")
        print("6. Request Quota Increase")
        print("7. Check Storage Usage")
        print("8. Manage / Delete Server Files")
        print("9. Help / What is a Manifest?")
        print("10. Clear Screen")
        print("11. Exit")

    def print_help(self):
        print("\n" + "-"*45)
        print(" HELP & TERMINOLOGY ")
        print("-"*45)
        print("Sync Local Folder: Uploads new/modified files to the server. Will NOT delete files.")
        print("Restore All Files: Downloads all files currently saved on the server back to you.")
        print("Manage Server Files: View your remote archive and selectively delete files or folders to free up space.")
        print("Manifest: A secure record of all your files. It contains the names, sizes, and a hash to ensure files aren't corrupted.")
        print("Deep Verification: Compares the digital fingerprints of your local files against the server to catch tampered or corrupted files.")
        print("TCP vs RUDP: TCP is the standard, reliable internet protocol. RUDP is a custom experimental protocol made by us.")
        print("-" * 45)

    def menu(self):
        self.print_menu()
        while self.running:
            choice = input("\nSelect an option (1-11): ").strip()

            if choice == '1':
                self.action_sync()
            elif choice == '2':
                self.action_restore_all()
            elif choice == '3':
                self.action_view_manifest()
            elif choice == '4':
                new_dir = input("Enter new absolute or relative path: ").strip()
                if new_dir:
                    self.sync_dir = os.path.abspath(new_dir)
                    if not os.path.exists(self.sync_dir):
                        os.makedirs(self.sync_dir)
                    print(f"[+] Directory set to {self.sync_dir}")
            elif choice == '5':
                self.protocol = "RUDP" if self.protocol == "TCP" else "TCP"
                os.system('cls' if os.name == 'nt' else 'clear')
                self.print_menu()
                print(f"[+] Protocol successfully switched to {self.protocol}")
            elif choice == '6':
                amount = input("How many additional MB do you need? ").strip()
                if amount.isdigit():
                    send_msg(self.secure_client, {"cmd": "QUOTA_REQUEST", "amount_mb": int(amount)})
                    resp = recv_msg(self.secure_client)
                    print(f"\n[Server Response]: {resp.get('msg', 'Request sent to admin.')}")
                else:
                    print("[-] Please enter a valid number.")
            elif choice == '7':
                send_msg(self.secure_client, {"cmd": "CHECK_USAGE"})
                resp = recv_msg(self.secure_client)
                if resp and resp.get("status") == "success":
                    used_mb = resp["used"] / (1024*1024)
                    total_mb = resp["quota"] / (1024*1024)
                    remaining_mb = max(0, total_mb - used_mb)
                    percent = (used_mb / total_mb) * 100 if total_mb > 0 else 0

                    print(f"\n--- STORAGE USAGE ---")
                    print(f"Used:      {used_mb:>7.2f} MB")
                    print(f"Remaining: {remaining_mb:>7.2f} MB")
                    print(f"Total:     {total_mb:>7.2f} MB")
                    print(f"Capacity:  {percent:.1f}% full\n")
                else:
                    print("[-] Failed to fetch usage data from server.")
            elif choice == '8':
                self.action_manage_server_files()
            elif choice == '9':
                self.print_help()
            elif choice == '10':
                os.system('cls' if os.name == 'nt' else 'clear')
                self.print_menu()
            elif choice == '11':
                self.shutdown_handler(None, None)
            else:
                print("[-] Invalid choice. Type 9 for help or 10 to view the menu again.")

    def action_manage_server_files(self):
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        resp = recv_msg(self.secure_client)
        server_manifest = resp.get("manifest", {})

        if not server_manifest:
            print("[-] No files currently stored on the server.")
            return

        print("\n--- SERVER FILES ---")
        for net_path in sorted(server_manifest.keys()):
            size_mb = server_manifest[net_path]['size'] / (1024 * 1024)
            print(f" - {net_path} ({size_mb:.2f} MB)")
        print("-" * 20)

        print("\nType the exact file path to delete it.")
        print("Type a folder path ending with '/' to delete the whole folder (e.g., 'photos/').")
        target = input("Target (or 'q' to cancel): ").strip()

        if target.lower() == 'q' or not target:
            return

        if target.endswith('/'):
            matches = [p for p in server_manifest.keys() if p.startswith(target.lower())]
            if not matches:
                print(f"[-] No files found inside folder '{target}'.")
                return

            confirm = input(f"[!] WARNING: This will delete {len(matches)} files. Are you absolutely sure? (y/n): ").strip().lower()
            if confirm == 'y':
                for net_path in matches:
                    send_msg(self.secure_client, {"cmd": "DELETE", "filename": net_path})
                    del_resp = recv_msg(self.secure_client)
                    if del_resp and del_resp.get("status") == "success":
                        print(f"[+] Deleted {net_path}")
                    else:
                        print(f"[-] Failed to delete {net_path}")
            else:
                print("[*] Deletion canceled.")
        else:
            if target.lower() not in server_manifest:
                print(f"[-] File '{target}' not found on server.")
                return

            confirm = input(f"[?] Are you sure you want to delete '{target}'? (y/n): ").strip().lower()
            if confirm == 'y':
                send_msg(self.secure_client, {"cmd": "DELETE", "filename": target.lower()})
                del_resp = recv_msg(self.secure_client)
                if del_resp and del_resp.get("status") == "success":
                    print(f"[+] Successfully deleted {target}")
                else:
                    print(f"[-] Failed to delete {target}")
            else:
                print("[*] Deletion canceled.")

    def action_view_manifest(self):
        print("\n[*] Fetching server manifest and verifying local hashes...")
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        resp = recv_msg(self.secure_client)
        server_manifest = resp.get("manifest", {})

        local_manifest = self.get_local_manifest()

        if not server_manifest and not local_manifest:
            print("[-] Both server and local directories are empty.")
            return

        print("\n--- DEEP MANIFEST VERIFICATION ---")

        for net_path, local_data in local_manifest.items():
            server_data = server_manifest.get(net_path)

            if not server_data:
                print(f"[?] {net_path:<20} | LOCAL ONLY (Not backed up)")
            else:
                if local_data["hash"] == server_data["hash"]:
                    print(f"[+] {net_path:<20} | OK (Hashes match)")
                else:
                    print(f"[!] {net_path:<20} | MODIFIED / CORRUPTED (Hash mismatch)")

        for net_path, server_data in server_manifest.items():
            if net_path not in local_manifest:
                size_mb = server_data['size'] / (1024*1024)
                print(f"[-] {net_path:<20} | SERVER ONLY ({size_mb:.2f} MB)")
        print("-" * 34)

    def action_sync(self):
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        server_manifest = recv_msg(self.secure_client).get("manifest", {})
        local_manifest = self.get_local_manifest()

        files_to_upload = []
        for net_path, local_data in local_manifest.items():
            server_data = server_manifest.get(net_path)
            if not server_data or local_data["mtime"] > server_data["mtime"] or local_data["size"] != server_data["size"]:
                files_to_upload.append((net_path, local_data["size"], local_data["local_path"]))

        if not files_to_upload:
            print("[+] Local folder is fully synced. Nothing to upload.")
            return

        print(f"[*] Found {len(files_to_upload)} files to update/upload.")
        for net_path, size, local_path in files_to_upload:
            if self.upload_file(net_path, size, local_path):
                print(f"[+] Successfully synced {net_path}")

    def action_restore_all(self):
        send_msg(self.secure_client, {"cmd": "GET_MANIFEST"})
        server_manifest = recv_msg(self.secure_client).get("manifest", {})

        if not server_manifest:
            print("[-] Nothing on the server to restore.")
            return

        print(f"[*] Restoring {len(server_manifest)} files from server...")
        for net_path, data in server_manifest.items():
            if self.download_file(net_path, data["hash"], data["size"]):
                print(f"[+] Restored {net_path}")

if __name__ == "__main__":
    client = SyncClient()
    if client.connect():
        client.authenticate()
        client.menu()
