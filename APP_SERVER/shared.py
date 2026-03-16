import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import socket
import json
import struct
from transport.rudp.rudp import RUDPSocket

CONTROL_PORT = 8443
DATA_PORT_RANGE = (50000, 50050)
BUFFER_SIZE = 4096
FORMAT = 'utf-8'


def send_msg(sock, msg_dict):
    msg_bytes = json.dumps(msg_dict).encode(FORMAT)
    sock.sendall(struct.pack('!I', len(msg_bytes)))
    sock.sendall(msg_bytes)


def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('!I', raw_msglen)[0]
    data = recvall(sock, msglen)
    if not data:
        return None
    return json.loads(data.decode(FORMAT))


def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


class DataConnection:
    def send_data(self, data: bytes):
        raise NotImplementedError

    def recv_data(self, buffer_size: int) -> bytes:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class TCPDataConnection(DataConnection):
    def __init__(self, sock):
        self.sock = sock

    def send_data(self, data: bytes):
        self.sock.sendall(data)

    def recv_data(self, buffer_size: int) -> bytes:
        return self.sock.recv(buffer_size)

    def close(self):
        self.sock.close()


class RUDPDataConnection(DataConnection):
    def __init__(self, sock, is_server=False, dest_addr=None):
        # Wrap the standard Python socket with our super secret mega ultra advanced RUDPSocket
        self.rudp_sock = RUDPSocket(sock)
        if dest_addr:
            self.rudp_sock.set_destination(dest_addr)
        self.is_server = is_server

    def accept_connection(self):
        """
        Server side: Waits for the initial token from the client.
        Because UDP is connectionless, receiving the first message (the token)
        is how the server learns the client's IP and port.
        """
        # UUID token is exactly 36 bytes long
        token_bytes = self.rudp_sock.recvall(36)
        return token_bytes.decode('utf-8'), self.rudp_sock.dest_addr

    def connect(self, token, dest_addr):
        """
        Client side: Sets the destination address and sends the initial token
        to 'handshake' with the server.
        """
        self.rudp_sock.set_destination(dest_addr)
        self.rudp_sock.sendall(token.encode('utf-8'))

    def send_data(self, data: bytes):
        self.rudp_sock.sendall(data)

    def recv_data(self, buffer_size: int) -> bytes:
        return self.rudp_sock.recvall(buffer_size)

    def close(self):
        self.rudp_sock.close()
