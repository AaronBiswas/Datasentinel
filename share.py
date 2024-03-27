import socket
import threading
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = []
        self.transfer_speed = 0
        self.transfer_time = 0
        self.registered_users = {}  # Dictionary to store registered users and passwords

    def register_user(self, username, password):
        encrypted_password, iv = self.encrypt_password(password)
        self.registered_users[username] = {'password': encrypted_password, 'iv': iv}

    def login(self, username, password):
        if username in self.registered_users:
            stored_password = self.registered_users[username]['password']
            iv = self.registered_users[username]['iv']
            decrypted_password = self.decrypt_password(stored_password, iv)
            return decrypted_password == password
        else:
            return False

    def encrypt_password(self, password):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CBC, iv)
        padded_password = self.pad_password(password)
        encrypted_password = cipher.encrypt(padded_password.encode())
        return encrypted_password, iv

    def decrypt_password(self, encrypted_password, iv):
        cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CBC, iv)
        decrypted_password = cipher.decrypt(encrypted_password).decode().strip()
        return decrypted_password

    def pad_password(self, password):
        block_size = AES.block_size
        padding_length = block_size - len(password) % block_size
        padding = chr(padding_length) * padding_length
        padded_password = password + padding
        return padded_password

    def connect(self, peer_host, peer_port):
        connection = socket.create_connection((peer_host, peer_port))
        self.connections.append(connection)
        print(f"Connected to {peer_host}:{peer_port}")

    def listen(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}")

        while True:
            connection, address = self.socket.accept()
            self.connections.append(connection)
            print(f"Accepted connection from {address}")
            threading.Thread(target=self.handle_client, args=(connection, address)).start()

    def send_data(self, data):
        start_time = time.time()
        md5_hash = hashlib.md5(data.encode()).hexdigest()
        for connection in self.connections:
            try:
                connection.sendall(data.encode())
                connection.sendall(md5_hash.encode())
            except socket.error as e:
                print(f"Failed to send data. Error: {e}")
                self.connections.remove(connection)
        end_time = time.time()
        self.transfer_time = end_time - start_time
        if self.transfer_time != 0:
            self.transfer_speed = len(data) / self.transfer_time

    def handle_client(self, connection, address):
        while True:
            try:
                data = connection.recv(1024).decode()
                md5_hash = connection.recv(32).decode()
                if not data:
                    break
                received_hash = hashlib.md5(data.encode()).hexdigest()
                if received_hash == md5_hash:
                    print(f"Received data from {address}: {data}")
                else:
                    print("Hash check failed. Data may have been corrupted.")
            except socket.error:
                break

        print(f"Connection from {address} closed.")
        self.connections.remove(connection)
        connection.close()

    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

# Example usage:
if __name__ == "__main__":
    node1 = Peer("0.0.0.0", 8000)
    node1.register_user("aaron", "biswas")  # Register user with username and password
    node1.start()

    node2 = Peer("0.0.0.0", 8001)
    node2.start()

    # Give some time for nodes to start listening
    time.sleep(2)

    # Attempt login with registered user credentials
    username = input("Enter username: ")
    password = input("Enter password: ")
    if node1.login(username, password):
        print("Login successful. Initiating file transfer.")
        node2.connect("127.0.0.1", 8000)
        time.sleep(1)  # Allow connection to establish
        data_to_send = "Hello from node2!"
        node2.send_data(data_to_send)
        print("File transfer complete.")
        # Print performance metrics
        print("Transfer Speed:", node2.transfer_speed, "bytes/second")
        print("Transfer Time:", node2.transfer_time, "seconds")
    else:
        print("Login failed. Incorrect username or password.")
