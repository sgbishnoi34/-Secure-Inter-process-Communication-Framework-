import os
import socket
import json
import hashlib
import hmac
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Dict, Tuple, Optional

# Configuration
AUTH_SERVER_PORT = 5000
BROKER_PORT = 5001
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
KEY_EXPIRATION_SEC = 3600  # 1 hour

# Shared secret for initial authentication (in production, this would be more secure)
INITIAL_SHARED_SECRET = b'super-secret-init-key-1234'

class AuthenticationServer:
    def __init__(self):
        self.process_keys: Dict[str, Tuple[bytes, float]] = {}  # {process_id: (key, expiration_time)}
        self.lock = threading.Lock()
        
    def generate_session_key(self, process_id: str) -> bytes:
        """Generate a unique session key for a process"""
        return hashlib.sha256(get_random_bytes(32) + process_id.encode()).digest()
    
    def authenticate_process(self, process_id: str, auth_token: bytes) -> Optional[bytes]:
        """Authenticate a process and return a session key if valid"""
        # In a real implementation, this would verify the auth_token against stored credentials
        expected_token = hmac.new(INITIAL_SHARED_SECRET, process_id.encode(), hashlib.sha256).digest()
        
        if not hmac.compare_digest(auth_token, expected_token):
            return None
            
        with self.lock:
            if process_id in self.process_keys:
                key, exp_time = self.process_keys[process_id]
                if exp_time > time.time():
                    return key
                    
            # Generate new key
            new_key = self.generate_session_key(process_id)
            self.process_keys[process_id] = (new_key, time.time() + KEY_EXPIRATION_SEC)
            return new_key
    
    def start_server(self):
        """Start the authentication server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', AUTH_SERVER_PORT))
            s.listen()
            print(f"Authentication server listening on port {AUTH_SERVER_PORT}")
            
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
    
    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        try:
            data = conn.recv(MAX_MESSAGE_SIZE)
            if not data:
                return
                
            try:
                request = json.loads(data.decode())
                process_id = request['process_id']
                auth_token = bytes.fromhex(request['auth_token'])
                
                session_key = self.authenticate_process(process_id, auth_token)
                response = {
                    'status': 'success' if session_key else 'failure',
                    'session_key': session_key.hex() if session_key else None
                }
                
                conn.sendall(json.dumps(response).encode())
            except (KeyError, ValueError, json.JSONDecodeError):
                conn.sendall(json.dumps({'status': 'invalid_request'}).encode())
        finally:
            conn.close()

class MessageBroker:
    def __init__(self, auth_server: AuthenticationServer):
        self.auth_server = auth_server
        self.subscriptions: Dict[str, list] = {}  # {channel: [sockets]}
        self.lock = threading.Lock()
        
    def verify_message(self, message: bytes, mac: bytes, key: bytes) -> bool:
        """Verify message integrity using HMAC"""
        expected_mac = hmac.new(key, message, hashlib.sha256).digest()
        return hmac.compare_digest(mac, expected_mac)
    
    def decrypt_message(self, encrypted: bytes, iv: bytes, key: bytes) -> Optional[bytes]:
        """Decrypt a message using AES-GCM"""
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt(encrypted)
        except ValueError:
            return None
            
    def encrypt_message(self, message: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt a message using AES-GCM"""
        cipher = AES.new(key, AES.MODE_GCM)
        encrypted = cipher.encrypt(message)
        return encrypted, cipher.nonce
        
    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        try:
            data = conn.recv(MAX_MESSAGE_SIZE)
            if not data:
                return
                
            try:
                request = json.loads(data.decode())
                process_id = request['process_id']
                session_key = bytes.fromhex(request['session_key'])
                
                # Verify the client has a valid session key
                with self.auth_server.lock:
                    stored_key, exp_time = self.auth_server.process_keys.get(process_id, (None, 0))
                    if not stored_key or not hmac.compare_digest(session_key, stored_key) or exp_time < time.time():
                        conn.sendall(json.dumps({'status': 'unauthorized'}).encode())
                        return
                
                action = request['action']
                
                if action == 'publish':
                    encrypted = bytes.fromhex(request['encrypted'])
                    iv = bytes.fromhex(request['iv'])
                    mac = bytes.fromhex(request['mac'])
                    
                    # Verify and decrypt message
                    if not self.verify_message(encrypted, mac, session_key):
                        conn.sendall(json.dumps({'status': 'integrity_check_failed'}).encode())
                        return
                        
                    decrypted = self.decrypt_message(encrypted, iv, session_key)
                    if not decrypted:
                        conn.sendall(json.dumps({'status': 'decryption_failed'}).encode())
                        return
                        
                    message_data = json.loads(decrypted.decode())
                    channel = message_data['channel']
                    message = message_data['message']
                    
                    # Broadcast to subscribers
                    with self.lock:
                        subscribers = self.subscriptions.get(channel, [])
                        for sub_conn in subscribers:
                            try:
                                # Re-encrypt for each subscriber with their own key
                                encrypted_msg, iv = self.encrypt_message(
                                    json.dumps({
                                        'channel': channel,
                                        'message': message,
                                        'sender': process_id
                                    }).encode(),
                                    session_key
                                )
                                mac = hmac.new(session_key, encrypted_msg, hashlib.sha256).digest()
                                
                                sub_conn.sendall(json.dumps({
                                    'encrypted': encrypted_msg.hex(),
                                    'iv': iv.hex(),
                                    'mac': mac.hex()
                                }).encode())
                            except (ConnectionError, OSError):
                                # Remove dead connections
                                subscribers.remove(sub_conn)
                                
                    conn.sendall(json.dumps({'status': 'published'}).encode())
                    
                elif action == 'subscribe':
                    channel = request['channel']
                    with self.lock:
                        if channel not in self.subscriptions:
                            self.subscriptions[channel] = []
                        self.subscriptions[channel].append(conn)
                    # Keep connection open for pub/sub
                    return
                    
                else:
                    conn.sendall(json.dumps({'status': 'invalid_action'}).encode())
                    
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                conn.sendall(json.dumps({'status': 'invalid_request'}).encode())
                
        except ConnectionError:
            # Remove connection from all subscriptions
            with self.lock:
                for channel, subscribers in self.subscriptions.items():
                    if conn in subscribers:
                        subscribers.remove(conn)
        finally:
            conn.close()
            
    def start_server(self):
        """Start the message broker"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', BROKER_PORT))
            s.listen()
            print(f"Message broker listening on port {BROKER_PORT}")
            
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

class SecureIPCClient:
    def __init__(self, process_id: str):
        self.process_id = process_id
        self.session_key: Optional[bytes] = None
        self.auth_token = hmac.new(INITIAL_SHARED_SECRET, process_id.encode(), hashlib.sha256).digest()
        
    def authenticate(self) -> bool:
        """Authenticate with the authentication server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', AUTH_SERVER_PORT))
                request = {
                    'process_id': self.process_id,
                    'auth_token': self.auth_token.hex()
                }
                s.sendall(json.dumps(request).encode())
                
                response = json.loads(s.recv(MAX_MESSAGE_SIZE).decode())
                if response.get('status') == 'success':
                    self.session_key = bytes.fromhex(response['session_key'])
                    return True
        except (ConnectionError, ValueError, KeyError):
            pass
        return False
        
    def encrypt_message(self, message: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt a message and generate HMAC"""
        cipher = AES.new(self.session_key, AES.MODE_GCM)
        encrypted = cipher.encrypt(message)
        mac = hmac.new(self.session_key, encrypted, hashlib.sha256).digest()
        return encrypted, cipher.nonce, mac
        
    def publish(self, channel: str, message: str) -> bool:
        """Publish a message to a channel"""
        if not self.session_key:
            if not self.authenticate():
                return False
                
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', BROKER_PORT))
                
                # Prepare and encrypt the message
                message_data = json.dumps({
                    'channel': channel,
                    'message': message
                }).encode()
                
                encrypted, iv, mac = self.encrypt_message(message_data)
                
                request = {
                    'process_id': self.process_id,
                    'session_key': self.session_key.hex(),
                    'action': 'publish',
                    'encrypted': encrypted.hex(),
                    'iv': iv.hex(),
                    'mac': mac.hex()
                }
                
                s.sendall(json.dumps(request).encode())
                response = json.loads(s.recv(MAX_MESSAGE_SIZE).decode())
                return response.get('status') == 'published'
        except (ConnectionError, json.JSONDecodeError, KeyError):
            return False
            
    def subscribe(self, channel: str, callback: callable) -> bool:
        """Subscribe to a channel and receive messages"""
        if not self.session_key:
            if not self.authenticate():
                return False
                
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', BROKER_PORT))
            
            # Send subscription request
            request = {
                'process_id': self.process_id,
                'session_key': self.session_key.hex(),
                'action': 'subscribe',
                'channel': channel
            }
            s.sendall(json.dumps(request).encode())
            
            # Start listener thread
            def listener():
                while True:
                    try:
                        data = s.recv(MAX_MESSAGE_SIZE)
                        if not data:
                            break
                            
                        message = json.loads(data.decode())
                        encrypted = bytes.fromhex(message['encrypted'])
                        iv = bytes.fromhex(message['iv'])
                        mac = bytes.fromhex(message['mac'])
                        
                        # Verify and decrypt
                        if not hmac.compare_digest(
                            mac,
                            hmac.new(self.session_key, encrypted, hashlib.sha256).digest()
                        ):
                            print("Integrity check failed on received message")
                            continue
                            
                        decrypted = AES.new(self.session_key, AES.MODE_GCM, nonce=iv).decrypt(encrypted)
                        message_data = json.loads(decrypted.decode())
                        callback(message_data['channel'], message_data['message'], message_data['sender'])
                    except (ConnectionError, json.JSONDecodeError, ValueError, KeyError):
                        break
                        
            threading.Thread(target=listener, daemon=True).start()
            return True
        except ConnectionError:
            return False

# Example usage
if __name__ == "__main__":
    import time
    
    # Start servers in separate threads
    auth_server = AuthenticationServer()
    broker = MessageBroker(auth_server)
    
    threading.Thread(target=auth_server.start_server, daemon=True).start()
    threading.Thread(target=broker.start_server, daemon=True).start()
    
    # Give servers time to start
    time.sleep(0.5)
    
    # Example process 1 - Publisher
    def publisher_process():
        client = SecureIPCClient("publisher1")
        if not client.authenticate():
            print("Publisher failed to authenticate")
            return
            
        for i in range(5):
            message = f"Hello from publisher! Message #{i+1}"
            if client.publish("test_channel", message):
                print(f"Published: {message}")
            else:
                print("Failed to publish message")
            time.sleep(1)
    
    # Example process 2 - Subscriber
    def subscriber_process():
        def message_handler(channel, message, sender):
            print(f"Received on {channel} from {sender}: {message}")
            
        client = SecureIPCClient("subscriber1")
        if client.subscribe("test_channel", message_handler):
            print("Subscriber successfully subscribed")
            # Keep process alive to receive messages
            time.sleep(10)
        else:
            print("Failed to subscribe")
    
    # Run the example processes
    threading.Thread(target=publisher_process).start()
    threading.Thread(target=subscriber_process).start()