#!/usr/bin/env python3
"""
Simple Plain Text Chat Server for Testing Chatterbox Compatibility
This simulates a basic P2P chat app that uses plain text messages
"""
import socket
import threading
import time

class SimpleChatServer:
    def __init__(self, port=41235):
        self.port = port
        self.clients = []
        self.running = True
        
    def handle_client(self, client_socket, address):
        """Handle a client connection"""
        print(f"New connection from {address}")
        self.clients.append(client_socket)
        
        try:
            while self.running:
                # Receive message
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                message = data.decode('utf-8', errors='ignore')
                print(f"Received from {address}: {message}")
                
                # Echo back with a prefix
                response = f"Echo: {message}"
                client_socket.send(response.encode('utf-8'))
                
                # Send some test messages
                if "hello" in message.lower():
                    time.sleep(1)
                    test_msg = "This is a plain text message from a basic chat app!"
                    client_socket.send(test_msg.encode('utf-8'))
                    time.sleep(2)
                    test_msg2 = "Your app should show security warnings for these messages."
                    client_socket.send(test_msg2.encode('utf-8'))
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()
            print(f"Connection closed: {address}")
    
    def start(self):
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', self.port))
        server_socket.listen(5)
        
        print(f"Simple Chat Server listening on port {self.port}")
        print("Connect from Chatterbox using 127.0.0.1 to test unverified connections")
        
        try:
            while self.running:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            self.running = False
            server_socket.close()

if __name__ == "__main__":
    server = SimpleChatServer()
    server.start()