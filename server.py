import socket
import ssl

HOST = "localhost"
PORT = 8080

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server = ssl.wrap_socket(server, server_side=True, keyfile="key.pem", certfile="root.crt")
    server.bind((HOST, PORT))
    server.listen(0)
    print(f"listening on port {PORT}")
    while True:
        connection, client_address = server.accept()
        while True:
            data = connection.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode('utf-8')}")