import socket
import sys
import threading


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Error determining local IP: {e}")
        sys.exit(1)


class DistanceVectorRouting:
    def __init__(self, topology_file):
        self.topology_file = topology_file
        self.server_id = None
        self.ip = None
        self.port = None
        self.server_details = {}
        self.connections = {}
        self.stop_event = threading.Event()

    def parse_topology_file(self):
        try:
            with open(self.topology_file, 'r') as file:
                lines = file.readlines()
                num_servers = int(lines[0].strip())

                # Parse server details
                for i in range(2, 2 + num_servers):
                    server_id, server_ip, server_port = lines[i].strip().split()
                    self.server_details[int(server_id)] = (server_ip, int(server_port))

                # Determine this server's ID based on its IP
                local_ip = get_local_ip()
                for server_id, (server_ip, server_port) in self.server_details.items():
                    if server_ip == local_ip:
                        self.server_id = server_id
                        self.ip = server_ip
                        self.port = server_port
                        break

                if self.server_id is None:
                    raise ValueError(f"Local IP {local_ip} does not match any server in the topology file.")

                print(f"Parsed server details: {self.server_details}")
                print(f"Local server ID: {self.server_id}, IP: {self.ip}, Port: {self.port}")
        except Exception as e:
            print(f"Error parsing topology file: {e}")
            sys.exit(1)

    def setup_server_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5)
            print(f"Server started at {self.ip}:{self.port}, waiting for connections...")
        except Exception as e:
            print(f"Error setting up server socket: {e}")
            sys.exit(1)

    def accept_connections(self):
        while not self.stop_event.is_set():
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"New connection from {client_address}")
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
            except socket.error:
                if self.stop_event.is_set():
                    break
                print("Error accepting connections.")

    def connect_to_neighbors(self):
        for neighbor_id, (neighbor_ip, neighbor_port) in self.server_details.items():
            if neighbor_id != self.server_id:  # Avoid connecting to self
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((neighbor_ip, neighbor_port))
                    self.connections[neighbor_id] = client_socket
                    print(f"Connected to neighbor {neighbor_id} at {neighbor_ip}:{neighbor_port}")
                except Exception as e:
                    print(f"Error connecting to neighbor {neighbor_id}: {e}")

    def handle_client(self, client_socket):
        try:
            while not self.stop_event.is_set():
                message = client_socket.recv(1024).decode()
                if not message:
                    break
                print(f"Message received: {message}")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def start_server(self):
        self.setup_server_socket()

        threading.Thread(target=self.accept_connections, daemon=True).start()
        self.connect_to_neighbors()

        try:
            while True:
                pass
        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        print("Shutting down server...")
        self.stop_event.set()
        for neighbor_id, conn in self.connections.items():
            conn.close()
        self.server_socket.close()
        print("Server shut down successfully.")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "-t":
        print("Usage: python dv.py -t <topology-file-name>")
        sys.exit(1)

    topology_file = sys.argv[2]
    server = DistanceVectorRouting(topology_file)
    server.parse_topology_file()
    server.start_server()
