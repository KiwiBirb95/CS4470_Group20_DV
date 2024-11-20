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
        self.link_costs = {}  # Link costs between servers

    def parse_topology_file(self):
        try:
            with open(self.topology_file, 'r') as file:
                lines = file.readlines()
                num_servers = int(lines[0].strip())
                counter = 2  # For iteration to find and store link cost info
                # Parse server details
                for i in range(2, 2 + num_servers):
                    server_id, server_ip, server_port = lines[i].strip().split()
                    self.server_details[int(server_id)] = (server_ip, int(server_port))
                    counter += 1

                # Initialize link costs between servers
                for i in range(counter, len(lines)):
                    source_id, destination_id, cost = lines[i].strip().split()
                    self.link_costs[(int(source_id), int(destination_id))] = int(cost)
                print(self.link_costs)
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
                threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
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

    def handle_client(self, client_socket, client_address):
        try:
            while not self.stop_event.is_set():
                message = client_socket.recv(1024).decode()
                if not message:
                    break
                for server_id, temp_socket in self.connections.items():
                    if client_address[0] in str(temp_socket):
                        print(f"RECEIVED A MESSAGE FROM SERVER {server_id}")
                parts = message.split()
                if parts[0] == "update":
                    for ids, cost in self.link_costs.items():
                        if int(parts[1]) == ids[0] and int(parts[2]) == ids[1]:
                            self.link_costs[(ids[0], ids[1])] = float(parts[3])
                #print(self.link_costs)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def handle_server(self):  # May or may not need
        pass

    def process_command(self, command):
        parts = command.split()
        if parts[0] == 'update' and len(parts) == 4:
            self.update(parts)
        elif parts[0] == "shutdown":
            self.shutdown()
        else:
            print("Invalid command format")

    def start_server(self):
        self.setup_server_socket()

        threading.Thread(target=self.accept_connections, daemon=True).start()
        self.connect_to_neighbors()

        # Command input loop
        threading.Thread(target=self.command_input_loop, daemon=True).start()

        try:
            while True:
                pass
        except KeyboardInterrupt:
            self.shutdown()

    def command_input_loop(self):
        while not self.stop_event.is_set():
            command = input("Enter command: ")
            self.process_command(command)

    def update(self, parts):
        try:
            server_id1 = int(parts[1])
            server_id2 = int(parts[2])
            new_cost = int(parts[3])

            if (server_id1, server_id2) in self.link_costs:
                # print(self.link_costs)
                self.link_costs[(server_id1, server_id2)] = new_cost
                print(f"Link cost updated: Server {server_id1} <-> Server {server_id2} to {new_cost}")
                # print(self.link_costs)

                # Optionally broadcast the update to neighbors (this step is up to your routing protocol logic)
                for neighbor_id, conn in self.connections.items():
                    try:
                        if neighbor_id == server_id2:
                            update_message = f"update {server_id2} {server_id1} {new_cost}\n"
                            conn.send(update_message.encode())
                            print(f"Send update to neighbor {neighbor_id}")
                    except Exception as e:
                        print(f"Error sending update to neighbor {neighbor_id}: {e}")

            else:
                print(f"No link found between Server {server_id1} and Server {server_id2}")
        except ValueError:
            print("Invalid input. Please use the format: update <server-ID1> <server-ID2> <Link Cost>")

    def shutdown(self):
        print("Shutting down server...")
        self.stop_event.set()
        for neighbor_id, conn in self.connections.items():
            conn.close()
        self.server_socket.close()
        print("Server shut down successfully.")
        sys.exit(0)

    def send_update(self):
        pass

    def periodic_update(self):
        pass

    def handle_incoming_messages(self):
        pass

    def initialise_routing_table(self):
        pass

    def apply_bellman_ford(self):
        pass

    def handle_display(self):
        pass

    def handle_packets(self):
        pass

    def handle_disable(self):
        pass

    def handle_step(self):
        pass

    def handle_crash(self):  # Can be implemented using shutdown()
        pass


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "-t" or sys.argv[3] != "-i" or (
            isinstance(sys.argv[4], int) and sys.argv[4] > 0):
        print("Usage: python dv.py -t <topology-file-name> -i <routing-update-interval>")
        sys.exit(1)

    topology_file = sys.argv[2]
    server = DistanceVectorRouting(topology_file)
    server.parse_topology_file()
    server.start_server()
