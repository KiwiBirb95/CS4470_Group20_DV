import socket
import sys
import threading
import struct  # Library for message formatting
import time


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
        self.link_costs = {}  # Link costs between servers, (host server id, destination server id) : cost
        self.routing_table = []  # array containing dict entries: ip, port, server_id, cost

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

                # Determine this server's ID based on its IP
                local_ip = get_local_ip()
                for server_id, (server_ip, server_port) in self.server_details.items():
                    if server_ip == local_ip:
                        self.server_id = server_id
                        self.ip = server_ip
                        self.port = server_port
                        break
                for i in range(2, 2 + num_servers):
                    server_id, server_ip, server_port = lines[i].strip().split()
                    if int(server_id) != int(self.server_id):
                        self.routing_table.append(
                            {"server_ip": server_ip, 'server_port': int(server_port), "server_id": int(server_id)})
                    # Initialize link costs between servers
                for i in range(counter, len(lines)):
                    source_id, destination_id, cost = lines[i].strip().split()
                    self.link_costs[(int(source_id), int(destination_id))] = int(cost)
                    for index, d in enumerate(self.routing_table):
                        if int(d.get('server_id')) == int(destination_id):
                            print("123")
                            self.routing_table[index]['cost'] = float(cost)
                #print(self.link_costs)
                #print(self.routing_table)
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

    def send_update(self, num_entries, routing_table):
        message = struct.pack('<H H 4s', num_entries, self.port, socket.inet_aton(self.ip))
        for entry in routing_table:
            server_ip_n = entry['server_ip']
            server_port_n = entry['server_port']
            server_id_n = entry['server_id']
            cost_n = entry['cost']
            message += struct.pack('<4s H H H', socket.inet_aton(server_ip_n), server_port_n, server_id_n, cost_n)

    def periodic_update(self):
        while not self.stop_event.is_set():
            try:
                self.send_update()
                time.sleep(10)
            except Exception as e:
                print(f"Error during periodic update: {e}")

    def handle_incoming_messages(self):
        while not self.stop_event.is_set():
            try:
                message, addr = self.server_socket.recvfrom(1024)
                message = message.decode()
                print(f"Received routing update from {addr}: {message}")
                self.apply_bellman_ford(message)
            except Exception as e:
                print(f"Error handling incoming message: {e}")

    def initialise_routing_table(self):
        for server_id in self.server_details.keys():
            if server_id in self.server_id:
                self.routing_table[server_id] = (server_id, 0)
            elif (self.server_id, server_id) in self.link_costs:
                self.routing_table[server_id] = (server_id, 0)
            else:
                self.routing_table[server_id] = (None, float('inf'))
        print("fInitial routing table: {self.routing_table}")

    def apply_bellman_ford(self, received_routing_table):
        updated = False
        sender_id = received_routing_table['server_id']
        sender_table = received_routing_table['routing_table']

        for dest_id, (next_hop, cost) in sender_table.items():
            if dest_id not in self.routing_table:
                self.routing_table[dest_id] = (sender_id, cost + self.link_costs[(self.server_id, sender_id)])
                updated = True
            else:
                current_cost = self.routing_table[dest_id][1]
                new_cost = cost + self.link_costs[(self.server_id, sender_id)]
                if new_cost < current_cost:
                    self.routing_table[dest_id] = (sender_id, new_cost)
                    updated = True

        if updated:
            print(f"Routing table updated: {self.routing_table}")

    def handle_display(self):
        print("Routing Table:")
        for dest_id, (next_hop, cost) in sorted(self.routing_table.items()):
            cost_str = "inf" if cost == float('inf') else str(cost)
            next_hop_str = "-" if next_hop is None else str(next_hop)
            print(f"{dest_id}: {next_hop_str} {cost_str}")

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
