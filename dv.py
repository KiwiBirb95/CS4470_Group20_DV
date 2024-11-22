import socket
import struct  # Library for message formatting
import sys
import threading
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
    def __init__(self, topology_file, update_interval):
        self.topology_file = topology_file
        self.update_interval = update_interval
        self.server_id = None
        self.ip = None
        self.port = None
        self.server_details = {}
        self.connections = {}
        self.stop_event = threading.Event()
        self.link_costs = {}
        self.routing_table = {}
        self.routing_table_lock = threading.Lock()
        self.neighbors = {}
        self.server_socket = None
        self.missed_updates = {neighbor_id: 0 for neighbor_id in self.neighbors.keys()}

    def parse_topology_file(self):
        try:
            with open(self.topology_file, 'r') as file:
                lines = file.readlines()
                if len(lines) < 2:
                    raise ValueError("Invalid topology file format. Must contain at least two lines.")

                # First two lines specify the number of servers and neighbors
                num_servers = int(lines[0].strip())
                num_neighbors = int(lines[1].strip())

                # Parse server details
                self.server_details = {}
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

                # Parse neighbor information
                self.neighbors = {}
                for i in range(2 + num_servers, len(lines)):
                    server1, server2, cost = map(int, lines[i].strip().split())
                    if server1 == self.server_id:
                        self.neighbors[server2] = cost
                    elif server2 == self.server_id:
                        self.neighbors[server1] = cost

                # Initialize routing table
                self.routing_table = {}
                for server_id in self.server_details.keys():
                    if server_id == self.server_id:
                        self.routing_table[server_id] = (server_id, 0)  # Cost to self is 0
                    elif server_id in self.neighbors:
                        self.routing_table[server_id] = (server_id, self.neighbors[server_id])  # Direct neighbors
                    else:
                        self.routing_table[server_id] = (None, float('inf'))  # Unreachable initially

                # Initialize missed updates counter for neighbors
                self.missed_updates = {neighbor_id: 0 for neighbor_id in self.neighbors.keys()}

                print("Topology file parsed successfully.")
                print(f"Server ID: {self.server_id}")
                print(f"Neighbors: {self.neighbors}")
                print(f"Routing Table: {self.routing_table}")

        except Exception as e:
            print(f"Error reading topology file: {e}")
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

    def parse_message(self, message):
        try:
            # Unpack the header
            num_entries, sender_port, sender_ip = struct.unpack('<H H 4s', message[:8])
            sender_ip = socket.inet_ntoa(sender_ip)

            # Print the header
            print(f"Number of update fields: {num_entries}")
            print(f"Server port: {sender_port}")
            print(f"Server IP: {sender_ip}")

            # Unpack the routing table entries
            offset = 8
            routing_table = []
            for _ in range(num_entries):
                server_ip, server_port, server_id, cost = struct.unpack('<4s H H f', message[offset:offset + 12])
                server_ip = socket.inet_ntoa(server_ip)
                routing_table.append((server_ip, server_port, server_id, cost))
                offset += 12

            print("Received update:")
            print(f"Number of update fields: {num_entries}")
            print(f"Server port: {sender_port}")
            print(f"Server IP: {sender_ip}")
            # Print each entry
            for entry in routing_table:
                print(f"Routing Table Entry: {entry}")

            return num_entries, sender_port, sender_ip, routing_table
        except Exception as e:
            print(f"Error parsing message: {e}")
            raise

    def process_incoming_update(self, message, sender_id):
        try:
            # Parse the incoming message
            update_data = self.parse_message(message)

            # Apply Bellman-Ford logic to update the routing table
            self.apply_bellman_ford(update_data['routing_table'], sender_id)

            # Reset missed updates counter for this neighbor
            with self.routing_table_lock:
                if sender_id in self.missed_updates:
                    self.missed_updates[sender_id] = 0
            print(f"RECEIVED A MESSAGE FROM SERVER {sender_id}")
        except Exception as e:
            print(f"Error processing incoming update: {e}")

    def handle_client(self, client_socket, client_address):
        try:
            while not self.stop_event.is_set():
                # Receive raw binary data
                message = client_socket.recv(1024)
                if not message:
                    break

                # Parse the binary message and process it
                parsed_data = self.parse_message(message)
                sender_id = parsed_data['server_id']

                # Process the incoming update
                self.process_incoming_update(message, sender_id)
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()

    def process_command(self, command):
        parts = command.split()
        if len(parts) == 0:
            print("No command entered.")
            return

        cmd = parts[0].lower()
        try:
            if cmd == "update" and len(parts) == 4:
                self.update(parts)
            elif cmd == "step":
                self.send_update(len(self.routing_table))
                print("step SUCCESS")
            elif cmd == "packets":
                self.handle_packets()
            elif cmd == "display":
                self.handle_display()
            elif cmd == "disable" and len(parts) == 2:
                server_id = int(parts[1])
                self.handle_disable(server_id)
            elif cmd == "crash":
                self.shutdown()
            else:
                print(
                    f"{command} ERROR: Unknown command. Available commands: update, step, packets, display, disable, "
                    f"crash.")
        except Exception as e:
            print(f"{command} Error handling command: {e}")

    def start_server(self):
        self.setup_server_socket()

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.connect_to_neighbors, daemon=True).start()
        threading.Thread(target=self.periodic_update, args=(self.update_interval,), daemon=True).start()
        threading.Thread(target=self.monitor_neighbors, args=(self.update_interval,), daemon=True).start()

        # Test message parsing (debugging)
        print("Parsing topology and testing message format...")
        num_entries = len(self.routing_table)

        # Debug
        message = struct.pack('<H H 4s', num_entries, self.port, socket.inet_aton(self.ip))
        for dest_id, (next_hop, cost) in self.routing_table.items():
            if cost != float('inf'):  # Skip unreachable destinations
                server_ip, server_port = self.server_details[dest_id]
                message += struct.pack('<4s H H f', socket.inet_aton(server_ip), server_port, dest_id, cost)

        parsed_data = self.parse_message(message)
        print(f"Parsed message: {parsed_data}")

        # Command input loop runs in the main thread to prevent immediate exit
        self.command_input_loop()

    def command_input_loop(self):
        while not self.stop_event.is_set():
            command = input("Enter command: ")
            self.process_command(command)

    def update(self, parts):
        try:
            server_id1, server_id2, link_cost = int(parts[1]), int(parts[2]), float(parts[3])

            # Update the link cost if this server is part of the link
            if self.server_id in (server_id1, server_id2):
                neighbor_id = server_id2 if self.server_id == server_id1 else server_id1
                with self.routing_table_lock:
                    self.link_costs[(self.server_id, neighbor_id)] = link_cost
                    self.routing_table[neighbor_id] = (neighbor_id if link_cost != float('inf') else None, link_cost)
                print(f"update {server_id1} {server_id2} {link_cost} SUCCESS")
                self.send_update(len(self.routing_table))
            else:
                print(f"update {server_id1} {server_id2} ERROR: This server is not part of the link.")
        except ValueError:
            print("update ERROR: Invalid input. Use: update <server-ID1> <server-ID2> <Link Cost>")

    def shutdown(self):
        print("Simulating server shutdown...")
        self.stop_event.set()  # Stop all periodic tasks and monitoring
        for neighbor_id, conn in list(self.connections.items()):
            try:
                conn.close()
            except Exception:
                pass
            self.link_costs[(self.server_id, neighbor_id)] = float('inf')
            self.routing_table[neighbor_id] = (None, float('inf'))
        self.connections.clear()  # Clear all active connections
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        print("Server has shut down.")
        sys.exit(0)  # Exit the program

    def send_update(self, num_entries):
        with self.routing_table_lock:
            # Pack the header: Number of update fields, sender's port, sender's IP
            message = struct.pack('<H H 4s', num_entries, self.port, socket.inet_aton(self.ip))

            # Pack each routing table entry: Server IP, port, ID, cost
            for dest_id, (next_hop, cost) in self.routing_table.items():
                if cost != float('inf'):  # Include only reachable destinations
                    server_ip, server_port = self.server_details[dest_id]
                    message += struct.pack('<4s H H f', socket.inet_aton(server_ip), server_port, dest_id, cost)

        # Debug
        # print(f"Packed message to be sent: {message}")
        print("Sending update:")
        print(f"Number of entries: {num_entries}")
        print(f"Server port: {self.port}")
        print(f"Server IP: {self.ip}")
        # Debug

        for dest_id, (next_hop, cost) in self.routing_table.items():
            print(f"Destination ID: {dest_id}, Next Hop: {next_hop}, Cost: {cost}")

        # Send the packed message to all neighbors
        for neighbor_id, conn in self.connections.items():
            try:
                conn.send(message)
                print(f"Routing update sent to server {neighbor_id}.")
            except Exception as e:
                print(f"Error sending update to server {neighbor_id}: {e}")

    def periodic_update(self, interval):
        while not self.stop_event.is_set():
            time.sleep(interval)
            num_entries = len(self.routing_table)
            try:
                self.send_update(num_entries)
            except RuntimeError as e:
                print(f"Runtime error during periodic update: {e}")
                break

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

    def apply_bellman_ford(self, received_routing_table, sender_id):
        updated = False
        for dest_id, (next_hop, cost) in received_routing_table.items():
            if dest_id == self.server_id:
                continue  # Skip self

            # Calculate the new cost via the sender
            new_cost = self.link_costs.get((self.server_id, sender_id), float('inf')) + cost

            with self.routing_table_lock:
                current_next_hop, current_cost = self.routing_table.get(dest_id, (None, float('inf')))

                if new_cost < current_cost:
                    # Update the routing table with better cost
                    self.routing_table[dest_id] = (sender_id, new_cost)
                    updated = True

        if updated:
            print(f"Routing table updated by applying Bellman-Ford from server {sender_id}.")
            self.send_update(len(self.routing_table))

    def handle_display(self):
        print("Routing Table:")
        with self.routing_table_lock:
            for dest_id in sorted(self.routing_table.keys()):
                next_hop, cost = self.routing_table[dest_id]
                cost_str = "inf" if cost == float('inf') else str(cost)
                next_hop_str = "-" if next_hop is None else str(next_hop)
                print(f"{dest_id}: {next_hop_str} {cost_str}")
        print("display SUCCESS")

    def monitor_neighbors(self, interval):
        time.sleep(interval * 3)  # Grace period: 3 intervals
        while not self.stop_event.is_set():
            time.sleep(interval)
            with self.routing_table_lock:
                all_neighbors_unreachable = True
                for neighbor_id in self.missed_updates.keys():
                    self.missed_updates[neighbor_id] += 1
                    if self.missed_updates[neighbor_id] > 3:  # Missed 3 intervals
                        self.link_costs[(self.server_id, neighbor_id)] = float('inf')
                        self.routing_table[neighbor_id] = (None, float('inf'))
                        print(f"Link to server {neighbor_id} set to infinity due to missed updates.")
                    else:
                        all_neighbors_unreachable = False  # At least one neighbor is reachable

                if all_neighbors_unreachable:
                    print("All neighbors are unreachable. Shutting down server...")
                    self.shutdown()

    def handle_packets(self):
        pass

    def handle_disable(self):
        pass


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "-t" or sys.argv[3] != "-i":
        print("Usage: python dv.py -t <topology-file-name> -i <routing-update-interval>")
        sys.exit(1)

    topology_file = sys.argv[2]
    update_interval = int(sys.argv[4])  # Convert interval to an integer
    print(f"Parsed arguments: Topology file: {topology_file}, Update interval: {update_interval}")  # Debugging line

    # Pass both arguments to the constructor
    server = DistanceVectorRouting(topology_file, update_interval)
    server.parse_topology_file()
    server.start_server()