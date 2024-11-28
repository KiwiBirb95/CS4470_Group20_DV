import socket
import struct  # Library for message formatting
import sys
import threading
import time


def get_local_ip():
    """
    Retrieve the local IP address of the machine by creating a temporary connection.
    :return: String containing the local IP address
    :raises: SystemExit if unable to determine local IP
    """
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
        """
        Initialize the Distance Vector Routing server with configuration settings.
        :param topology_file: Path to the file containing network topology information
        :param update_interval: Time interval in seconds between routing updates
        :return: None
        """
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
        self.packets = 0

    def parse_topology_file(self):
        """
        Parse the topology configuration file to set up routing information and server details.
        File format:
        Line 1: Number of servers (N)
        Line 2: Number of neighbors
        Lines 3 to N+2: Server ID, IP, and port for each server
        Remaining lines: Server1 Server2 Cost triplets
        :return: None
        :raises: ValueError if topology file format is invalid
        :raises: SystemExit if file cannot be read or parsed
        """
        try:
            with open(self.topology_file, 'r') as file:
                lines = file.readlines()
                if len(lines) < 2:
                    raise ValueError("Invalid topology file format. Must contain at least two lines.")

                # First two lines specify the number of servers and neighbors
                num_servers = int(lines[0].strip())

                # Parse server details (ID, IP, port)
                self.server_details = {}  # Maps server ID -> (IP, port)
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

                # Parse neighbor information (connections and costs)
                self.neighbors = {}  # Maps neighbor server ID -> cost
                for i in range(2 + num_servers, len(lines)):
                    server1, server2, cost = map(int, lines[i].strip().split())
                    if server1 == self.server_id:
                        self.neighbors[server2] = cost
                    elif server2 == self.server_id:
                        self.neighbors[server1] = cost

                # Initialize routing table with (next_hop, cost) for each server
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
        """
        Create and configure the server's TCP socket, binding it to the specified IP and port.
        :return: None
        :raises: SystemExit if socket cannot be created or bound
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5)
            print(f"Server started at {self.ip}:{self.port}, waiting for connections...")
        except Exception as e:
            print(f"Error setting up server socket: {e}")
            sys.exit(1)

    def accept_connections(self):
        """
        Continuously accept incoming TCP connections and spawn new threads to handle them.
        Runs until stop_event is set.
        :return: None
        """
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
        """
        Establish TCP connections to all neighboring servers defined in the topology.
        Stores connections in self. Connections dictionary.
        :return: None
        """
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
        """
        Parse a received routing update message from binary format.
        :param message: Raw binary message received from network
        :return: Tuple containing (num_entries, sender_port, sender_ip, routing_table)
        :raises: Exception if message parsing fails
        """
        try:
            # Unpack the header: number of entries, sender's port, and sender's IP
            num_entries, sender_port, sender_ip = struct.unpack('<H H 4s', message[:8])
            sender_ip = socket.inet_ntoa(sender_ip)  # Convert binary IP to human-readable format

            print(f"Number of update fields: {num_entries}")
            print(f"Server port: {sender_port}")
            print(f"Server IP: {sender_ip}")

            # Unpack the routing table entries
            offset = 8  # Start of routing table entries
            routing_table = {}
            for _ in range(num_entries):
                # Each entry: IP (4 bytes), port (2 bytes), ID (2 bytes), cost (4 bytes)
                server_ip, server_port, server_id, cost = struct.unpack('<4s H H f', message[offset:offset + 12])
                server_ip = socket.inet_ntoa(server_ip)  # Convert binary IP to readable format
                routing_table[server_id] = {
                    'server_ip': server_ip,
                    'server_port': server_port,
                    'cost': cost
                }
                offset += 12  # Move to the next entry
                if sender_ip == server_ip:
                    print(f"RECEIVED AN UPDATE FROM SERVER: {server_id}")
            self.packets += 1  # Increment packet count for received updates
            return num_entries, sender_port, sender_ip, routing_table
        except Exception as e:
            print(f"Error parsing message: {e}")
            raise

    def process_incoming_update(self, message, sender_id):
        """
        Process a routing update message received from a neighboring server.
        :param message: Raw binary message containing routing updates
        :param sender_id: ID of the server that sent the update
        :return: None
        """
        try:
            # Parse the incoming message
            num_entries, sender_port, sender_ip, update_table = self.parse_message(message)

            sender_id = 0
            for id, server_details in update_table.items():
                if server_details['server_port'] == sender_port and server_details['server_ip'] == sender_ip:
                    sender_id = id
            self.apply_bellman_ford(update_table, sender_id)

            # Reset missed updates counter for this neighbor
            with self.routing_table_lock:
                if sender_id in self.missed_updates:
                    self.missed_updates[sender_id] = 0

            print(f"RECEIVED A MESSAGE FROM SERVER {sender_id}")
        except Exception as e:
            print(f"Error processing incoming update: {e}")

    def handle_client(self, client_socket, client_address):
        """
        Handle communication with a connected client, processing received messages.
        :param client_socket: Socket object for the client connection
        :param client_address: Tuple containing (IP, port) of the connected client
        :return: None
        """
        try:
            while not self.stop_event.is_set():
                message = client_socket.recv(4096)
                if not message:
                    break

                # Parse the binary message and process it
                sender_id = 0  # placeholder
                num_entries, sender_port, sender_ip, parsed_table = self.parse_message(message)
                for id, server_details in parsed_table.items():
                    if server_details['server_port'] == sender_port and server_details['server_ip'] == sender_ip:
                        sender_id = id

                # Process the incoming update
                self.process_incoming_update(message, sender_id)
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()

    def process_command(self, command):
        """
        Process a user-entered command and execute the corresponding action.
        Supported commands: update, step, packets, display, disable, crash
        :param command: String containing the command entered by user
        :return: None
        """
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
        """
        Start the routing server and initialize all components including threads for
        connection handling and periodic updates.
        :return: None
        """
        self.setup_server_socket()

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.connect_to_neighbors, daemon=True).start()
        threading.Thread(target=self.periodic_update, args=(self.update_interval,), daemon=True).start()
        threading.Thread(target=self.monitor_neighbors, args=(self.update_interval,), daemon=True).start()

        self.command_input_loop()

    def command_input_loop(self):
        """
        Main loop for processing user input commands until stop_event is set.
        :return: None
        """
        while not self.stop_event.is_set():
            command = input("Enter command: ")
            self.process_command(command)

    def update(self, parts):
        """
        Handle an update command to modify link costs between servers.
        :param parts: List containing command parts [command, server1, server2, cost]
        :return: None
        """
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
        """
        Perform graceful server shutdown by closing all connections and cleaning up resources.
        :return: None
        """
        print("Simulating server shutdown...")
        self.stop_event.set()  # Stop all periodic tasks and monitoring

        # Close all active connections
        for neighbor_id, conn in list(self.connections.items()):
            try:
                conn.close()
            except socket.error as e:
                print(f"Error closing connection with neighbor {neighbor_id}: {e}")
            self.link_costs[(self.server_id, neighbor_id)] = float('inf')
            self.routing_table[neighbor_id] = (None, float('inf'))
        self.connections.clear()  # Clear all active connections

        # Close the server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except socket.error as e:
                print(f"Error closing server socket: {e}")

        print("Server has shut down.")
        sys.exit(0)  # Exit the program

    def send_update(self, num_entries):
        """
        Send routing updates to all connected neighbors.
        :param num_entries: Number of routing table entries to send
        :return: None
        """
        with self.routing_table_lock:
            # Pack the message header: Number of entries, sender's port, sender's IP
            message = struct.pack('<H H 4s', num_entries, self.port, socket.inet_aton(self.ip))

            # Pack each routing table entry (only include reachable destinations)
            for dest_id, (next_hop, cost) in self.routing_table.items():
                if cost != float('inf'):  # Skip unreachable destinations
                    server_ip, server_port = self.server_details[dest_id]
                    message += struct.pack('<4s H H f', socket.inet_aton(server_ip), server_port, dest_id, cost)

        # Send the packed message to all connected neighbors
        for neighbor_id, conn in self.connections.items():
            try:
                conn.send(message)
                print(f"Routing update sent to server {neighbor_id}.")
            except Exception as e:
                print(f"Error sending update to server {neighbor_id}: {e}")

    def periodic_update(self, interval):
        """
        Periodically send routing updates to neighbors at specified intervals.
        :param interval: Time in seconds between updates
        :return: None
        """
        while not self.stop_event.is_set():
            time.sleep(interval)
            num_entries = len(self.routing_table)
            try:
                self.send_update(num_entries)
            except RuntimeError as e:
                print(f"Runtime error during periodic update: {e}")
                break

    def handle_incoming_messages(self):
        """
        Process incoming routing update messages continuously until stop_event is set.
        :return: None
        """
        while not self.stop_event.is_set():
            try:
                message, addr = self.server_socket.recvfrom(4096)  # Receive raw message
                num_entries, sender_port, sender_ip, routing_table = self.parse_message(message)  # Parse message
                sender_id = None

                # Determine sender_id from sender_ip and sender_port
                for server_id, server_details in self.server_details.items():
                    if server_details[0] == sender_ip and server_details[1] == sender_port:
                        sender_id = server_id
                        break

                if sender_id is None:
                    print(f"Error: Could not determine sender ID for {sender_ip}:{sender_port}.")
                    continue

                print(f"Received routing update from {addr}: {routing_table}")

                # Call apply_bellman_ford with parsed routing table and sender_id
                self.apply_bellman_ford(routing_table, sender_id)
            except Exception as e:
                print(f"Error handling incoming message: {e}")

    def initialise_routing_table(self):
        """
        Initialize the routing table with initial routes and costs for all known destinations.
        :return: None
        """
        for server_id in self.server_details.keys():
            if server_id in self.server_id:
                self.routing_table[server_id] = (server_id, 0)
            elif (self.server_id, server_id) in self.link_costs:
                self.routing_table[server_id] = (server_id, 0)
            else:
                self.routing_table[server_id] = (None, float('inf'))
        print("fInitial routing table: {self.routing_table}")

    def apply_bellman_ford(self, received_routing_table, sender_id):
        """
        Apply the Bellman-Ford algorithm to update routing table with new information.
        :param received_routing_table: Dictionary containing routing information from neighbor
        :param sender_id: ID of the server that sent the update
        :return: None
        """
        updated = False
        print(f"\nApplying Bellman-Ford Updates from Server {sender_id}")
        print("-" * 42)
        print(f"{'Dest':^6} | {'Via':^6} | {'Old Cost':^10} | {'New Cost':^10}")
        print("-" * 42)

        with self.routing_table_lock:
            for dest_id, server_details in received_routing_table.items():
                if dest_id == self.server_id:  # Skip entries for this server
                    continue

                # Current route information
                current_next_hop, current_cost = self.routing_table.get(dest_id, (None, float('inf')))

                # Calculate cost through the sender
                cost_through_sender = (self.link_costs.get((self.server_id, sender_id), float('inf'))
                                       + server_details['cost'])

                # Determine the best cost (minimization logic)
                best_cost = min(current_cost, cost_through_sender)
                best_next_hop = sender_id if cost_through_sender < current_cost else current_next_hop

                # Display cost comparisons for debugging
                current_cost_str = "inf" if current_cost == float('inf') else f"{current_cost:.1f}"
                new_cost_str = "inf" if best_cost == float('inf') else f"{best_cost:.1f}"
                print(f"{dest_id:^6} | {sender_id:^6} | {current_cost_str:^10} | {new_cost_str:^10}")

                # Update the routing table if a better path is found
                if best_cost < current_cost:
                    self.routing_table[dest_id] = (best_next_hop, best_cost)
                    updated = True

        print("-" * 42)
        if updated:
            print(f"Routing table updated at Server {self.server_id}:")
            print(f"{'Dest':^6} | {'Next Hop':^10} | {'Cost':^8}")
            print("-" * 42)
            for dest_id, (next_hop, cost) in sorted(self.routing_table.items()):
                cost_str = "inf" if cost == float('inf') else f"{cost:.1f}"
                next_hop_str = "-" if next_hop is None else str(next_hop)
                print(f"{dest_id:^6} | {next_hop_str:^10} | {cost_str:^8}")
            print("-" * 42)
            self.send_update(len(self.routing_table))  # Notify neighbors of updates

    def handle_display(self):
        """
        Display the current routing table showing destinations, next hops, and costs.
        :return: None
        """
        print("Routing Table:")
        with self.routing_table_lock:
            # Sort entries by destination ID for consistent display
            for dest_id in sorted(self.routing_table.keys()):
                next_hop, cost = self.routing_table[dest_id]

                # Format cost for readability (e.g., "inf" or numeric value)
                if cost == float('inf'):
                    cost_str = "inf"
                else:
                    cost_float = float(cost)
                    cost_str = str(int(cost_float)) if cost_float.is_integer() else f"{cost_float}"

                # Format next hop (e.g., "-" for None or numeric value)
                next_hop_str = "-" if next_hop is None else str(next_hop)

                print(f"{dest_id}: {next_hop_str} {cost_str}")
        print("display SUCCESS")

    def monitor_neighbors(self, interval):
        """
        Monitor neighbor connectivity and handle failures using warning and critical thresholds.
        :param interval: Time interval in seconds between connectivity checks
        :return: None
        """
        grace_period = interval * 3  # Wait period before monitoring neighbors
        warning_threshold = 2  # Number of missed updates before warning
        critical_threshold = 4  # Number of missed updates before marking unreachable

        # Wait for the grace period to avoid false positives during initialization
        time.sleep(grace_period)

        while not self.stop_event.is_set():
            time.sleep(interval)  # Periodically check connectivity
            with self.routing_table_lock:
                active_neighbors = set(self.neighbors.keys())  # Track connected neighbors
                warned_neighbors = set()  # Track neighbors that triggered warnings

                for neighbor_id in list(self.missed_updates.keys()):
                    self.missed_updates[neighbor_id] += 1  # Increment missed updates counter

                    # Warning phase
                    if self.missed_updates[neighbor_id] == warning_threshold:
                        print(f"\nWARNING: Server {neighbor_id} may be unreachable")
                        warned_neighbors.add(neighbor_id)

                    # Critical phase: Assume link failure if updates are consistently missed
                    elif self.missed_updates[neighbor_id] >= critical_threshold:
                        if neighbor_id in active_neighbors:
                            # Mark the link as failed
                            active_neighbors.remove(neighbor_id)
                            self.link_costs[(self.server_id, neighbor_id)] = float('inf')
                            self.routing_table[neighbor_id] = (None, float('inf'))
                            print(f"Link to server {neighbor_id} set to infinity due to missed updates.")

                            # Attempt to find alternate paths for destinations via this neighbor
                            self.find_alternate_paths(neighbor_id)

                # Check if all neighbors are unreachable and warn about possible isolation
                if len(active_neighbors) == 0 and len(warned_neighbors) == len(self.neighbors):
                    print("\nCRITICAL: All neighbors are unreachable.")
                    print("Attempting to maintain partial connectivity...")
                    time.sleep(interval * 2)  # Allow extra time for recovery

                    # Final check before concluding isolation
                    if all(self.missed_updates[n] >= critical_threshold for n in self.neighbors):
                        print("No recovery possible. Shutting down server...")
                        self.shutdown()

    def find_alternate_paths(self, failed_server_id):
        """
        Search for alternate paths when a neighbor fails by checking other available routes.
        :param failed_server_id: ID of the server that has failed
        :return: None
        """
        with self.routing_table_lock:
            updated = False
            print("\nSearching for alternate paths:")
            print("-" * 50)

            for dest_id, (next_hop, cost) in list(self.routing_table.items()):
                # Skip if destination is not affected by the failure
                if next_hop != failed_server_id:
                    continue

                min_cost = float('inf')  # Initialize with high cost
                best_next_hop = None  # Placeholder for the best next hop

                # Check all neighbors for alternate paths
                for neighbor_id in self.neighbors:
                    if neighbor_id != failed_server_id:
                        path_cost = self.link_costs.get((self.server_id, neighbor_id), float('inf'))
                        if path_cost < min_cost:
                            min_cost = path_cost
                            best_next_hop = neighbor_id

                # Update routing table if a new path is found
                if best_next_hop is not None:
                    self.routing_table[dest_id] = (best_next_hop, min_cost)
                    print(f"Found new path to {dest_id} via {best_next_hop} cost {min_cost}")
                    updated = True

            # Notify neighbors if any updates were made
            if updated:
                self.send_update(len(self.routing_table))

    def handle_packets(self):
        """
        Display the number of routing update packets received and reset the counter.
        :return: None
        """
        print("packets SUCCESS")
        print(self.packets)
        self.packets = 0

    def handle_disable(self, server_id):
        """
        Disable connection to a specified neighbor by setting link cost to infinity.
        :param server_id: ID of the neighbor server to disable
        :return: None
        """
        try:
            # Verify the server is a neighbor we can disable
            if server_id not in self.neighbors:
                print(f"disable {server_id} ERROR: Not a neighbor")
                return

            with self.routing_table_lock:
                # Update routing information
                self.routing_table[server_id] = (None, float('inf'))
                self.link_costs[(self.server_id, server_id)] = float('inf')
                self.link_costs[(server_id, self.server_id)] = float('inf')

                # Close and remove the connection
                if server_id in self.connections:
                    self.connections[server_id].close()
                    self.connections.pop(server_id)

                # Remove from neighbors but keep in missed_updates
                if server_id in self.neighbors:
                    self.neighbors.pop(server_id)

            print(f"disable {server_id} SUCCESS")
            # Send updates to remaining neighbors
            self.send_update(len(self.routing_table))

        except Exception as e:
            print(f"Error disabling server {server_id}: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "-t" or sys.argv[3] != "-i":
        print("Usage: python dv.py -t <topology-file-name> -i <routing-update-interval>")
        sys.exit(1)

    topology_file = sys.argv[2]
    update_interval = int(sys.argv[4])  # Convert interval to an integer

    # Pass both arguments to the constructor
    server = DistanceVectorRouting(topology_file, update_interval)
    server.parse_topology_file()
    server.start_server()
