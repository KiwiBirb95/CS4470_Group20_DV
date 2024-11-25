import os
import socket
import json
import threading
import time
from typing import Dict, List, Tuple
import struct
import sys

def get_public_ip():
    """Get public-facing IP by connecting to Google's DNS."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception as e:
        print(f"Error getting IP address: {e}")
        sys.exit(1)

class DVRouter:
    def __init__(self, topology_file: str, update_interval: int):
        self.topology_file = topology_file
        self.update_interval = update_interval
        self.server_id = None
        self.ip = None
        self.port = None
        self.num_servers = 0
        self.num_neighbors = 0
        self.neighbors = {}  # {server_id: (ip, port, cost)}
        self.routing_table = {}  # {dest_id: (next_hop_id, cost)}
        self.servers = {}  # {server_id: (ip, port)}
        self.packets_received = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True
        self.last_update = {}  # {neighbor_id: last_update_time}

    def read_topology(self):
        """Read and parse the topology file according to PDF specifications."""
        try:
            with open(self.topology_file, 'r') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]

            # First line: num_servers
            self.num_servers = int(lines[0])

            # Second line: num_neighbors
            self.num_neighbors = int(lines[1])

            # Find our port first
            our_ip = get_public_ip()

            # Read server information
            current_line = 2
            for i in range(self.num_servers):
                server_id, ip, port = lines[current_line + i].strip().split()
                server_id = int(server_id)
                port = int(port)
                self.servers[server_id] = (ip, port)

                # Set up our server info when we find matching IP
                if ip == our_ip:
                    self.server_id = server_id
                    self.ip = ip
                    self.port = port
                    try:
                        self.sock.bind((ip, port))
                        print(f"Successfully bound to {ip}:{port}")
                    except socket.error as e:
                        print(f"Error binding to {ip}:{port}: {e}")
                        sys.exit(1)

            if not self.server_id:
                print("Error: Could not find my server ID in topology file")
                sys.exit(1)

            print(f"Successfully initialized as Server {self.server_id} ({self.ip}:{self.port})")

            # Initialize routing table with infinity costs
            for server_id in self.servers:
                self.routing_table[server_id] = (None, float('inf'))

            # Set cost to self as 0
            self.routing_table[self.server_id] = (self.server_id, 0)

            # Read neighbor link costs
            current_line += self.num_servers
            neighbors_found = 0

            # Read all link costs and find our neighbors
            while current_line < len(lines):
                line = lines[current_line].strip()
                if not line:
                    break

                src, dst, cost = map(int, line.split())

                # If we're either source or destination, this is our neighbor
                if src == self.server_id:
                    self.neighbors[dst] = (*self.servers[dst], cost)
                    self.routing_table[dst] = (dst, cost)
                    neighbors_found += 1
                elif dst == self.server_id:
                    self.neighbors[src] = (*self.servers[src], cost)
                    self.routing_table[src] = (src, cost)
                    neighbors_found += 1

                current_line += 1

            print(f"Found {neighbors_found} neighbors: {list(self.neighbors.keys())}")

            if neighbors_found != self.num_neighbors:
                print(f"Warning: Expected {self.num_neighbors} neighbors but found {neighbors_found}")

        except Exception as e:
            print(f"Error reading topology file: {e}")
            raise

    def find_my_port(self) -> int:
        """No longer needed as we handle IP matching in read_topology"""
        pass

    def create_update_message(self) -> bytes:
        """Create a distance vector update message."""
        # Message format from PDF:
        # - Number of update fields (2 bytes)
        # - Server port (2 bytes)
        # - Server IP (4 bytes)
        # - For each update:
        #   - Server IP (4 bytes)
        #   - Server port (2 bytes)
        #   - Padding (2 bytes)
        #   - Server ID (2 bytes)
        #   - Cost (2 bytes)

        updates = []
        ip_parts = list(map(int, self.ip.split('.')))

        # Add header
        header = struct.pack('!HH4B',
                             len(self.routing_table),  # num_updates
                             self.port,  # server_port
                             *ip_parts  # server_ip
                             )

        # Add each routing table entry
        for dest_id, (next_hop, cost) in self.routing_table.items():
            dest_ip, dest_port = self.servers[dest_id]
            dest_ip_parts = list(map(int, dest_ip.split('.')))

            update = struct.pack('!4BHxx2H',
                                 *dest_ip_parts,  # server_ip
                                 dest_port,  # server_port
                                 dest_id,  # server_id
                                 int(cost) if cost != float('inf') else 0xFFFF  # cost
                                 )
            updates.append(update)

        return header + b''.join(updates)

    def process_update(self, data: bytes, addr: Tuple[str, int]):
        """Process received distance vector update."""
        try:
            self.packets_received += 1

            # Unpack header
            num_updates = struct.unpack('!H', data[0:2])[0]
            sender_port = struct.unpack('!H', data[2:4])[0]
            sender_ip = '.'.join(map(str, struct.unpack('!4B', data[4:8])))

            # Find sender ID
            sender_id = None
            for sid, (ip, port) in self.servers.items():
                if ip == sender_ip and port == sender_port:
                    sender_id = sid
                    break

            if sender_id is None:
                print(f"DEBUG: Received update from unknown server {sender_ip}:{sender_port}")
                return False

            print(f"RECEIVED A MESSAGE FROM SERVER {sender_id}")
            print(f"\nDEBUG: Processing update from Server {sender_id}")
            print(f"DEBUG: Current routing table before updates:")
            for dest_id, (next_hop, cost) in sorted(self.routing_table.items()):
                cost_str = 'inf' if cost == float('inf') else str(cost)
                print(f"  To {dest_id}: via {next_hop}, cost {cost_str}")

            self.last_update[sender_id] = time.time()

            # Process updates
            changed = False
            offset = 8  # Start after header

            print(f"\nDEBUG: Received {num_updates} updates from Server {sender_id}")

            for update_num in range(num_updates):
                # Unpack update entry
                ip = '.'.join(map(str, struct.unpack('!4B', data[offset:offset + 4])))
                port = struct.unpack('!H', data[offset + 4:offset + 6])[0]
                server_id = struct.unpack('!H', data[offset + 8:offset + 10])[0]
                cost = struct.unpack('!H', data[offset + 10:offset + 12])[0]

                if cost == 0xFFFF:  # Convert back from wire format
                    cost = float('inf')

                print(f"\nDEBUG: Processing update #{update_num + 1}:")
                print(f"  Destination: Server {server_id}")
                print(f"  Advertised cost from Server {sender_id} to {server_id}: {cost}")

                # Apply Bellman-Ford equation
                if server_id != self.server_id:  # Skip updates about ourselves
                    current_cost = self.routing_table[server_id][1]
                    current_next_hop = self.routing_table[server_id][0]
                    path_cost = float('inf') if cost == float('inf') else cost + self.routing_table[sender_id][1]

                    print(f"  Bellman-Ford calculation:")
                    print(f"    Current cost to Server {server_id}: {current_cost}")
                    print(f"    Current next hop: Server {current_next_hop}")
                    print(f"    Cost to Server {sender_id}: {self.routing_table[sender_id][1]}")
                    print(f"    Their cost to Server {server_id}: {cost}")
                    print(f"    Total new path cost: {path_cost}")

                    if path_cost < current_cost:
                        self.routing_table[server_id] = (sender_id, path_cost)
                        changed = True
                        print(
                            f"  >>> UPDATED ROUTE: To Server {server_id} via Server {sender_id}, new cost {path_cost}")
                    else:
                        print("  >>> NO UPDATE: New path is not better than current path")

                offset += 12

            if changed:
                print("\nDEBUG: Final routing table after updates:")
                for dest_id, (next_hop, cost) in sorted(self.routing_table.items()):
                    cost_str = 'inf' if cost == float('inf') else str(cost)
                    print(f"  To {dest_id}: via {next_hop}, cost {cost_str}")
            else:
                print("\nDEBUG: No changes made to routing table")

            return changed

        except Exception as e:
            print(f"Error processing update: {e}")
            import traceback
            traceback.print_exc()
            return False

    def send_updates(self):
        """Send routing updates to all neighbors."""
        message = self.create_update_message()
        for neighbor_id, (ip, port, _) in self.neighbors.items():
            try:
                self.sock.sendto(message, (ip, port))
            except Exception as e:
                print(f"Error sending update to neighbor {neighbor_id}: {e}")

    def receive_updates(self):
        """Listen for and process incoming updates."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if self.process_update(data, addr):
                    # If routing table changed, could trigger update
                    # But per requirements, we only send on interval or step command
                    pass
            except Exception as e:
                if self.running:  # Only print error if we're still meant to be running
                    print(f"Error receiving update: {e}")

    def check_timeouts(self):
        """Check for neighbors that haven't sent updates."""
        while self.running:
            current_time = time.time()
            for neighbor_id in list(self.neighbors.keys()):
                last_update = self.last_update.get(neighbor_id, 0)
                if current_time - last_update > self.update_interval * 3:
                    # Mark link as infinity but keep neighbor
                    self.neighbors[neighbor_id] = (*self.neighbors[neighbor_id][:2], float('inf'))
                    self.routing_table[neighbor_id] = (neighbor_id, float('inf'))
            time.sleep(self.update_interval)

    def periodic_updates(self):
        """Send periodic routing updates."""
        while self.running:
            self.send_updates()
            time.sleep(self.update_interval)

    def start(self):
        """Start the router."""
        self.read_topology()

        # Start receiver thread
        self.receiver_thread = threading.Thread(target=self.receive_updates)
        self.receiver_thread.daemon = True
        self.receiver_thread.start()

        # Start periodic update thread
        self.update_thread = threading.Thread(target=self.periodic_updates)
        self.update_thread.daemon = True
        self.update_thread.start()

        # Start timeout checker thread
        self.timeout_thread = threading.Thread(target=self.check_timeouts)
        self.timeout_thread.daemon = True
        self.timeout_thread.start()

        print(f"Server {self.server_id} starting up...")

        # Handle user commands
        while True:
            try:
                command = input().strip().split()
                if not command:
                    continue

                if command[0] == "update":
                    self.handle_update(command)
                elif command[0] == "step":
                    self.handle_step()
                elif command[0] == "packets":
                    self.handle_packets()
                elif command[0] == "display":
                    self.handle_display()
                elif command[0] == "disable":
                    self.handle_disable(command)
                elif command[0] == "crash":
                    self.handle_crash()
                    break
                else:
                    print(f"{' '.join(command)} ERROR: Invalid command")
            except KeyboardInterrupt:
                self.handle_crash()
                break
            except Exception as e:
                print(f"Error processing command: {e}")

    def handle_update(self, command):
        """Handle update command."""
        if len(command) != 4:
            print("update ERROR: Invalid arguments")
            return

        try:
            server1, server2, cost = command[1:]
            server1, server2 = int(server1), int(server2)
            cost = float('inf') if cost == 'inf' else int(cost)

            if server1 != self.server_id and server2 != self.server_id:
                print("update ERROR: Cannot update link between other servers")
                return

            other_id = server2 if server1 == self.server_id else server1
            if other_id not in self.neighbors:
                print("update ERROR: Server is not a neighbor")
                return

            # Update neighbor cost
            self.neighbors[other_id] = (*self.neighbors[other_id][:2], cost)
            self.routing_table[other_id] = (other_id, cost)
            print("update SUCCESS")

        except ValueError:
            print("update ERROR: Invalid cost value")

    def handle_step(self):
        """Handle step command."""
        self.send_updates()
        print("step SUCCESS")

    def handle_packets(self):
        """Handle packets command."""
        print(f"packets SUCCESS\nNumber of packets received: {self.packets_received}")
        self.packets_received = 0

    def handle_display(self):
        """Handle display command."""
        print("display SUCCESS")
        # Sort by destination ID
        for dest_id in sorted(self.routing_table.keys()):
            next_hop, cost = self.routing_table[dest_id]
            cost_str = 'inf' if cost == float('inf') else str(cost)
            next_hop_str = str(next_hop) if next_hop is not None else 'inf'
            print(f"{dest_id} {next_hop_str} {cost_str}")

    def handle_disable(self, command):
        """Handle disable command."""
        if len(command) != 2:
            print("disable ERROR: Invalid arguments")
            return

        try:
            server_id = int(command[1])
            if server_id not in self.neighbors:
                print("disable ERROR: Server is not a neighbor")
                return

            self.neighbors[server_id] = (*self.neighbors[server_id][:2], float('inf'))
            self.routing_table[server_id] = (server_id, float('inf'))
            print("disable SUCCESS")

        except ValueError:
            print("disable ERROR: Invalid server ID")

    def handle_crash(self):
        """Handle crash command."""
        self.running = False
        self.sock.close()
        print("crash SUCCESS")


def main():
    """
    Main function to handle command line arguments and start the router.
    Format: server -t <topology-file-name> -i <routing-update-interval>
    """
    try:
        # Check correct number of arguments
        if len(sys.argv) != 5:
            print("Usage: python dv.py -t <topology-file-name> -i <routing-update-interval>")
            sys.exit(1)

        # Check correct argument flags
        if sys.argv[1] != '-t' or sys.argv[3] != '-i':
            print("Usage: python dv.py -t <topology-file-name> -i <routing-update-interval>")
            sys.exit(1)

        topology_file = sys.argv[2]

        try:
            update_interval = int(sys.argv[4])
            if update_interval <= 0:
                print("Error: Routing update interval must be positive")
                sys.exit(1)
        except ValueError:
            print("Error: Routing update interval must be an integer")
            sys.exit(1)

        # Check if topology file exists
        if not os.path.exists(topology_file):
            print(f"Error: Topology file '{topology_file}' not found")
            sys.exit(1)

        # Create and start the router
        router = DVRouter(topology_file, update_interval)
        router.start()

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()