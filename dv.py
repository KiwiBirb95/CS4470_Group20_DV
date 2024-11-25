import socket
import threading
import time
import sys
import struct
import json

def get_local_ip():
    """
    Retrieves the local IP address by connecting to an external server (Google's DNS).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to Google's public DNS server
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]  # Get the local IP address
    except Exception as e:
        print(f"Error determining local IP: {e}")
        sys.exit(1)

class DistanceVectorRouting:
    def __init__(self, topology_file, update_interval):
        self.topology_file = topology_file
        self.update_interval = update_interval
        self.server_socket = None
        self.server_id = None
        self.server_ip = None
        self.server_port = None
        self.neighbors = {}
        self.routing_table = {}
        self.stop_event = threading.Event()

    def parse_topology_file(self):
        try:
            with open(self.topology_file, 'r') as file:
                lines = file.readlines()
                if len(lines) < 2:
                    raise ValueError("Invalid topology file format. Must contain at least two lines.")

                # Parse the number of servers and neighbors
                num_servers, num_neighbors = map(int, lines[0].strip().split())

                # Parse server details
                self.server_details = {}
                for i in range(1, 1 + num_servers):
                    server_id, server_ip, server_port = lines[i].strip().split()
                    self.server_details[int(server_id)] = (server_ip, int(server_port))

                # Determine this server's ID based on its real IP
                local_ip = get_local_ip()
                for server_id, (server_ip, server_port) in self.server_details.items():
                    if server_ip == local_ip:
                        self.server_id = server_id
                        self.server_ip = server_ip
                        self.server_port = server_port
                        break

                if self.server_id is None:
                    raise ValueError(f"Local IP {local_ip} not found in the topology file.")

                # Parse neighbor information
                self.neighbors = {}
                for i in range(1 + num_servers, len(lines)):
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

                print("Topology file parsed successfully.")
                print(f"Server ID: {self.server_id}")
                print(f"Neighbors: {self.neighbors}")
                print(f"Routing Table: {self.routing_table}")

        except Exception as e:
            print(f"Error reading topology file: {e}")
            sys.exit(1)

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        print(f"Server started at {self.server_ip}:{self.server_port}, waiting for messages...")

        threading.Thread(target=self.listen_for_updates, daemon=True).start()
        threading.Thread(target=self.periodic_update, daemon=True).start()

    def listen_for_updates(self):
        while not self.stop_event.is_set():
            try:
                message, addr = self.server_socket.recvfrom(1024)
                self.process_incoming_update(message, addr)
            except Exception as e:
                print(f"Error receiving message: {e}")

    def process_incoming_update(self, message, addr):
        try:
            header, data = message[:8], message[8:]
            num_fields, sender_port, sender_ip = struct.unpack('!HH4s', header)
            sender_ip = socket.inet_ntoa(sender_ip)

            if (sender_ip, sender_port) not in self.server_details.values():
                print(f"Invalid sender {addr}. Ignoring.")
                return

            parsed_table = json.loads(data.decode())
            self.update_routing_table(parsed_table, sender_ip, sender_port)
        except Exception as e:
            print(f"Error processing update: {e}")

    def update_routing_table(self, parsed_table, sender_ip, sender_port):
        sender_id = next(
            (id_ for id_, (ip, port) in self.server_details.items() if ip == sender_ip and port == sender_port),
            None
        )
        if sender_id is None:
            print(f"Could not determine sender ID for {sender_ip}:{sender_port}")
            return

        updated = False
        for dest_id, (next_hop, cost) in parsed_table.items():
            new_cost = self.neighbors[sender_id] + cost
            if new_cost < self.routing_table[dest_id][1]:
                self.routing_table[dest_id] = (sender_id, new_cost)
                updated = True

        if updated:
            print(f"Routing table updated at Server {self.server_id}: {self.routing_table}")

    def periodic_update(self):
        while not self.stop_event.is_set():
            self.send_update()
            time.sleep(self.update_interval)

    def send_update(self):
        try:
            routing_data = json.dumps(self.routing_table).encode()
            header = struct.pack('!HH4s', len(self.routing_table), self.server_port, socket.inet_aton(self.server_ip))
            packet = header + routing_data

            for neighbor_id, (neighbor_ip, neighbor_port) in self.server_details.items():
                if neighbor_id in self.neighbors:
                    self.server_socket.sendto(packet, (neighbor_ip, neighbor_port))
                    print(f"Routing update sent to server {neighbor_id}.")
        except Exception as e:
            print(f"Error sending update: {e}")

    def shutdown(self):
        self.stop_event.set()
        self.server_socket.close()
        print("Server has shut down.")
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 5 or sys.argv[1] != "-t" or sys.argv[3] != "-i":
        print("Usage: python dv.py -t <topology-file> -i <update-interval>")
        sys.exit(1)

    topology_file = sys.argv[2]
    update_interval = int(sys.argv[4])

    dv_routing = DistanceVectorRouting(topology_file, update_interval)
    dv_routing.parse_topology_file()
    dv_routing.start_server()
