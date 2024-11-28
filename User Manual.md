# Distance Vector Routing Implementation
## User Manual

### Getting Started

#### System Requirements
- Python 3.6 or higher
- Network connectivity between nodes
- Read/write permissions in the program directory

#### Installation
1. Copy the `dv.py` file to your desired location
2. Ensure you have a valid topology file in the same directory
3. Verify network connectivity between all nodes

### Running the Program

#### Basic Startup
Launch the program using the following command format:
```bash
python dv.py -t <topology-file-name> -i <routing-update-interval>
```

Parameters:
- `-t`: Specifies the topology file path
- `-i`: Sets the routing update interval in seconds

Example:
```bash
python dv.py -t topology.txt -i 5
```

#### Topology File Format
```
<number_of_servers>
<number_of_neighbors>
<server_id> <server_ip> <server_port>
[Additional server entries...]
<server1_id> <server2_id> <link_cost>
[Additional link entries...]
```

Example:
```
4
3
1 192.168.0.229 6000
2 192.168.0.237 6001
3 192.168.0.168 6002
4 192.168.0.134 6003
1 2 1
1 3 2
1 4 4
```

### Available Commands

#### 1. Update Command
Updates the cost of a link between two servers.

Syntax: `update <server1-id> <server2-id> <new-cost>`

Example:
```
Enter command: update 1 2 5
```
- Changes the link cost between servers 1 and 2 to 5
- Only works if your server is one of the endpoints
- Use `inf` or a very large number to simulate link failure

#### 2. Step Command
Forces an immediate routing update broadcast.

Syntax: `step`

Example:
```
Enter command: step
```
- Triggers routing updates to all neighbors
- Useful for testing or verifying route changes

#### 3. Packets Command
Displays the number of routing update packets received.

Syntax: `packets`

Example:
```
Enter command: packets
```
- Shows total packets received since last reset
- Counter resets after display

#### 4. Display Command
Shows the current routing table.

Syntax: `display`

Example:
```
Enter command: display
```
Output format:
```
<destination>: <next-hop> <cost>
```
- `-` indicates no available next hop
- `inf` indicates unreachable destination

#### 5. Disable Command
Simulates a link failure to a specified neighbor.

Syntax: `disable <server-id>`

Example:
```
Enter command: disable 2
```
- Marks the link cost as infinity
- Triggers routing updates to other neighbors
- Cannot be undone without program restart

#### 6. Crash Command
Performs a graceful shutdown of the server.

Syntax: `crash`

Example:
```
Enter command: crash
```
- Closes all connections
- Updates neighbors about unreachability
- Exits the program

### Error Handling

#### Common Error Messages

1. Topology File Errors:
```
Error reading topology file: [error details]
```
- Verify file format and permissions
- Check if all IPs and ports are valid

2. Connection Errors:
```
Error connecting to neighbor [ID]: [error details]
```
- Verify network connectivity
- Check if target server is running

3. Update Command Errors:
```
update ERROR: Invalid input
```
- Verify server IDs exist in topology
- Ensure cost value is numeric

### Best Practices

1. Network Setup
   - Use unique server IDs
   - Ensure all IPs are reachable
   - Use available ports (>1024 for non-root)

2. Operation
   - Monitor neighbor connectivity regularly
   - Use `display` to verify route changes
   - Handle link failures promptly

3. Maintenance
   - Keep topology file updated
   - Monitor packet counts for abnormalities
   - Use `step` to verify updates

### Troubleshooting

#### Unable to Start Server
1. Check port availability
2. Verify IP address in topology file
3. Ensure Python version compatibility

#### Lost Connectivity
1. Use `display` to check routing table
2. Verify physical network connectivity
3. Check for `WARNING` messages in output

#### High Packet Counts
1. Check update interval setting
2. Look for routing loops
3. Verify neighbor stability

### Examples

#### Basic Operation
```bash
# Start server
python dv.py -t topology.txt -i 5

# Check current routes
Enter command: display

# Update link cost
Enter command: update 1 2 3

# Verify changes
Enter command: display
```

#### Handling Failures
```bash
# Disable connection
Enter command: disable 2

# Check routing changes
Enter command: display

# Force update broadcast
Enter command: step

# Check received packets
Enter command: packets
```