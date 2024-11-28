# Distance Vector Routing Implementation Report

## 1. Overview
This implementation provides a distributed distance vector routing protocol using TCP connections between nodes. The system supports dynamic route updates, neighbor monitoring, and handles network topology changes gracefully.

## 2. Key Data Structures

### 2.1 Update Message Structure
Location: dv.py, lines 196-208 (parse_message method)
```python
# Message format:
# Header (8 bytes):
#   - Number of entries (2 bytes, unsigned short)
#   - Sender port (2 bytes, unsigned short)
#   - Sender IP (4 bytes)
# For each entry (12 bytes):
#   - Server IP (4 bytes)
#   - Server port (2 bytes, unsigned short)
#   - Server ID (2 bytes, unsigned short)
#   - Cost (4 bytes, float)
```

### 2.2 Routing Table Structure
Location: dv.py, line 26 (DistanceVectorRouting class initialization)
```python
self.routing_table = {}  # Format: {destination_id: (next_hop, cost)}
```
- Key: destination_id (integer)
- Value: Tuple containing (next_hop, cost)
  - next_hop: ID of the next server in the path (or None if unreachable)
  - cost: Float representing the path cost (float('inf') for unreachable destinations)

## 3. Core Components

### 3.1 Network Setup
- The server initializes by parsing a topology file (lines 31-107)
- Creates TCP connections with neighbors (lines 145-156)
- Uses threading for concurrent handling of:
  - Connection acceptance
  - Periodic updates
  - Neighbor monitoring
  - Command processing

### 3.2 Distance Vector Algorithm Implementation
Location: dv.py, lines 392-434 (apply_bellman_ford method)

Key features:
1. Thread-safe updates using routing_table_lock
2. Considers all possible paths through neighbors
3. Updates routes only when finding better paths
4. Implements split horizon with poison reverse
5. Triggers updates to neighbors when routes change

### 3.3 Neighbor Monitoring
Location: dv.py, lines 518-568 (monitor_neighbors method)

Features:
- Uses a three-stage monitoring system:
  1. Grace period (3 × update interval)
  2. Warning threshold (2 missed updates)
  3. Critical threshold (4 missed updates)
- Implements automatic failover to alternate paths
- Handles complete network isolation scenarios

## 4. Command Interface

The implementation supports the following commands:

1. update (lines 284-295)
   - Updates link costs between servers
   - Triggers routing table updates

2. step (lines 287-289)
   - Forces immediate routing update broadcast

3. packets (lines 571-574)
   - Displays and resets packet counter

4. display (lines 476-495)
   - Shows current routing table state

5. disable (lines 576-601)
   - Simulates link failure to specified neighbor

6. crash (lines 297-316)
   - Graceful server shutdown

## 5. Error Handling and Recovery

### 5.1 Connection Management
- Implements graceful connection closure
- Handles unexpected disconnections
- Maintains partial connectivity when possible

### 5.2 Message Processing
- Validates message formats
- Handles malformed updates
- Implements thread-safe operations

### 5.3 Topology Changes
- Dynamically updates routing on link failures
- Attempts to find alternate paths
- Handles network partitioning

## 6. Performance Considerations

1. Thread Safety
   - Uses locks for routing table access
   - Prevents race conditions during updates

2. Memory Management
   - Efficient data structures for routing table
   - Proper cleanup of closed connections

3. Network Efficiency
   - Sends updates only when needed
   - Implements triggered updates

## 7. Limitations and Potential Improvements

1. Scalability
   - Current implementation might face challenges with large networks
   - Could benefit from hierarchical routing

2. Security
   - No authentication mechanism
   - No encryption for routing updates

3. Performance
   - Could implement route aggregation
   - Might benefit from more efficient update messaging

## 8. Testing

The implementation can be tested using the provided topology file:
```
4       # Number of servers
3       # Number of neighbors
1 192.168.0.229 6000
2 192.168.0.237 6001
3 192.168.0.168 6002
4 192.168.0.134 6003
1 2 1
1 3 2
1 4 4
2 3 3
2 4 2
3 4 1
```

This creates a network of 4 nodes with various link costs, allowing testing of all implemented features.
