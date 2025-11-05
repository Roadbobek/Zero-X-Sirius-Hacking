import socket
import sys
import time

# --- Configuration ---
# The target port where the drone is sending video data (port 57840 for the Sirius drone)
UDP_PORT = 57840 
# Listen on all available network interfaces
LISTEN_HOST = '0.0.0.0'
# The maximum number of packets to listen for before stopping
MAX_PACKETS = 10
# --- End Configuration ---

print(f"--- Python UDP Packet Listener ---")
print(f"Attempting to bind to {LISTEN_HOST}:{UDP_PORT}...")

# Create a UDP socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set a timeout so we don't hang forever
    sock.settimeout(5) 
    # Allow address reuse (crucial if the port was recently used)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind the socket to the host and port
    sock.bind((LISTEN_HOST, UDP_PORT))
    
    print(f"\nSUCCESS: Socket bound to port {UDP_PORT}. Waiting for drone packets...")
    print("----------------------------------------------------------------------")
    print("Remember to start the drone's video stream (or arm the drone) now.")
    print("Press Ctrl+C to stop listening.")
    
except socket.error as e:
    print(f"\nFATAL ERROR: Could not bind socket. This usually means the port is already in use (E.g., by the sirius script).")
    print(f"Details: {e}")
    sys.exit(1)

packets_received = 0
start_time = time.time()

while packets_received < MAX_PACKETS:
    try:
        # Try to receive data (up to 65507 bytes, which is the max UDP payload size)
        data, addr = sock.recvfrom(65507) 
        
        packets_received += 1
        elapsed = time.time() - start_time
        
        # We only print the first few packets to confirm arrival, then summarize.
        if packets_received <= 3:
            print(f"Packet {packets_received}: Received {len(data)} bytes from {addr[0]} (Port: {addr[1]})")

        if packets_received == MAX_PACKETS:
            break
            
    except socket.timeout:
        if packets_received == 0:
            print("\nTIMEOUT: No packets received within 5 seconds.")
            print("Action: Ensure the drone is connected to the Access Point and the video stream is active.")
        else:
            # If we received some packets but timed out before reaching MAX_PACKETS
            print("\nTIMEOUT: Stream seems to have stopped.")
        break
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"\nAn unexpected error occurred during reception: {e}")
        break

# --- Summary ---
print("\n=====================================================================")
if packets_received > 0:
    print(f"** DIAGNOSIS COMPLETE: PACKETS ARE ARRIVING! **")
    print(f"Total packets received: {packets_received} in {elapsed:.2f} seconds.")
    print(f"This confirms that the data is reaching your Linux machine.")
else:
    print("** DIAGNOSIS COMPLETE: NO PACKETS RECEIVED. **")
    print("The data is NOT reaching your Linux machine.")
print("=====================================================================")

sock.close()
