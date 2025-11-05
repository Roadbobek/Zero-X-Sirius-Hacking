import socket
import sys

# Configuration
# We use '0.0.0.0' to bind to all available network interfaces (INADDR_ANY).
HOST = '0.0.0.0'
BUFFER_SIZE = 65536  # Standard maximum UDP datagram size

def listen_for_packets():
    """
    Sets up a UDP socket to listen for incoming packets on the specified port, 
    which is read from the command-line arguments.
    """
    
    # 1. Handle command-line argument for the port
    if len(sys.argv) != 2:
        print("Usage: python3 packet_listener.py <PORT_NUMBER>")
        print("Example: python3 packet_listener.py 57840")
        sys.exit(1)

    try:
        # Get the port number from the argument
        PORT = int(sys.argv[1])
        
        # Simple validation for non-reserved ports
        if not (1025 <= PORT <= 65535):
            raise ValueError("Port number must be between 1025 and 65535 (inclusive).")
            
    except ValueError as e:
        print(f"[!] Invalid port argument: {e}")
        print("Usage: python3 packet_listener.py <PORT_NUMBER>")
        sys.exit(1)


    # 2. Setup the socket and listening loop
    try:
        # Create a UDP socket (AF_INET for IPv4, SOCK_DGRAM for UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind the socket to all interfaces and the user-specified port
        sock.bind((HOST, PORT))
        print(f"[*] Successfully bound socket to {HOST}:{PORT}")
        print("[*] Waiting for incoming packets (Ctrl+C to stop)...")

        # Start the listening loop
        while True:
            # Receive data and the address of the sender
            data, addr = sock.recvfrom(BUFFER_SIZE)
            
            # Output packet details
            print("-" * 30)
            print(f"[+] Received packet from: {addr}")
            print(f"[+] Packet size: {len(data)} bytes")
            
            # Decode a small snippet of the data
            try:
                snippet = data[:50].decode('utf-8', errors='ignore').strip()
                print(f"[+] Data snippet (text): '{snippet}'...")
            except Exception:
                # If decoding fails, show a hex representation
                print(f"[+] Data snippet (hex): {data[:50].hex()}...")

    except socket.error as e:
        # Handle the common "Address already in use" error
        if hasattr(e, 'errno') and e.errno == 98: 
            print(f"\n[!] Socket error: Port {PORT} is already in use.")
            print("[!] Please ensure no other process is using this port, or choose a different port number.")
        else:
            print(f"\n[!] Critical Socket Error: {e}")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n[i] Listener stopped by user.")
        
    finally:
        if 'sock' in locals():
            sock.close()
            print("[i] Socket closed.")

if __name__ == "__main__":
    listen_for_packets()
