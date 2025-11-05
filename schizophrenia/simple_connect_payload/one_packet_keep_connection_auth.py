import socket
import binascii
import time

# --- Configuration ---
# NOTE: YOU MUST CHANGE THIS IP ADDRESS! 
# Drones often use an address like 192.168.1.1 or 192.168.10.1.
# Check your drone's documentation or the connection settings of your phone.
DRONE_IP = '192.168.169.1' 

DRONE_PORT = 8800 # The specific port for video/command data
PAYLOAD_HEX = (
    "ef02580002020001000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000032"
    "4b142d0000"
)

# ---------------------

if __name__ == "__main__":
    # Send singular packet.
    """
    Converts a hexadecimal string to raw bytes and sends it via a UDP socket.
    """
    try:
        # 1. Convert the hex string into raw bytes
        # The unhexlify function converts 'ff' to b'\xff'
        raw_bytes = binascii.unhexlify(PAYLOAD_HEX)
        
        print(f"Prepared payload size: {len(raw_bytes)} bytes")
        print(f"Sending to {DRONE_IP}:{DRONE_PORT}...")

        # 2. Create a UDP socket (AF_INET for IPv4, SOCK_DGRAM for UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 3. Send the data to the target IP and Port
        # sendto returns the number of bytes sent
        bytes_sent = sock.sendto(raw_bytes, (DRONE_IP, DRONE_PORT))
        
        print(f"Success! Sent {bytes_sent} bytes to the drone.")
        print(f"Payload (first 20 bytes): {raw_bytes[:20].hex()}")
        print()
        
    except binascii.Error as e:
        print(f"Error converting hex data: Invalid hexadecimal string. {e}")
    except socket.error as e:
        print(f"Socket error: Could not send data. Check if the drone is connected and the IP is correct.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    # Check for user input then close connection / port.
    while True:
        exit = input("[?] Close connection? (ENTER): ")
        sock.close()
        print("Connection closed, port disconnected.")
        break
