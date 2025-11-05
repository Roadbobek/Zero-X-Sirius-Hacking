import socket
import binascii
import time
import struct

# --- Configuration ---
DRONE_IP = '192.168.169.1'
DRONE_PORT = 8800

# The 128-byte template payload for connection/heartbeat
# Checksum is static: 324b142d
PAYLOAD_HEX_TEMPLATE = (
    "ef02580002020001000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000032"
    "4b142d0000"
)

# Static Checksum bytes (4 bytes)
STATIC_CHECKSUM_BYTES = binascii.unhexlify("324b142d")

# --- Placeholder for Checksum Logic ---
# THIS FUNCTION MUST BE REPLACED when you determine the actual algorithm.
def calculate_checksum(data: bytearray) -> bytes:
    """
    Placeholder: returns the static checksum. 
    In a real scenario, this would calculate a new 4-byte CRC or XOR sum 
    over the first 122 bytes of 'data' and return those 4 bytes.
    """
    # For now, we return the checksum calculated for the original template
    return STATIC_CHECKSUM_BYTES

# ---------------------

def send_udp_command(ip, port, hex_template):
    """
    Continuously sends a command packet with an INCREMENTING sequence number.
    """
    
    try:
        raw_bytes_template = bytearray(binascii.unhexlify(hex_template))
    except binascii.Error as e:
        print(f"Error converting hex data: Invalid hexadecimal string. {e}")
        return

    print(f"Prepared payload size: {len(raw_bytes_template)} bytes")
    print(f"Sending to {ip}:{port}...")

    sock = None
    # Initialize the sequence number based on the template (0001 in this case)
    sequence_number = int(hex_template[12:16], 16) 

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("Looping payload send with INCREMENTING SEQUENCE (press CTRL+C to stop)...")
        
        while True:
            # 1. Update Sequence Counter (Bytes 7-8, index 6-7)
            # '>H' = Big-Endian Unsigned Short (2 bytes)
            seq_bytes = struct.pack('>H', sequence_number)
            raw_bytes_template[6:8] = seq_bytes
            
            # 2. Update Checksum (Bytes 123-126, index 122-125)
            # The function currently returns the static value, but is ready to be replaced.
            checksum_bytes = calculate_checksum(raw_bytes_template[:122]) 
            raw_bytes_template[122:126] = checksum_bytes
            
            # 3. Send the modified data
            bytes_sent = sock.sendto(raw_bytes_template, (ip, port))
            
            print(f"[{sequence_number:05d}] Sent {bytes_sent} bytes. Seq: {seq_bytes.hex()} | Chksum: {checksum_bytes.hex()}")
            
            # 4. Prepare for the next loop
            sequence_number += 1
            if sequence_number > 65535: # Prevent overflow (2-byte counter)
                sequence_number = 1
                
            time.sleep(0.01) # Send every 10 milliseconds

    except KeyboardInterrupt:
        print("\n\n--- CTRL+C Detected. Exiting Loop. ---")
    except socket.error as e:
        print(f"Socket error: Could not send data. Check connection and IP. Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
    finally:
        if sock:
            print("Closing UDP socket.")
            sock.close()


if __name__ == "__main__":
    send_udp_command(DRONE_IP, DRONE_PORT, PAYLOAD_HEX_TEMPLATE)
