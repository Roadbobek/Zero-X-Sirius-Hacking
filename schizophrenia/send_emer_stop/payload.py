import socket
import binascii
import time

# --- Configuration ---
# The IP address of the target device (192.168.169.1, the target from the logs)
TARGET_IP = '192.168.169.1'
# The UDP port the target listens on (8800, the target port from the logs)
TARGET_PORT = 8800
# The source port the app used in the log (59377)
# Note: Using 0 lets the OS pick an available port, but we'll try to match the source IP/Port convention.
SOURCE_IP = '192.168.169.2'
SOURCE_PORT = 59377
# The protocol is UDP

# Payload for E-Stop (FE) Status
# This payload is derived from packet #9235 (7.273s) in your log, which has the 33rd byte set to 'fe'.
# ef025800...fe99...324b142d0000
# Offset 33 (0-indexed) is highlighted: ...00000000000000000000000000000000**fe**9900...
# The header length (58) corresponds to 88 bytes.
E_STOP_PAYLOAD_HEX = (
    "ef025800020200010000000036000000140066147e808080020200000000000000000000"
    "fe9900000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000324b142d0000"
)

def send_e_stop_command():
    """Sends the defined E-Stop UDP packet to the target device."""
    try:
        # Convert the hex string payload to bytes
        payload_bytes = binascii.unhexlify(E_STOP_PAYLOAD_HEX)

        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to the source IP and port if possible, matching the log sender
        try:
            sock.bind((SOURCE_IP, SOURCE_PORT))
        except OSError:
            print(f"Warning: Could not bind to {SOURCE_IP}:{SOURCE_PORT}. Using any available port.")
            # If binding fails, create a new socket without binding to let the OS choose
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        print(f"--- Sending Emergency Stop Command to {TARGET_IP}:{TARGET_PORT} ---")
        print(f"Payload Length: {len(payload_bytes)} bytes")
        print(f"Payload (Hex): {E_STOP_PAYLOAD_HEX}")

        # Send the first E-Stop packet
        sock.sendto(payload_bytes, (TARGET_IP, TARGET_PORT))
        print("1/2: E-Stop packet sent successfully.")

        # Wait a small moment, as these packets are often sent in quick succession
        time.sleep(0.05)

        # Send the second E-Stop packet
        sock.sendto(payload_bytes, (TARGET_IP, TARGET_PORT))
        print("2/2: E-Stop packet sent successfully.")

    except binascii.Error as e:
        print(f"Error converting hex data: {e}. Check the hex payload string for invalid characters.")
    except Exception as e:
        print(f"An error occurred during socket operation: {e}")
    finally:
        if 'sock' in locals():
            sock.close()
            print("Socket closed.")

if __name__ == "__main__":
    send_e_stop_command()
