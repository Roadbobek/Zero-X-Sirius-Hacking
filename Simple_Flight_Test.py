import socket
import binascii
import time

# --- Configuration ---
DRONE_IP = '192.168.169.1'
DRONE_PORT = 8800 

# The byte change is assumed to be at index 32/33 (0-indexed).
# This is the most likely location for a command ID or function code.

# Command 1: The "FE" variant (Currently acts as Hover/Keep-Alive when looped)
# Test this as a ONE-SHOT command to see if it triggers E-Stop.
FE_PAYLOAD_HEX = (
    "ef025800020200010000000036000000140066147e808080020200000000000000000000fe99000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)

# Command 2: The "FC" variant (The newly discovered payload from Wireshark)
# Test this as a CONTINUOUS heartbeat to see if it is the normal "I'm flying" signal.
FC_PAYLOAD_HEX = (
    "ef025800020200010000000036000000140066147e808080020200000000000000000000fc99000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)

# ---------------------

def send_udp_command(ip, port, hex_data, command_name, send_loop):
    """
    Converts a hexadecimal string to raw bytes and sends it via a UDP socket.
    """
    try:
        raw_bytes = binascii.unhexlify(hex_data)
        print(f"--- Sending '{command_name}' Command to {ip}:{port} ---")
        print(f"Payload Length: {len(raw_bytes)} bytes")
        print(f"Payload (Hex, Key Byte in CAPS): {hex_data[:64]}{hex_data[64:66].upper()}{hex_data[66:120]}...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        if send_loop:
            number_sent = 0
            try:
                print("\nSending continuously (CTRL+C to stop)...")
                while True:
                    bytes_sent = sock.sendto(raw_bytes, (ip, port))
                    # Optionally, you can turn off this print to reduce console spam
                    # print(f"[{number_sent + 1}/?]: Packet sent ({bytes_sent} bytes).")
                    number_sent += 1
                    time.sleep(0.01) # 100 times per second
            except KeyboardInterrupt:
                print(f"\nStopped sending after {number_sent} packets.")
            
        else:
            # Send the packet only once
            bytes_sent = sock.sendto(raw_bytes, (ip, port))
            print(f"1/1: Packet sent successfully. ({bytes_sent} bytes)")
            time.sleep(0.1) # Give it a moment to send
        
        sock.close()
            
    except binascii.Error as e:
        print(f"Error converting hex data: Invalid hexadecimal string. {e}")
    except socket.error as e:
        print(f"Socket error: Could not send data. Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    
    # --- User Selection ---
    print("Select command to test:")
    print("  1) FC Command (Hypothesized Normal Flight/Heartbeat)")
    print("  2) FE Command (Hypothesized E-Stop Command)")
    
    choice = input("Enter choice (1 or 2): ")
    
    if choice == '1':
        payload = FC_PAYLOAD_HEX
        name = "FC_HEARTBEAT"
    elif choice == '2':
        payload = FE_PAYLOAD_HEX
        name = "FE_ESTOP"
    else:
        print("Invalid choice. Exiting.")
        exit()

    loop_yn = input(f"\n[?] Send '{name}' command in a continuous loop? (Y/n): ")
    should_loop = loop_yn.casefold() in ("", "y", "yes")

    print()
    
    send_udp_command(DRONE_IP, DRONE_PORT, payload, name, should_loop)

    print("Socket closed.")
