import socket
import binascii
import time

# --- Configuration ---
DRONE_IP = '192.168.169.1'
DRONE_PORT = 8800 
# Note: Source IP/Port 192.168.169.2:59377 is NOT specified here. 
# The OS will choose the source port automatically, as the explicit bind failed.

# EMERGENCY STOP COMMAND PAYLOAD
PAYLOAD_HEX = (
    "ef025800020200010000000036000000140066147e808080020200000000000000000000fe99000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)

# ---------------------

def send_udp_command(ip, port, hex_data, loop):
    """
    Converts a hexadecimal string to raw bytes and sends it via a UDP socket 
    to the target IP and Port.
    """
    try:
        # 1. Convert the hex string into raw bytes
        raw_bytes = binascii.unhexlify(hex_data)
        print(f"--- Sending Emergency Stop Command to {ip}:{port} ---")
        print(f"Payload Length: {len(raw_bytes)} bytes")
        print(f"Payload (Hex): {hex_data[:120]}...") # Print first 60 bytes of hex

        # 2. Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 3. Send loop
        if loop:
            number_sent = 0
            try:
                while True:
                    # Send the data to the target IP and Port
                    bytes_sent = sock.sendto(raw_bytes, (ip, port))
                    print(f"[{number_sent + 1}/?]: E-Stop packet sent ({bytes_sent} bytes).")
                    number_sent += 1
                    time.sleep(0.01) # Send every 10 milliseconds
            except KeyboardInterrupt:
                print("\nCTRL+C detected. Gracefully closing connection.")
            finally:
                sock.close()
        
        # 4. Single send
        else:
            bytes_sent = sock.sendto(raw_bytes, (ip, port))
            print(f"1/1: E-Stop packet sent successfully. ({bytes_sent} bytes)")
            sock.close()
            
    except binascii.Error as e:
        print(f"Error converting hex data: Invalid hexadecimal string. {e}")
    except socket.error as e:
        print(f"Socket error: Could not send data. Check if the drone is connected and the IP is correct.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Remove the bind attempt and just confirm if the E-Stop worked
    loop_yn = input("[?] Send packet in loop? (Y/n): ")
    print()
    
    # Emergency Stop packets are often sent rapidly in a loop by apps, so default to 'Y'
    should_loop = loop_yn.casefold() in ("", "y", "yes")
    
    send_udp_command(DRONE_IP, DRONE_PORT, PAYLOAD_HEX, should_loop)

    print("Socket closed.")
