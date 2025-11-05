import socket
import binascii
import time

# --- Configuration ---
# NOTE: YOU MUST CHANGE THIS IP ADDRESS! 
# Drones often use an address like 192.168.1.1 or 192.168.10.1.
# Check your drone's documentation or the connection settings of your phone.
DRONE_IP = '192.168.169.1' 

DRONE_PORT = 8800 # The specific port for heartbeat/command data
PAYLOAD_HEX = (
    "ef02580002020001000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000032"
    "4b142d0000"
)

# ---------------------

def send_udp_command(ip, port, hex_data, Loop):
    """
    Converts a hexadecimal string to raw bytes and sends it via a UDP socket.
    """
    try:
        # 1. Convert the hex string into raw bytes
        # The unhexlify function converts 'ff' to b'\xff'
        raw_bytes = binascii.unhexlify(hex_data)
        
        print(f"Prepared payload size: {len(raw_bytes)} bytes")
        print(f"Sending to {ip}:{port}...")

        # 2. Create a UDP socket (AF_INET for IPv4, SOCK_DGRAM for UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 3. Send the data to the target IP and Port
        # sendto returns the number of bytes sent
        if Loop:
            number_sent = 0
            try:
                while True:
                    bytes_sent = sock.sendto(raw_bytes, (ip, port))
                    print(f"[{number_sent}] Success! Sent {bytes_sent} bytes to the drone.")
                    print(f"Payload (first 20 bytes): {raw_bytes[:20].hex()}")
                    number_sent += 1
                    time.sleep(0.01)
            except KeyboardInterrupt as e:
                print(e)
                print("CTRL+C detected.")
                print("Gracefull exit, closing connection...")
                sock.close()
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                print("Gracefull exit, closing connection...")
                sock.close()
                    
        else:
            bytes_sent = sock.sendto(raw_bytes, (ip, port))
            
            sock.close()
            
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

if __name__ == "__main__":
    loop_yn = input("[?] Send packet in loop? (y/N): ")
    print()
    if loop_yn.casefold() == "y" or loop_yn.casefold() == "yes":
        send_udp_command(DRONE_IP, DRONE_PORT, PAYLOAD_HEX, True)
    else:
        send_udp_command(DRONE_IP, DRONE_PORT, PAYLOAD_HEX, False)
