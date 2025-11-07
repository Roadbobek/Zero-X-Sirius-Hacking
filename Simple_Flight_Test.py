import socket
import binascii
import time

# --- Configuration ---
DRONE_IP = '192.168.169.1'
DRONE_PORT = 8800
# Note: Source IP/Port 192.168.169.2:59377 is NOT specified here.
# The OS will choose the source port automatically, as the explicit bind failed.

# RANDOM SMALLEST LEN MAX THROTTLE COMMAND PAYLOAD
MAXTHRTL_HEX = (
    "ef028400020200010200000061000000140066148080ff800002000000000000000000007d990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d00005600000000000000010000001c000000ffffffffffffffffffffffff57000000000000000300000010000000"
)

# RANDOM SMALLEST LEN IDLE COMMAND PAYLOAD
IDLE_HEX = (
    "ef02580002020001000000008e000000140066148080808000020000000000000000000002990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)

# RANDOM SMALLEST LEN STOP COMMAND PAYLOAD
STOP_HEX = (
    "ef0258000202000100000000d7000000140066148080808002020000000000000000000000990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)


# ---------------------

def send_udp_command(ip, port, maxthrtl_hex, idle_hex, stop_hex, loop):
    """
    Converts a hexadecimal string to raw bytes and sends it via a UDP socket
    to the target IP and Port.
    """
    try:
        # 1. Convert the hex string into raw bytes
        maxthrtl_hex_raw_bytes = binascii.unhexlify(maxthrtl_hex)
        print(f"--- Sending Max Throttle Stop Command to {ip}:{port} ---")
        print(f"Payload Length: {len(maxthrtl_hex)} bytes")
        print(f"Payload (Hex): {maxthrtl_hex[:120]}...")  # Print first 60 bytes of hex
        print()

        # Convert second hex string to raw bytes
        idle_hex_raw_bytes = binascii.unhexlify(idle_hex)
        print(f"--- Sending Idle Command to {ip}:{port} ---")
        print(f"Payload Length: {len(idle_hex)} bytes")
        print(f"Payload (Hex): {idle_hex[:120]}...")  # Print first 60 bytes of hex
        print()

        # Convert third hex string to raw bytes
        stop_hex_raw_bytes = binascii.unhexlify(stop_hex)
        print(f"--- Sending Stop Command to {ip}:{port} ---")
        print(f"Payload Length: {len(stop_hex)} bytes")
        print(f"Payload (Hex): {stop_hex[:120]}...")  # Print first 60 bytes of hex
        print()

        # 2. Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 3. Send loop
        if loop:
            number_sent = 0
            try:
                while True:
                    # Send the data to the target IP and Port
                    # Send Max Throttle packet to arm
                    bytes_sent = sock.sendto(maxthrtl_hex_raw_bytes, (ip, port))
                    print(f"[{number_sent + 1}/?]: (ARMED) Max Throttle packet sent ({bytes_sent} bytes).")
                    number_sent += 1

                    # Send Idle packet
                    bytes_sent = sock.sendto(idle_hex_raw_bytes, (ip, port))
                    print(f"[{number_sent + 1}/?]: Idle packet sent ({bytes_sent} bytes).")
                    number_sent += 1

                    # Send Max Throttle packet to fly
                    bytes_sent = sock.sendto(maxthrtl_hex_raw_bytes, (ip, port))
                    print(f"[{number_sent + 1}/?]: (FLYING) Max Throttle packet sent ({bytes_sent} bytes).")
                    number_sent += 1

                    # Wait 1 second
                    time.sleep(1)

                    # Send Idle packet
                    bytes_sent = sock.sendto(idle_hex_raw_bytes, (ip, port))
                    print(f"[{number_sent + 1}/?]: Idle packet sent ({bytes_sent} bytes).")
                    number_sent += 1

                    # Wait 3 seconds
                    time.sleep(3)

                    # Send a Stop packet
                    bytes_sent = sock.sendto(stop_hex_raw_bytes, (ip, port))
                    print(f"[{number_sent + 1}/?]: (STOPPED) Stop packet sent ({bytes_sent} bytes).")
                    number_sent += 1

                    # Wait 3 seconds
                    time.sleep(3)

            except KeyboardInterrupt:
                print("\nCTRL+C detected. Gracefully closing connection.")
            finally:
                sock.close()

        # 4. Single send
        else:
            # Send one Full Throttle packet to arm drone
            bytes_sent = sock.sendto(maxthrtl_hex_raw_bytes, (ip, port))
            print(f"1/4: Full Throttle packet sent successfully. ({bytes_sent} bytes)")
            # Now send a Idle packet
            bytes_sent = sock.sendto(idle_hex_raw_bytes, (ip, port))
            print(f"2/4: Idle packet sent successfully. ({bytes_sent} bytes)")
            # Now send second Full Throttle packet to fly
            bytes_sent = sock.sendto(maxthrtl_hex_raw_bytes, (ip, port))
            print(f"3/4: Full Throttle packet sent successfully. ({bytes_sent} bytes)")
            # Wait 2 seconds
            time.sleep(2)
            # Now send a Stop packet
            bytes_sent = sock.sendto(stop_hex_raw_bytes, (ip, port))
            print(f"4/4: Stop packet sent successfully. ({bytes_sent} bytes)")
            # Close connection
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

    send_udp_command(DRONE_IP, DRONE_PORT, MAXTHRTL_HEX, IDLE_HEX, STOP_HEX, should_loop)

    print("Socket closed.")
