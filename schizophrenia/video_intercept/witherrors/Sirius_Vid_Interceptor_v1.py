import subprocess
import argparse
import sys

def parse_args():
    """Parses command line arguments for interface and port."""
    parser = argparse.ArgumentParser(
        description="Run TShark with elevated privileges to stream raw UDP packet payloads to Python, bypassing firewall issues.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--interface',
        '-i',
        required=True,
        help="The network interface to listen on (e.g., wlan0mon)."
    )
    parser.add_argument(
        '--port',
        '-p',
        type=int,
        required=True,
        help="The destination UDP port number to capture (e.g., 57840)."
    )
    return parser.parse_args()

def process_tshark_output(interface: str, port: int):
    """
    Executes TShark with elevated privileges and streams its output into Python.
    """
    
    # TShark Command Breakdown:
    # 1. sudo tshark: Run TShark as root to access the network interface directly.
    # 2. -i {interface}: Specifies the network interface.
    # 3. -f "udp port {port}": Capture filter to only listen for UDP packets on the specified port.
    # 4. -T fields: Output results as field values (machine readable).
    # 5. -e data.text: Extract the raw payload data as a hexadecimal text string.
    # 6. -l: Line buffer output (CRUCIAL for real-time streaming to Python).
    
    TSHARK_CMD = [
        'sudo', 'tshark',
        '-i', interface,
        '-f', f'udp port {port}',
        '-T', 'fields',
        '-e', 'data.text',
        '-l'
    ]

    print(f"[*] Starting TShark sniffer on interface '{interface}' for UDP port {port}...")
    print("    You will be prompted for your system password (required for TShark/sudo).")
    print("    Press Ctrl+C to stop the sniffer.\n")

    process = None
    try:
        # Start the TShark process and capture its stdout stream
        process = subprocess.Popen(
            TSHARK_CMD,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True  # Decode output as text
        )

        # Loop forever, reading lines of output from TShark
        for line in process.stdout:
            payload_hex = line.strip()
            
            if payload_hex:
                # Convert the payload data from hex string (from tshark) to bytes
                try:
                    # Example of payload_hex: '68656c6c6f20776f726c64'
                    payload_bytes = bytes.fromhex(payload_hex)
                    
                    # --- PROCESSING STEP ---
                    # This is where your application-specific logic would go.
                    print("-" * 30)
                    print(f"[+] Captured {len(payload_bytes)} bytes")
                    
                    # Attempt to decode as ASCII for general viewing
                    try:
                        decoded_text = payload_bytes.decode('ascii', errors='replace')
                        if all(c in '0123456789abcdefABCDEF' for c in decoded_text):
                            print(f"[+] Raw Hex: {payload_hex}")
                        else:
                            print(f"[+] Decoded Text: {decoded_text}")
                    except UnicodeDecodeError:
                        print(f"[+] Raw Hex: {payload_hex}")


                except ValueError:
                    # TShark might occasionally output status lines or non-hex data
                    print(f"[*] Received non-data TShark output: {line.strip()}")

        # If the TShark process exits unexpectedly
        process.wait()
        print(f"\n[!] TShark process exited with return code: {process.returncode}")

    except FileNotFoundError:
        print("[!!!] ERROR: 'tshark' command not found. Please ensure Wireshark/TShark is installed and in your system PATH.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[i] Sniffer stopped by user (Ctrl+C).")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
    finally:
        # Ensure the TShark process is terminated when the Python script finishes
        if process and process.poll() is None:
            process.terminate()
            print("[i] TShark process terminated.")


if __name__ == "__main__":
    args = parse_args()
    process_tshark_output(args.interface, args.port)
    
# Example usage:
#   python3 tshark_sniffer.py --interface wlan0mon --port 57840
