import argparse
import subprocess
import shlex
import sys
import time

# --- Configuration Constants ---
# TShark command arguments to extract the raw packet payload
# -i <interface>: Specifies the network interface (e.g., wlan0mon)
# -f <filter>: Captures only UDP traffic to the specified port
# -T fields: Sets the output format to fields
# -e data.text: Extracts the raw data payload as hexadecimal text
# -l: Flush output immediately
TSHARK_CMD_TEMPLATE = 'sudo tshark -i {} -f "udp port {}" -T fields -e data.text -l'
MAX_RETRIES = 5

def stream_payload_data(interface, port):
    """
    Runs TShark as a subprocess and continuously streams the raw hexadecimal
    payload data of packets matching the interface and UDP port filter.
    """
    print(f"--- Starting TShark Stream ---")
    print(f"Interface: {interface}")
    print(f"Filter Port: {port}")
    print(f"Ensure your drone video stream is active now.")
    print(f"------------------------------")
    print("Streaming payload data (raw hex output)...")

    # Construct the full TShark command
    full_command = TSHARK_CMD_TEMPLATE.format(interface, port)
    
    # shlex.split safely handles the command and its arguments
    command_parts = shlex.split(full_command)

    # Use a retry loop to handle potential errors like "no such device"
    for attempt in range(MAX_RETRIES):
        try:
            # Start the TShark subprocess
            process = subprocess.Popen(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, # Capture errors
                text=True,              # Decode output as text
                bufsize=1               # Line buffering
            )
            
            # Read and print the output line by line in real-time
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break # Process terminated
                if line:
                    # Strip newline/whitespace and print the raw hex payload
                    print(line.strip())

            # If the loop breaks, check if the process exited cleanly
            exit_code = process.wait()
            if exit_code != 0:
                stderr_output = process.stderr.read()
                print(f"\n[ERROR] TShark process exited with code {exit_code}.", file=sys.stderr)
                print(f"TShark Error Output:\n{stderr_output}", file=sys.stderr)
            
            # If we reached here, the process terminated, break the retry loop
            break 

        except FileNotFoundError:
            print("\n[CRITICAL ERROR] tshark command not found. Ensure Wireshark/TShark is installed.", file=sys.stderr)
            return
        except PermissionError:
            print("\n[CRITICAL ERROR] Permission denied. Did you forget to run with 'sudo'?", file=sys.stderr)
            return
        except Exception as e:
            print(f"\n[Error] Attempt {attempt + 1}/{MAX_RETRIES} failed: {e}", file=sys.stderr)
            time.sleep(2)
            if attempt == MAX_RETRIES - 1:
                print("\n[Fatal] Failed to start TShark after multiple attempts. Exiting.", file=sys.stderr)
                return

def main():
    """Main function to parse arguments and start the streaming."""
    parser = argparse.ArgumentParser(
        description="Stream raw UDP video payload data using TShark in monitor mode."
    )
    # Changed to use -i shorthand and made it required
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help="The monitor mode interface (e.g., wlan0mon)."
    )
    # Changed to use -p shorthand and made it required (no default value)
    parser.add_argument(
        '-p', '--port',
        type=int,
        required=True,
        help="The UDP port number where the video stream is currently running (e.g., 38009)."
    )

    args = parser.parse_args()
    stream_payload_data(args.interface, args.port)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStream stopped by user. Goodbye!")

# Example usage:
#   sudo python3 tshark_video_streamer.py -i wlan0mon -p 38009