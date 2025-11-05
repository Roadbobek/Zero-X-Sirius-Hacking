import socket
import sys
import subprocess
import time

# --- Configuration ---
# Based on analysis of the drone's UDP packets
HEADER_SIZE = 50 
LISTEN_IP = '0.0.0.0' # Listen on all interfaces

# The command to launch FFplay and read raw H.264 data from standard input (pipe:0)
# -f h264: forces raw H.264 demuxer
# -i pipe:0: reads input from stdin
# -window_title: gives the window a name
FFPLAY_COMMAND = ['ffplay', '-f', 'h264', '-i', 'pipe:0', '-window_title', 'Drone Video Feed', '-an', '-vcodec', 'h264']
# Note: '-an' skips audio, '-vcodec h264' explicitly sets the decoder.
# You might need to adjust this command if 'ffplay' isn't found or for latency.

# Install FFmped on Kali Linux:
# sudo apt update && sudo apt install ffmpeg -y


# --- Utility Functions ---

def capture_and_display(listen_port):
    """
    Sets up the UDP listener, launches ffplay, and pipes video data to it.
    """
    # 1. Start FFplay process
    try:
        ffplay_proc = subprocess.Popen(
            FFPLAY_COMMAND, 
            stdin=subprocess.PIPE, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        print("FFplay process launched successfully.")
    except FileNotFoundError:
        print("\n[ERROR] 'ffplay' command not found.")
        print("Please ensure FFmpeg is installed and 'ffplay' is in your system PATH.")
        return

    # 2. Setup UDP Socket
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Reuse address is helpful if the socket was recently closed
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        
        # We need to bind to the port *the phone is listening on* to intercept 
        # the broadcast packets in monitor mode.
        sock.bind((LISTEN_IP, listen_port))
        
        print("-" * 60)
        print(f"UDP Listener Active on {LISTEN_IP}:{listen_port}")
        print(f"**REMINDER: Ensure your Wi-Fi is in MONITOR MODE!**")
        print("Start the drone video feed now. Close the FFplay window or press CTRL+C to stop.")
        print("-" * 60)

        # 3. Main Capture Loop
        while ffplay_proc.poll() is None: # Loop while ffplay is still running
            try:
                # Receive up to 2048 bytes of data
                # Timeout is used so we can check if ffplay is still alive
                sock.settimeout(0.5) 
                data, addr = sock.recvfrom(2048)
                
                # Check for minimum length and strip header
                if len(data) > HEADER_SIZE:
                    video_payload = data[HEADER_SIZE:]
                    
                    # Pipe the clean video data directly to ffplay's stdin
                    ffplay_proc.stdin.write(video_payload)
                
            except socket.timeout:
                # Timeout is expected if no data is received
                continue 
            
            except KeyboardInterrupt:
                break
                
    except KeyboardInterrupt:
        pass # Handled in the finally block
    except OSError as e:
        print(f"\n[ERROR] Failed to bind to port {listen_port}.")
        print("Ensure the port is correct and no other application (like the original app) is running.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
    # 4. Cleanup
    finally:
        print("\nStopping capture...")
        if sock:
            sock.close()
            print("UDP Socket closed.")
        
        if ffplay_proc and ffplay_proc.poll() is None:
            # Terminate ffplay gracefully
            ffplay_proc.stdin.close()
            ffplay_proc.terminate()
            ffplay_proc.wait(timeout=2)
            print("FFplay process terminated.")

# --- Execution ---

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python realtime_interceptor.py <target_port>")
        print("\nExample (from your Wireshark trace: 1234 > 42604):")
        print("python realtime_interceptor.py 42604")
        sys.exit(1)

    try:
        port = int(sys.argv[1])
        capture_and_display(port)
    except ValueError:
        print(f"Error: Port '{sys.argv[1]}' must be a valid number.")
        sys.exit(1)
