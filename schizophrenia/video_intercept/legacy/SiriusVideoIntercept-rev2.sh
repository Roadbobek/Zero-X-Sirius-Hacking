#!/bin/bash
# Dynamic Drone Video Stream Redirector
#
# This script is designed to intercept a UDP video stream from a drone 
# (which typically broadcasts to the controller/phone) and simultaneously
# redirect it to a local netcat port (for the viewer) and back to the 
# phone/controller.
#
# It automatically detects the DRONE_IP and PHONE_IP using 'tshark' 
# by monitoring traffic on the specified port, which is provided as an argument.
#
# PREREQUISITES:
# 1. 'tshark' must be installed and in your PATH.
# 2. 'socat' must be installed (used for parallel redirection).
# 3. 'ffplay' (from FFmpeg) must be installed.
# 4. The monitoring interface (MON_INTERFACE) must be active (e.g., using airmon-ng).

# --- Configuration Variables (Hardcoded, non-changing) ---

MON_INTERFACE="wlan0mon"   # <-- REQUIRED: Your active monitor interface name
FF_CODEC="h264"            # <-- The video codec used by the drone (often h264)
FF_LISTEN_PORT="12345"     # <-- The local UDP port for ffplay to listen on

# Variables set at runtime
DRONE_PORT=""              # Set by command-line argument $1
DRONE_IP=""
PHONE_IP=""

# --- Core Functions ---

cleanup() {
    echo -e "\n\n[INFO] Killing background processes..."
    # Kill the socat process (The main redirection tool)
    kill -9 $SOCAT_PID 2>/dev/null
    # Kill the ffplay process (The viewer)
    kill -9 $FFPLAY_PID 2>/dev/null
    # Kill the tcpdump process if it's running (used to keep traffic flowing)
    kill -9 $TCPDUMP_PID 2>/dev/null
    exit 0
}

# Trap signals (Ctrl+C, termination) for clean exit
trap cleanup SIGINT SIGTERM

detect_ips() {
    echo -e "\n--- Step 1: Dynamic IP Discovery ---"
    echo "[INFO] Scanning interface $MON_INTERFACE for the first UDP packet on port $DRONE_PORT..."
    echo "[ACTION] Please START the drone video stream on your controller/phone NOW."
    
    # Run tshark to capture exactly 1 packet matching the UDP port, extracting source/destination IPs.
    local tshark_output
    # tshark will output two IPs separated by a tab: [Source IP]\t[Destination IP]
    tshark_output=$(tshark -i "$MON_INTERFACE" -f "udp port $DRONE_PORT" -c 1 -T fields -e ip.src -e ip.dst 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$tshark_output" ]; then
        echo -e "\n[ERROR] Failed to run tshark. Check if 'tshark' is installed and your interface '$MON_INTERFACE' is active."
        echo "[HINT] You might need to run the script with 'sudo' or check network permissions."
        exit 1
    fi

    # Process the output: tshark uses tabs, so we convert the tab to a space for easy reading.
    local processed_output=$(echo -e "$tshark_output" | tr '[:space:]' ' ' | sed 's/  */ /g' | xargs)

    # Read the two IPs into the dynamic variables
    # Assuming the drone is the source and the phone is the destination.
    read DRONE_IP PHONE_IP <<< "$processed_output"

    # Minimal validation
    if [[ ! "$DRONE_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "\n[ERROR] Could not extract valid DRONE IP. Output was: '$processed_output'"
        exit 1
    fi

    echo -e "\n[SUCCESS] IP Discovery Complete!"
    echo "  DRONE (Source) IP: $DRONE_IP"
    echo "  PHONE (Destination) IP: $PHONE_IP"
}

start_redirection() {
    echo -e "\n--- Step 2: Stream Redirection (socat) ---"
    
    # socat command:
    # 1. Listen on the drone's port ($DRONE_PORT) on the phone's IP ($PHONE_IP).
    # 2. Redirect the incoming stream to two places (using FORK):
    #    a) The FFplay listener port ($FF_LISTEN_PORT) on localhost (127.0.0.1).
    #    b) Back to the original phone's IP/port ($PHONE_IP:$DRONE_PORT) to maintain the original connection.
    echo "[ACTION] Starting socat redirector... (PID: $$)"
    socat UDP-LISTEN:$DRONE_PORT,bind=$PHONE_IP,fork UDP:127.0.0.1:$FF_LISTEN_PORT UDP:$PHONE_IP:$DRONE_PORT &
    SOCAT_PID=$!
    
    echo "[INFO] Redirection running (socat PID: $SOCAT_PID). Press Ctrl+C to stop."
}

start_viewer() {
    echo -e "\n--- Step 3: Local Video Viewer (ffplay) ---"
    echo "[ACTION] Starting ffplay viewer..."

    # ffplay command:
    # -i: Input stream
    # -analyzeduration 1000: Speed up analysis (quick start)
    
    ffplay -i udp://127.0.0.1:$FF_LISTEN_PORT?fifo_size=1000000\&overrun_nonfatal=1 \
        -analyzeduration 1000 -probesize 32 -flags low_delay -framedrop \
        -vcodec "$FF_CODEC" \
        -loglevel quiet -window_title "Drone Stream Viewer" &
    FFPLAY_PID=$!
    
    echo "[INFO] ffplay viewer started (PID: $FFPLAY_PID)."
    echo "--------------------------------------------------------"
    echo "VIEWER WINDOW SHOULD APPEAR SHORTLY. PRESS 'q' IN VIEWER OR Ctrl+C HERE TO EXIT."
}

# --- Main Execution ---

# 1. Handle command-line argument for DRONE_PORT
if [ -z "$1" ]; then
    echo "ERROR: Missing required DRONE_VIDEO_PORT."
    echo "Usage: $0 <DRONE_VIDEO_PORT>"
    echo "Example: sudo $0 10000"
    exit 1
fi
DRONE_PORT="$1"
echo "[INFO] Using monitor interface: $MON_INTERFACE"
echo "[INFO] Using DRONE_PORT: $DRONE_PORT"
echo "[INFO] Local FFplay listening on port: $FF_LISTEN_PORT"

# 2. Check for required tools
for tool in tshark socat ffplay; do
    if ! command -v $tool &> /dev/null; then
        echo "[ERROR] Required tool '$tool' not found. Please install it (e.g., sudo apt install $tool)."
        exit 1
    fi
done

# 3. Dynamically find IPs
detect_ips

# 4. Start redirection (runs in background)
start_redirection

# 5. Start video viewer (runs in background)
start_viewer

# 6. Keep the script running to catch Ctrl+C
wait $SOCAT_PID
