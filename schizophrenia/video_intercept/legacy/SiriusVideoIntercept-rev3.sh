#!/bin/bash
# Dynamic Drone Video Stream Redirector
#
# This script is designed to intercept a UDP video stream from a drone 
# and redirect it to a local ffplay viewer.
#
# USAGE: sudo ./sirius_dynamic_video_redirector.sh <DRONE_VIDEO_PORT>
# Example: sudo ./sirius_dynamic_video_redirector.sh 9000
#
# PREREQUISITES: tshark, socat, ffplay must be installed.

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
    
    local tshark_output
    tshark_output=$(tshark -i "$MON_INTERFACE" -f "udp port $DRONE_PORT" -c 1 -T fields -e ip.src -e ip.dst 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$tshark_output" ]; then
        echo -e "\n[ERROR] Failed to run tshark. Check if 'tshark' is installed and your interface '$MON_INTERFACE' is active."
        exit 1
    fi

    local processed_output=$(echo -e "$tshark_output" | tr '[:space:]' ' ' | sed 's/  */ /g' | xargs)
    read DRONE_IP PHONE_IP <<< "$processed_output"

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
    
    # CORRECTED socat command: 
    # This now only forwards the stream to the local FFplay port (12345).
    # It adheres to the required 2-address format for UDP-LISTEN with fork.
    echo "[INFO] Starting socat listener (PID: $$) to intercept stream..."
    
    # Source Address (Listener): UDP-LISTEN on $DRONE_PORT, bound to $PHONE_IP, with forking for raw payload delivery
    # Target Address: UDP stream sent to localhost on the FFplay port
    socat UDP-LISTEN:$DRONE_PORT,bind=$PHONE_IP,fork UDP:127.0.0.1:$FF_LISTEN_PORT &
    SOCAT_PID=$!
    
    echo "[INFO] Redirection running (socat PID: $SOCAT_PID). Press Ctrl+C to stop."
    echo "[WARNING] The phone's video feed may break as the stream is no longer being actively forwarded back."
}

start_viewer() {
    echo -e "\n--- Step 3: Local Video Viewer (ffplay) ---"
    echo "[ACTION] Starting ffplay viewer..."
    
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
    echo "Example: sudo $0 9000"
    exit 1
fi
DRONE_PORT="$1"
echo "[INFO] Using monitor interface: $MON_INTERFACE"
echo "[INFO] Using DRONE_PORT (from drone): $DRONE_PORT"
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
