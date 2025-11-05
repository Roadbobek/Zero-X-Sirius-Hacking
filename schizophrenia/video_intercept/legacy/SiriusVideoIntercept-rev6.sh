#!/bin/bash
# Sirius Stream Interceptor (v6 - Final Fix for 'Address already in use')
#
# FIX: Uses 'reuseaddr' and 'reuseport' to share the binding address with the existing
#      Access Point service, which is causing the 'Address already in use' error.
#
# USAGE: sudo ./sirius_dynamic_video_redirector.sh <DRONE_VIDEO_PORT>
# Example: sudo ./sirius_dynamic_video_redirector.sh 57840
#
# PREREQUISITES: tshark, socat, ffplay, and the 'ip' command must be installed.

# --- Configuration Variables ---

MON_INTERFACE="wlan0mon"   # <-- REQUIRED: Your active monitor interface name
FF_CODEC="h264"            # <-- The video codec used by the drone
FF_LISTEN_PORT="12345"     # <-- The local UDP port for ffplay to listen on

# Variables set at runtime
DRONE_PORT=""              # Set by command-line argument $1
DRONE_IP=""
PHONE_IP=""

# --- Core Functions ---

cleanup() {
    echo -e "\n\n[INFO] Killing background processes and cleaning up..."
    
    # 1. Remove the IP alias using the 'ip' command
    if [ ! -z "$PHONE_IP" ] && command -v ip &> /dev/null; then
        echo "[INFO] Removing temporary IP address $PHONE_IP..."
        # Using 'del' to ensure it's removed, ignoring errors if it's already gone
        ip address del "$PHONE_IP"/24 dev "$MON_INTERFACE" 2>/dev/null
    fi
    
    # 2. Kill the running processes
    kill -9 $SOCAT_PID 2>/dev/null
    kill -9 $FFPLAY_PID 2>/dev/null
    
    exit 0
}

# Trap signals (Ctrl+C, termination) for clean exit
trap cleanup SIGINT SIGTERM

detect_ips() {
    echo -e "\n--- Step 1: Dynamic IP Discovery ---"
    echo "[INFO] Scanning interface $MON_INTERFACE for the first UDP packet on port $DRONE_PORT..."
    echo "[ACTION] Please START the drone video stream on your controller/phone NOW."
    
    local tshark_output
    # Listen for one packet, ignore tshark's non-zero exit code if it finds the packet.
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

manage_ip_alias() {
    echo -e "\n--- Step 2: Fixing 'Address already in use' Prerequisite ---"
    if ! command -v ip &> /dev/null; then
        echo "[ERROR] 'ip' command not found. This is needed for IP aliasing."
        exit 1
    fi
    
    # Use 'add' or 'replace' to ensure the IP alias is present. 
    # 'replace' handles the 'Address already assigned' error from previous failed runs.
    echo "[INFO] Ensuring temporary IP alias: $PHONE_IP on $MON_INTERFACE is active..."
    ip address replace "$PHONE_IP"/24 dev "$MON_INTERFACE"
    
    if [ $? -ne 0 ]; then
        echo "[FATAL] Failed to create or replace IP alias using 'ip address replace'."
        exit 1
    fi
    echo "[SUCCESS] IP alias active. Your machine can now bind to $PHONE_IP."
}

start_redirection() {
    echo -e "\n--- Step 3: Stream Redirection (socat with REUSE options) ---"
    
    # UDP-LISTEN on $DRONE_PORT, bound to $PHONE_IP, with fork, and crucial REUSE options
    echo "[INFO] Binding to $PHONE_IP:$DRONE_PORT using reuseaddr,reuseport..."
    
    socat UDP-LISTEN:"$DRONE_PORT",bind="$PHONE_IP",fork,reuseaddr,reuseport UDP:127.0.0.1:"$FF_LISTEN_PORT" &
    SOCAT_PID=$!
    
    echo "[INFO] Redirection running (socat PID: $SOCAT_PID). Press Ctrl+C to stop."
    echo "[WARNING] The phone's video feed may break as the stream is only being sent to your local viewer."
}

start_viewer() {
    echo -e "\n--- Step 4: Local Video Viewer (ffplay) ---"
    echo "[ACTION] Starting ffplay viewer..."
    
    # ffplay command optimized for low latency UDP streaming
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
for tool in tshark socat ffplay ip; do
    if ! command -v $tool &> /dev/null; then
        echo "[ERROR] Required tool '$tool' not found. Please install it (e.g., sudo apt install $tool)."
        exit 1
    fi
done

# 3. Dynamically find IPs
detect_ips

# 4. Manage IP Alias (using 'ip address replace')
manage_ip_alias

# 5. Start redirection (with REUSE flags)
start_redirection

# 6. Start video viewer
start_viewer

# 7. Keep the script running to catch Ctrl+C (and run cleanup)
wait $SOCAT_PID
