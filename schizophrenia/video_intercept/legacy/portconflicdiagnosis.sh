#!/bin/bash
# Find the process already listening on the drone video port (57840)
# -u: UDP sockets
# -l: Listening sockets
# -p: Show process info (PID/Name)
# -n: Don't resolve service names

echo "--- Diagnostic: Finding process using UDP port 57840 ---"
sudo ss -ulpn | grep 57840
echo "--------------------------------------------------------"
echo "If output exists, the last column shows 'users' (process name) and 'pid' (process ID)."
