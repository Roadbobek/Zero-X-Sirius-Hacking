# Zero X Sirius Hacking
### Repository for my Zero-X Sirius drone hacking stuff.

## Info on the Sirius drone by Zero-X

I used an ALFA AWUS036ACH wireless adapter with monitor mode on Kali Linux with tools like Wireshark and the aircrack-ng suite to capture this data.

The Zero-X Sirius drone can be controlled either by its radio controller or the Zero-X Swift mobile app which is also used for receiving the video feed by connecting the mobile device to the drone's wireless access point.

The drone uses a Bouffalo Lab chip for its 2.4ghz wireless functionalities.

The drone assigns itself the IPV4 address 192.168.169.1, the subsequent mobile device is assigned the address 192.168.169.2.

When connected to the drone's 2.4ghz WiFi wireless access point, on the app's connection to the drone (when clicking Start) the mobile device is assigned a random high number port around the range of thirty to fifty thousand, this port is used for the ensuing UDP communication.

When the mobile device is connected to the drone's wireless access point, the app is open and control mode is on (the ON and OFF button) the drone receives control data packets from the mobile device on port 8800 through UDP. This port is used for all commands issued to the drone.

The mobile device continuously sends packets to the drone, any commands will appear there. But there are always packets even if not issuing commands.

When the app is connected to the drone, the drone's video feed is received by the mobile device on port 1234 through UDP.

The video feed is transmitted live as a H.264 encoded video stream, which is also known as Advanced Video Coding (AVC). It seems to follow this structure seen in vidcap.png, the first inner column is the frame number and the second column is the frame part, since the entire frame isn't transmitted in one packet.

### Files

- **Simple_Flight_Test.py:**

    A simple script to fly the drone, it will go up and down. It simply replays two captured commands, the script requires you to connect to the drone's WAP.

- **vidcap.csv:**

    A Wireshark capture of the drone's video feed cleaned up and exported as a CSV.

- **vidcap.png:**

    An annotated screenshot of vidcap.csv, showing some valuable info in the hexadecimal payload.

### Folders

- **schizophrenia:**

    Random scripts, notes and wireless captures from before this repositories creation.













































---

---

---

---

---

---

---

---

---


---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

wip...

# Zero X Sirius Hacking
### Repository for my Zero-X Sirius drone hacking stuff.

## Project Overview
This repository documents the process of reverse-engineering and analyzing the wireless communication protocols of the Zero-X Sirius drone. The primary goal is to understand the control and video streaming mechanisms, with the eventual aim of developing custom control scripts and potentially identifying security vulnerabilities.

The analysis was performed using an ALFA AWUS036ACH wireless adapter on Kali Linux, utilizing tools such as the `aircrack-ng` suite and `Wireshark`/`TShark` for packet capture and analysis.

## Network & Communication Analysis

The drone operates as a wireless access point (WAP) and uses a Bouffalo Lab chip for its 2.4GHz Wi-Fi functionalities.

### IP & Port Configuration
*   **Drone IP Address (Static):** `192.168.169.1`
*   **Mobile Device IP Address (DHCP):** `192.168.169.2`
*   **Control Port (Drone):** UDP `8800`. The mobile app sends control commands (flight, camera, etc.) to this port.
*   **Video Port (Drone):** UDP `1234`. The drone streams H.264 video data from this port.
*   **Client Port (Mobile Device):** A random high-number port (e.g., `42604`) is used by the mobile app to send and receive UDP traffic.

### Communication Flow
1.  The mobile device connects to the drone's Wi-Fi network.
2.  The Zero-X Swift app initiates a UDP communication session.
3.  Control commands are sent from the mobile device (`192.168.169.2`) to the drone (`192.168.169.1:8800`).
4.  The drone sends a live H.264 video stream from `192.168.169.1:1234` to the mobile device's high-number port.

## Protocol Reverse Engineering

Significant progress has been made in decoding the structure of the UDP payloads for both control and video.

### Control Protocol (Mobile -> Drone)

Packet captures reveal a custom protocol for drone commands sent over UDP. The payloads have variable lengths, with `88`, `112`, and `116` bytes being common.

A key discovery is the structure of the 116-byte "STOP" command packet:

*   **Sequence Number:** Located at `index 12` (0-based). This byte increments with each command sent, wrapping around from `0xff` to `0x00`. This is likely a mechanism to prevent simple replay attacks and ensure command order.
*   **Command Byte:** Located at `index 96`. This byte appears to control the drone's state.
    *   `0x01`: Active/Flying state.
    *   `0x00`: Stop/Kill state. This was used to create a "kill switch" script.
*   **Checksum:** A 1-byte checksum is located at `index 104`. Initial analysis suggests this is a simple 8-bit XOR checksum calculated over the first 104 bytes of the payload (`payload[0]` to `payload[103]`). While this is a strong hypothesis, it may require further validation if packet injection fails.

### Video Protocol (Drone -> Mobile)

The video stream is confirmed to be H.264 encoded data sent over UDP. Based on the `camfeedcap.5.10.csv` capture, the video data is fragmented across multiple UDP packets.

A common video packet structure has a payload length of 1080 bytes and begins with the magic bytes `93 01`.

*   **Frame Number:** Located at `index 32` (0-based). This 4-byte little-endian integer (`0x000000d1` -> 209) appears to be a unique identifier for a full video frame.
*   **Fragment Index:** Located at `index 36`. This 4-byte little-endian integer (`0x00000000`, `0x00000001`, etc.) indicates the sequence of the packet within a larger frame. A single video frame is reconstructed by assembling these fragments in order.

This fragmentation is necessary because a full video frame is much larger than the Maximum Transmission Unit (MTU) of a standard network packet.

### Other Observed Packets

The captures show other interesting UDP packets that are part of the drone's communication:

*   **Heartbeat/Keep-Alive:** Small, 4-byte UDP packets with payload `ef 00 04 00` are sent frequently from the mobile device to the drone. This is likely a keep-alive mechanism to maintain the connection state.
*   **Handshake/Info:** A 25-byte packet with payload `ef 20 19 00 ...` is sent from the mobile device. The ASCII representation `<i=2^bf_ssid=cmd=2>` suggests it might be part of a handshake or command initialization sequence.
*   **Status/Telemetry:** The drone sends 88-byte and 112-byte packets from port 8800. These could be status updates, acknowledgments, or telemetry data sent back to the app.

## Tools & Scripts

This repository contains several scripts developed during the analysis.

### `Simple_Flight_Test.py`

A basic script that connects to the drone's WAP and uses standard UDP sockets to send pre-captured flight commands. This script demonstrates a simple **replay attack** to make the drone take off and land. It requires a direct Wi-Fi connection to the drone.

### `schizophrenia/misc/sirius_replay.py`

This script is a work in progress, it is a more advanced script for crafting and injecting a specific "STOP" command to the drone. This script is designed for a **packet injection attack** and does not require being connected to the drone's Wi-Fi.

**Functionality:**
*   Uses Scapy to build a raw Layer 2 packet.
*   Targets the drone's MAC address (`C4:D7:FD:0E:F3:6D`).
*   Modifies a captured packet payload to create a "STOP" command (`0x00` at index 96).
*   Increments the sequence number (`index 12`) to appear as a valid new command.
*   Calculates and inserts a guessed XOR checksum.
*   Injects the packet using a wireless adapter in monitor mode.

**Code Quality Note:** The script is well-structured and heavily commented, which is excellent for documenting the reverse-engineering process. The checksum function is correctly identified as a guess, which is important for future work.

## Future Work & Research Areas

1.  **Checksum Validation:** The 8-bit XOR checksum is a strong hypothesis but needs to be definitively confirmed. This can be done by capturing multiple known commands, calculating the checksum for each, and verifying that the algorithm holds true across all of them.

2.  **Full Control Protocol Mapping:** The "STOP" command has been identified, but the bytes corresponding to flight controls (roll, pitch, yaw, throttle) are still unknown. A systematic approach would be to:
    *   Capture short, isolated maneuvers (e.g., "forward for 1 second," "roll left for 1 second").
    *   Compare the packet payloads from these captures against a baseline "hover" command.
    *   The bytes that change will correspond to the specific control inputs.

3.  **Video Stream Reassembly:** Write a script to capture the fragmented H.264 UDP packets and reassemble them into a playable video file. This would involve:
    *   Grouping packets by the "Frame Number" field.
    *   Sorting the packets within each group by the "Fragment Index".
    *   Concatenating the payloads in the correct order to reconstruct the raw H.264 frame data.

4.  **Vulnerability Analysis:**
    *   **Jamming/Deauthentication:** Can the drone's Wi-Fi be effectively jammed or deauthenticated, causing it to lose control and initiate a failsafe (e.g., land, return to home)?
    *   **Unauthenticated Control:** The `sirius_replay.py` script proves that commands can be injected without being associated with the drone's AP. This is a significant vulnerability. Can this be expanded to full, unauthenticated flight control?
    *   **Fuzzing:** The control protocol could be fuzzed by sending malformed UDP packets to port 8800 to test for crashes or unexpected behavior in the drone's flight controller.

## Capture Data

*   **`vidcap.csv` / `camfeedcap.5.10.csv`:** Wireshark captures of the drone's video feed and other communication, cleaned up and exported as CSV. These are invaluable for protocol analysis.
*   **`vidcap.png`:** An annotated screenshot of `vidcap.csv`, highlighting key fields in the video stream payload like the frame number and fragment index.
*   **`schizophrenia/misc/testing_data.txt`:** Raw packet data snippets from Wireshark, useful for quick reference.
