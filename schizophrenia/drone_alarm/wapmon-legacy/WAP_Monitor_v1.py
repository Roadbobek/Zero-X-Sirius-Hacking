import math
import wave
import struct
import os
import sys
import time
import subprocess
import re

# --- Configuration ---
SCAN_INTERVAL_SECONDS = 0.2
NEW_WAP_ALARM = {
    'filename': 'f1880_d0.2_c10_g0.07.wav',
    'frequency': 1880, 'duration': 0.2, 'cycles': 10, 'gap': 0.07
}
REMOVED_WAP_ALARM = {
    'filename': 'f1440_d0.35_c5_g0.12.wav',
    'frequency': 1440, 'duration': 0.35, 'cycles': 5, 'gap': 0.12
}

# --- Core Sound Utilities (Reused from previous turn) ---

def generate_square_wave_alarm(filename, frequency, duration, cycles, gap, rate=44100, volume=32767):
    """Generates a pulsing square wave and saves it as a WAV file."""
    try:
        pulse_samples = int(rate * duration)
        period = rate / frequency
        pulse_data = []
        
        for i in range(pulse_samples):
            # Square wave logic
            sample = volume if (i % period) < (period / 2) else -volume
            pulse_data.append(struct.pack('<h', int(sample)))

        gap_samples = int(rate * gap)
        silence_sample = struct.pack('<h', 0)
        silence_data = [silence_sample] * gap_samples

        full_data = []
        for _ in range(cycles):
            full_data.extend(pulse_data)
            full_data.extend(silence_data)
        
        with wave.open(filename, 'w') as wav_file:
            wav_file.setparams((1, 2, rate, len(full_data), 'NONE', 'not compressed'))
            wav_file.writeframes(b''.join(full_data))
    except Exception as e:
        print(f"[ERROR] Could not generate WAV file {filename}: {e}")
        
def play_system_sound(filename):
    """Plays the generated WAV file using the simplest OS-specific method."""
    try:
        if sys.platform == "win32": # Windows: use winsound (built-in)
            import winsound
            winsound.PlaySound(filename, winsound.SND_FILENAME | winsound.SND_ASYNC)
        elif sys.platform == "darwin": # macOS: use afplay (built-in)
            # Use Popen to non-blockingly play the sound
            subprocess.Popen(['afplay', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif sys.platform.startswith("linux"): # Linux: use aplay (common utility)
            subprocess.Popen(['aplay', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] Playback failed: OS not supported.")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Playback failed (Is {sys.platform}'s sound utility installed?). Error: {e}")

def generate_required_alarms():
    """Generates the two specific WAV files if they don't already exist."""
    
    # New WAP Alarm Generation
    new = NEW_WAP_ALARM
    if not os.path.exists(new['filename']):
        print(f"Generating NEW WAP alarm sound: {new['filename']}...")
        generate_square_wave_alarm(new['filename'], new['frequency'], new['duration'], new['cycles'], new['gap'])

    # Removed WAP Alarm Generation
    removed = REMOVED_WAP_ALARM
    if not os.path.exists(removed['filename']):
        print(f"Generating REMOVED WAP alarm sound: {removed['filename']}...")
        generate_square_wave_alarm(removed['filename'], removed['frequency'], removed['duration'], removed['cycles'], removed['gap'])

# --- Cross-Platform Scanning Logic ---

def scan_waps():
    """
    Executes the OS-specific command to scan for Wi-Fi networks 
    and returns a set of BSSIDs (MAC addresses) found.
    """
    cmd = []
    
    if sys.platform == "win32":
        # Windows: Uses netsh wlan show networks mode=bssid
        cmd = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']
        # CORRECTED REGEX: Capture 6 pairs of hex digits separated by colon or hyphen.
        # This replaces the complex and error-prone backreference (\3)
        mac_regex = r"BSSID\s*\d*\s*:\s*([\dA-F]{2}(?:[:\-][\dA-F]{2}){5})" 

    elif sys.platform.startswith("linux"):
        # Linux: Uses nmcli or iwlist (nmcli is more modern and structured)
        try:
            # Try nmcli first
            subprocess.run(['nmcli', '-v'], check=True, capture_output=True) # Check if nmcli exists
            cmd = ['nmcli', '-t', '-f', 'bssid', 'dev', 'wifi', 'list']
            # nmcli output is clean, one BSSID per line.
            mac_regex = r"([\dA-F:]{17})" 
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback to iwlist (requires the interface name, assuming wlan0 or use ip a to find it)
            print("[INFO] nmcli not found, falling back to iwlist (requires sudo/root privileges)...")
            cmd = ['sudo', 'iwlist', 'wlan0', 'scan'] # NOTE: May need to adjust 'wlan0'
            mac_regex = r"Address:\s*([\dA-F:]{17})"

    else:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR: Unsupported operating system: {sys.platform}")
        return set()
        
    try:
        # Execute the command
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=5)
        output = result.stdout.upper()
        
        # Find all MAC addresses using the regex
        # We ensure they are stripped and formatted consistently (e.g., colons) before adding to set
        bssids = set()
        for mac in re.findall(mac_regex, output, re.IGNORECASE):
             # Normalize format (e.g., 00:1A:2B:3C:4D:5E)
             normalized_mac = mac.replace('-', ':').strip()
             if len(normalized_mac) == 17:
                bssids.add(normalized_mac)

        return bssids

    except subprocess.CalledProcessError as e:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR: Scan command failed. Ensure Wi-Fi is enabled and permissions are correct (try running with sudo/Administrator).")
        print(f"Command: {' '.join(cmd)}\nError: {e.stderr.strip()}")
        return set()
    except FileNotFoundError:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR: Required utility ('{cmd[0]}') not found.")
        return set()
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] An unexpected error occurred during scan: {e}")
        return set()


# --- Main Monitoring Loop ---

def main():
    print("--- Wi-Fi Access Point Monitor Initializing ---")
    generate_required_alarms()
    print("\nAlarms ready. Starting monitoring loop...")
    print(f"Scanning every {SCAN_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.\n")

    # Initial scan to populate the baseline set
    last_waps = scan_waps()
    if not last_waps:
        print("[WARNING] Initial scan found no WAPs. This may indicate an issue with the scan command.")
    
    print(f"[{time.strftime('%H:%M:%S')}] Initial WAP count: {len(last_waps)}")

    try:
        while True:
            # 1. Wait for the interval
            time.sleep(SCAN_INTERVAL_SECONDS)

            # 2. Scan and compare
            current_waps = scan_waps()
            
            # WAPs that appeared (Current WAPs MINUS Last WAPs)
            new_waps = current_waps - last_waps
            
            # WAPs that disappeared (Last WAPs MINUS Current WAPs)
            removed_waps = last_waps - current_waps
            
            # 3. Handle events
            
            if new_waps:
                print(f"[{time.strftime('%H:%M:%S')}] !!! NEW WAP(s) DETECTED ({len(new_waps)}): {', '.join(new_waps)}")
                play_system_sound(NEW_WAP_ALARM['filename'])
                time.sleep(1) # Pause to ensure sound plays
            
            if removed_waps:
                print(f"[{time.strftime('%H:%M:%S')}] --- WAP(s) REMOVED ({len(removed_waps)}): {', '.join(removed_waps)}")
                play_system_sound(REMOVED_WAP_ALARM['filename'])
                time.sleep(1) # Pause to ensure sound plays

            if not new_waps and not removed_waps:
                print(f"[{time.strftime('%H:%M:%S')}] Status: Stable. Total WAPs: {len(current_waps)}")
            
            # 4. Update state for the next comparison
            last_waps = current_waps

    except KeyboardInterrupt:
        print("\nMonitor stopped by user (Ctrl+C). Goodbye!")
    finally:
        # Clean up files upon exit (optional, but good practice)
        # os.remove(NEW_WAP_ALARM['filename'])
        # os.remove(REMOVED_WAP_ALARM['filename'])
        pass

if __name__ == "__main__":
    main()
