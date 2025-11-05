import math
import wave
import struct
import os
import sys
import time
import subprocess
import re
import json

# --- Configuration ---
# Setting the scan interval to 0.2 seconds for fastest possible polling.
SCAN_INTERVAL_SECONDS = 0.2 
MAX_LSWIFI_RETRIES = 3 # Maximum times to retry the fast lswifi scan before falling back.

NEW_WAP_ALARM = {
    'filename': 'f1880_d0.2_c10_g0.07.wav',
    'frequency': 1880, 'duration': 0.2, 'cycles': 10, 'gap': 0.07
}
REMOVED_WAP_ALARM = {
    'filename': 'f1440_d0.35_c5_g0.12.wav',
    'frequency': 1440, 'duration': 0.35, 'cycles': 5, 'gap': 0.12
}

# --- Core Sound Utilities (Unchanged) ---

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
            # Fix applied: Correctly join byte samples
            wav_file.writeframes(b''.join(full_data))
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Could not generate WAV file {filename}: {e}")
        
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
        print(f"[{time.strftime('%H:%M:%S')}] Generating NEW WAP alarm sound: {new['filename']}...")
        generate_square_wave_alarm(new['filename'], new['frequency'], new['duration'], new['cycles'], new['gap'])

    # Removed WAP Alarm Generation
    removed = REMOVED_WAP_ALARM
    if not os.path.exists(removed['filename']):
        print(f"[{time.strftime('%H:%M:%S')}] Generating REMOVED WAP alarm sound: {removed['filename']}...")
        generate_square_wave_alarm(removed['filename'], removed['frequency'], removed['duration'], removed['cycles'], removed['gap'])

# --- Cross-Platform Scanning Logic ---

def parse_lswifi_output(output_json):
    """
    Parses the lswifi JSON output, handling multiple known structures.
    Returns a set of BSSIDs.
    """
    bssids = set()
    try:
        data = json.loads(output_json)
        
        # 1. Primary Case (User's Structure): Top-level list of WAP objects
        if isinstance(data, list) and all(isinstance(item, dict) and 'bssid' in item for item in data):
            for bss in data:
                bssids.add(bss['bssid'].upper().replace('-', ':'))
            return bssids

        # 2. Case: Dictionary with 'scan_data' key (alternate lswifi version)
        elif isinstance(data, dict) and 'scan_data' in data and isinstance(data['scan_data'], list):
            for bss in data['scan_data']:
                if 'bssid' in bss:
                    bssids.add(bss['bssid'].upper().replace('-', ':'))
            return bssids
        
        # 3. Case: Legacy list of interface dictionaries with 'BSSList'
        elif isinstance(data, list):
            for interface in data:
                if 'BSSList' in interface:
                    for bss in interface['BSSList']:
                        if 'BSSID' in bss:
                            bssids.add(bss['BSSID'].upper().replace('-', ':'))
            return bssids

    except json.JSONDecodeError:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR: Failed to decode JSON from lswifi output.")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR: An error occurred during lswifi parsing: {e}")
        
    return bssids


def scan_waps():
    """
    Executes the OS-specific command to scan for Wi-Fi networks 
    and returns a set of BSSIDs (MAC addresses) found.
    """
    bssids = set()
    cmd = []
    
    if sys.platform == "win32":
        
        # --- Attempt 1: Fast Scan using lswifi (with retries) ---
        for attempt in range(1, MAX_LSWIFI_RETRIES + 1):
            try:
                cmd = ['lswifi', '-n', '1', '--json', '-all'] 
                
                if attempt == 1:
                    print(f"[{time.strftime('%H:%M:%S')}] INFO: Attempting fast scan using 'lswifi'...")
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] INFO: Retrying 'lswifi' scan (Attempt {attempt}/{MAX_LSWIFI_RETRIES})...")

                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                
                # --- NEW: Use robust parsing logic ---
                bssids = parse_lswifi_output(result.stdout)

                if bssids:
                    print(f"[{time.strftime('%H:%M:%S')}] SUCCESS: 'lswifi' scan found {len(bssids)} WAPs. Using fast results.")
                    return bssids # Return immediately on successful fast scan with data
                else:
                    # If parsing succeeded but bssids is empty, it means the utility genuinely found nothing.
                    if attempt < MAX_LSWIFI_RETRIES:
                        # Log warning and try again
                        print(f"[{time.strftime('%H:%M:%S')}] WARNING: 'lswifi' executed successfully but found 0 WAPs. Retrying...")
                        time.sleep(1) 
                        continue
                    else:
                        # Final attempt failed, fall through to netsh
                        print(f"[{time.strftime('%H:%M:%S')}] WARNING: 'lswifi' failed after {MAX_LSWIFI_RETRIES} attempts or returned 0 WAPs.")
                        break # Exit loop to fall back to netsh

            except subprocess.TimeoutExpired:
                print(f"[{time.strftime('%H:%M:%S')}] ERROR: 'lswifi' timed out. Falling through to netsh.")
                break 
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                # If lswifi isn't installed or throws an OS-level error
                print(f"[{time.strftime('%H:%M:%S')}] ERROR: 'lswifi' execution failed. Falling through to netsh. ({type(e).__name__})")
                break 
        
        # --- Fallback: Slow Scan using netsh (Windows Cache) ---
        print(f"[{time.strftime('%H:%M:%S')}] INFO: Falling back to Windows Wi-Fi cache (detection will be delayed).")
        cmd = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
            
            # Use regex to find MAC addresses (BSSIDs)
            # Example: BSSID 1                : dc:62:79:bc:c6:9b
            bssid_matches = re.findall(r'BSSID \d+\s+:\s+([0-9a-fA-F:]{17})', result.stdout)
            bssids.update(bssid_matches)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            print(f"[{time.strftime('%H:%M:%S')}] ERROR: netsh scan failed. Cannot retrieve WAPs. ({type(e).__name__})")

    elif sys.platform == "darwin" or sys.platform.startswith("linux"):
        # macOS/Linux logic (using 'airport' or 'nmcli' which are generally reliable)
        if sys.platform == "darwin":
            cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s']
            print(f"[{time.strftime('%H:%M:%S')}] INFO: Running macOS scan ('airport')...")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                
                # Split lines and skip header (first line)
                lines = result.stdout.strip().split('\n')[1:]
                for line in lines:
                    # MAC address is the second token
                    tokens = line.split()
                    if len(tokens) >= 2:
                        bssids.add(tokens[1].upper().replace('-', ':'))
                        
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError) as e:
                 print(f"[{time.strftime('%H:%M:%S')}] ERROR: macOS 'airport' failed. Cannot retrieve WAPs. ({type(e).__name__})")
                 
        elif sys.platform.startswith("linux"):
            # Requires NetworkManager and nmcli
            cmd = ['nmcli', '-t', '-f', 'BSSID', 'dev', 'wifi', 'list']
            print(f"[{time.strftime('%H:%M:%S')}] INFO: Running Linux scan ('nmcli')...")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                
                # Each line is expected to be a BSSID
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line:
                        bssids.add(line.strip().upper().replace('-', ':'))
                        
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError) as e:
                print(f"[{time.strftime('%H:%M:%S')}] ERROR: Linux 'nmcli' failed. Cannot retrieve WAPs. ({type(e).__name__})")

    # Clean the BSSID set by removing duplicates and ensuring valid format (already handled by .add)
    # The set() ensures uniqueness

    return bssids

# --- Monitor and Alarm Logic (Unchanged) ---

def monitor_loop():
    """Main loop for WAP monitoring."""
    
    # Global state to hold the previously detected WAPs
    global previous_waps 
    previous_waps = set()
    
    try:
        # Initial scan to populate the first list
        current_waps = scan_waps()
        previous_waps = current_waps
        print(f"[{time.strftime('%H:%M:%S')}] Initial WAP count: {len(current_waps)}")
        
        while True:
            time.sleep(SCAN_INTERVAL_SECONDS) # Wait for the interval
            current_waps = scan_waps()

            # Identify new WAPs
            new_waps = current_waps - previous_waps
            
            # Identify removed WAPs (only if netsh fallback wasn't just used, 
            # as netsh is slower and may miss some transient APs)
            removed_waps = previous_waps - current_waps
            
            for bssid in new_waps:
                print(f"[{time.strftime('%H:%M:%S')}] ALARM: NEW WAP detected: {bssid}")
                play_system_sound(NEW_WAP_ALARM['filename'])

            for bssid in removed_waps:
                print(f"[{time.strftime('%H:%M:%S')}] ALARM: WAP REMOVED: {bssid}")
                play_system_sound(REMOVED_WAP_ALARM['filename'])

            # Update the previous state for the next comparison
            previous_waps = current_waps

    except KeyboardInterrupt:
        print(f"\n[{time.strftime('%H:%M:%S')}] Monitor stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        print(f"\n[{time.strftime('%H:%M:%S')}] A fatal error occurred: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    print("--- Wi-Fi Access Point Monitor Initializing ---")
    generate_required_alarms()
    print("Alarms ready. Starting monitoring loop...")
    print(f"Polling network list every {SCAN_INTERVAL_SECONDS} second(s). Press Ctrl+C to stop.")
    monitor_loop()
