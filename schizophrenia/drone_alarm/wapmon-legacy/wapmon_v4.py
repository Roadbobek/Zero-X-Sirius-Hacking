import time
from datetime import datetime
import re
import json
import logging
from collections import defaultdict
import math
import wave
import struct
import os
import sys
import subprocess

# --- Configuration ---
# Setting the scan interval to 0.2 seconds for fastest possible polling.
SCAN_INTERVAL_SECONDS = 0.2
MAX_LSWIFI_RETRIES = 3 # Maximum times to retry the fast lswifi scan before falling back.
LOG_FILE = 'wap_monitor.log' # Persistent log file for event history

NEW_WAP_ALARM = {
    'filename': 'f1880_d0.2_c10_g0.07.wav',
    'frequency': 1880, 'duration': 0.2, 'cycles': 10, 'gap': 0.07
}
REMOVED_WAP_ALARM = {
    'filename': 'f1440_d0.35_c5_g0.12.wav',
    'frequency': 1440, 'duration': 0.35, 'cycles': 5, 'gap': 0.12
}

# Define the structure for a WAP object for consistency
WAP_TEMPLATE = {
    'bssid': 'N/A',
    'ssid': 'Hidden/Unknown',
    'signal': '0%', # Signal strength in percentage
    'channel': 'N/A',
    'band': 'N/A',
    'auth': 'N/A',
    'encryption': 'N/A'
}

# --- Core Sound Utilities ---

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
        # Use logging.error instead of print for errors
        logging.error(f"Could not generate WAV file {filename}: {e}")

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
            logging.error(f"Playback failed: OS not supported ({sys.platform}).")
    except Exception as e:
        logging.error(f"Playback failed (Is {sys.platform}'s sound utility installed?). Error: {e}")

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
    Parses the lswifi JSON output and returns a dictionary of WAP objects
    keyed by BSSID.
    """
    waps = {} # {BSSID: WAP_OBJECT}
    try:
        data = json.loads(output_json)

        # We assume the common structure: Top-level list of WAP objects
        if isinstance(data, list):
            for bss in data:
                bssid = bss.get('bssid')
                if not bssid:
                    continue

                bssid_formatted = bssid.upper().replace('-', ':')

                # Extract key fields from the lswifi JSON output
                signal_percent = f"{bss.get('signal_quality_percent', 0)}%"

                # Use a dictionary comprehension to clean/map the data
                wap_details = {
                    'bssid': bssid_formatted,
                    'ssid': bss.get('ssid') or WAP_TEMPLATE['ssid'],
                    'signal': signal_percent,
                    # lswifi usually provides these fields
                    'channel': str(bss.get('channel', 'N/A')),
                    'band': bss.get('band', 'N/A'),
                    'auth': bss.get('auth_type', 'N/A'),
                    'encryption': bss.get('cipher_type', 'N/A')
                }
                waps[bssid_formatted] = wap_details

    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON from lswifi output.")
    except Exception as e:
        logging.error(f"An error occurred during lswifi parsing: {e}")

    return waps

def parse_netsh_output(output_text):
    """
    Parses the netsh wlan show networks mode=bssid text output.
    Returns a dictionary of WAP objects keyed by BSSID.
    """
    waps = {}
    # Secondary, simpler regex for fields that can be associated with the whole SSID block
    ssid_auth_enc_pattern = re.compile(
        r"SSID \d+ : (?P<ssid>[^\n]+?)\s*Network type\s+:\s+(?P<type>[^\n]+?)\s*Authentication\s+:\s+(?P<auth>[^\n]+?)\s*Encryption\s+:\s+(?P<encryption>[^\n]+?)\s*",
        re.DOTALL
    )

    # First pass: Extract high-level details (Auth, Enc) per SSID block
    ssid_info = {}
    for match in ssid_auth_enc_pattern.finditer(output_text):
        ssid = match.group('ssid').strip()
        auth = match.group('auth').strip()
        enc = match.group('encryption').strip()
        ssid_info[ssid] = {'auth': auth, 'encryption': enc}

    # Second pass: Extract BSSID-specific details (BSSID, Signal, Channel, Band)
    bssid_signal_pattern = re.compile(
        r"SSID \d+ : (?P<ssid>[^\n]+?)\s*[\s\S]+?(?:BSSID \d+)\s+:\s+(?P<bssid>[0-9a-fA-F:]{17})\s+Signal\s+:\s+(?P<signal>\d+)%",
        re.DOTALL
    )

    for match in bssid_signal_pattern.finditer(output_text):
        bssid_formatted = match.group('bssid').upper().replace('-', ':')
        ssid = match.group('ssid').strip()
        signal = f"{match.group('signal')}%"

        # Look up authentication/encryption from the first pass
        auth = ssid_info.get(ssid, {}).get('auth', 'N/A')
        encryption = ssid_info.get(ssid, {}).get('encryption', 'N/A')

        # Note: Channel and Band are hard to reliably extract for each individual BSSID using netsh's format.

        waps[bssid_formatted] = {
            'bssid': bssid_formatted,
            'ssid': ssid or WAP_TEMPLATE['ssid'],
            'signal': signal,
            'channel': 'N/A (netsh)',
            'band': 'N/A (netsh)',
            'auth': auth,
            'encryption': encryption
        }

    return waps


def scan_waps():
    """
    Executes the OS-specific command to scan for Wi-Fi networks
    and returns a dictionary of WAP objects keyed by BSSID.
    """
    waps = {}

    if sys.platform == "win32":
        # --- Attempt 1: Fast Scan using lswifi (with retries) ---
        for attempt in range(1, MAX_LSWIFI_RETRIES + 1):
            try:
                cmd = ['lswifi', '-n', '1', '--json', '-all']

                if attempt == 1:
                    # Initial info log
                    logging.info("Attempting fast scan using 'lswifi'...")
                else:
                    logging.info(f"Retrying 'lswifi' scan (Attempt {attempt}/{MAX_LSWIFI_RETRIES})...")

                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)

                waps = parse_lswifi_output(result.stdout)

                if waps:
                    logging.info(f"'lswifi' scan found {len(waps)} WAPs. Using fast results.")
                    return waps # Return immediately on successful fast scan with data
                else:
                    if attempt < MAX_LSWIFI_RETRIES:
                        logging.warning("'lswifi' executed successfully but found 0 WAPs. Retrying...")
                        time.sleep(1)
                        continue
                    else:
                        logging.warning(f"'lswifi' failed after {MAX_LSWIFI_RETRIES} attempts or returned 0 WAPs.")
                        break # Exit loop to fall back to netsh

            except subprocess.TimeoutExpired:
                logging.error("'lswifi' timed out. Falling through to netsh.")
                break
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                logging.error(f"'lswifi' execution failed. Falling through to netsh. ({type(e).__name__})")
                break

        # --- Fallback: Slow Scan using netsh (Windows Cache) ---
        logging.info("Falling back to Windows Wi-Fi cache (detection may be delayed).")
        cmd = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
            waps = parse_netsh_output(result.stdout)

        except Exception as e:
            logging.error(f"netsh scan failed. Cannot retrieve WAPs. ({type(e).__name__})")

    elif sys.platform == "darwin" or sys.platform.startswith("linux"):
        # For simplicity on non-Windows platforms, we only capture BSSID and RSSI

        if sys.platform == "darwin":
            cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s']
            logging.info("Running macOS scan ('airport')...")

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                lines = result.stdout.strip().split('\n')[1:]
                for line in lines:
                    tokens = line.split()
                    # Example: SSID, RSSI, BSSID, CHANNEL, HT, CC, SECURITY
                    if len(tokens) >= 3:
                        ssid, rssi_dbm, bssid, *rest = tokens
                        signal_percent = f"{min(max(2 * (int(rssi_dbm) + 100), 0), 100)}%" # Crude conversion
                        bssid_formatted = bssid.upper().replace('-', ':')

                        waps[bssid_formatted] = {
                            'bssid': bssid_formatted,
                            'ssid': ssid or WAP_TEMPLATE['ssid'],
                            'signal': signal_percent,
                            'channel': rest[0].split(',')[0] if rest else 'N/A', # Channel is usually first in rest
                            'band': 'N/A',
                            'auth': 'N/A',
                            'encryption': 'N/A'
                        }

            except Exception as e:
                logging.error(f"macOS 'airport' failed. Cannot retrieve WAPs. ({type(e).__name__})")

        elif sys.platform.startswith("linux"):
            # Use 'nmcli' to get BSSID, SSID, and Signal (RATE/BARS/SIGNAL fields)
            cmd = ['nmcli', '-t', '-f', 'BSSID,SSID,SIGNAL,CHAN', 'dev', 'wifi', 'list']
            logging.info("Running Linux scan ('nmcli')...")

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    # Format is BSSID:SSID:SIGNAL:CHAN
                    parts = line.split(':')
                    if len(parts) >= 4:
                        bssid, ssid, signal_percent, channel = parts[0], parts[1], parts[2], parts[3]
                        bssid_formatted = bssid.strip().upper().replace('-', ':')

                        waps[bssid_formatted] = {
                            'bssid': bssid_formatted,
                            'ssid': ssid.strip() or WAP_TEMPLATE['ssid'],
                            'signal': f"{signal_percent.strip()}%",
                            'channel': channel.strip() or 'N/A',
                            'band': 'N/A',
                            'auth': 'N/A',
                            'encryption': 'N/A'
                        }

            except Exception as e:
                logging.error(f"Linux 'nmcli' failed. Cannot retrieve WAPs. ({type(e).__name__})")

    return waps

def display_initial_waps(waps_dict):
    """Prints all WAPs currently in the cache upon initialization with clear formatting."""
    count = len(waps_dict)

    if count == 0:
        print("--------------------------------------------------------------------------------------------------")
        print("--- Initial WAP Cache Content: No WAPs detected. ---")
        print("--------------------------------------------------------------------------------------------------")
        return

    print("\n--------------------------------------------------------------------------------------------------")
    print(f"--- Initial WAP Cache Content ({count} WAP{'s' if count > 1 else ''} Detected) ---")
    
    # Sort for consistent display (e.g., by SSID then BSSID)
    sorted_waps = sorted(waps_dict.values(), key=lambda w: (w['ssid'] or "ZZZ", w['bssid']))
    
    # Header for alignment
    print(f"{'BSSID':<20} {'SSID':<30} {'Signal':<10} {'Channel':<10} {'Band':<10} {'Auth':<15}")
    print("-" * 100)

    for wap in sorted_waps:
        # Get fields with fallback to N/A
        ssid_display = wap.get('ssid') if wap.get('ssid') and wap.get('ssid') != 'Hidden/Unknown' else "(Hidden SSID)"
        bssid = wap.get('bssid', 'N/A')
        signal = wap.get('signal', 'N/A')
        channel = wap.get('channel', 'N/A')
        band = wap.get('band', 'N/A')
        auth = wap.get('auth', 'N/A')
        
        # Print using f-string alignment
        print(f"{bssid:<20} {ssid_display:<30} {signal:<10} {channel:<10} {band:<10} {auth:<15}")

    print("--------------------------------------------------------------------------------------------------")

# --- Monitor and Alarm Logic ---

def monitor_loop():
    """Main loop for WAP monitoring."""

    # Global state to hold the previously detected WAPs (BSSID -> WAP_OBJECT)
    global previous_waps
    previous_waps = {} # Start with an empty dictionary

    try:
        # Initial scan to populate the first list
        current_waps = scan_waps()
        previous_waps = current_waps

        logging.info("WAP Monitor initialized successfully.")
        
        # Simple print for initial status
        print(f"[{time.strftime('%H:%M:%S')}] Monitoring started with {len(current_waps)} initial WAPs in cache.")
        
        # >>> NEW LOGIC: Print the contents of the initial cache
        display_initial_waps(current_waps)
        
        while True:
            time.sleep(SCAN_INTERVAL_SECONDS) # Wait for the interval
            current_waps = scan_waps()

            # Compare sets of BSSIDs (the keys of the dictionaries)
            current_bssids = set(current_waps.keys())
            previous_bssids = set(previous_waps.keys())

            # Identify new WAPs (BSSIDs in current but not in previous)
            new_bssids = current_bssids - previous_bssids

            # Identify removed WAPs (BSSIDs in previous but not in current)
            removed_bssids = previous_bssids - current_bssids

            # --- Simplified New Logic: Only print changes concisely ---
            if new_bssids or removed_bssids:
                current_time = time.strftime('%H:%M:%S')
                
                new_count = len(new_bssids)
                removed_count = len(removed_bssids)

                # Simplified summary print
                if new_count > 0:
                    print(f"\n[{current_time}] ** {new_count} NEW WAP{'s' if new_count > 1 else ''} detected: **")
                if removed_count > 0:
                    # Print removed summary *before* the list of new WAPs if new WAPs are also present
                    if new_count == 0:
                        print(f"\n[{current_time}] ** {removed_count} WAP{'s' if removed_count > 1 else ''} removed: **")
                    else:
                        print(f"[{current_time}] ** {removed_count} WAP{'s' if removed_count > 1 else ''} removed: **")


                # 1. Handle NEW WAPs (Concise print)
                for bssid in new_bssids:
                    wap = current_waps[bssid] # Get the newly detected WAP object
                    
                    # Create a simple, single-line summary
                    ssid_display = wap['ssid'] if wap['ssid'] and wap['ssid'] != 'Hidden/Unknown' else "(Hidden SSID)"
                    
                    print(f"  [NEW] BSSID: {bssid} | SSID: {ssid_display} | Sig: {wap['signal']} | Ch: {wap['channel']} | Auth: {wap['auth']}")

                    # Alarm and logging
                    alarm_msg = f"NEW WAP detected: {ssid_display} ({bssid})"
                    logging.warning(alarm_msg)
                    play_system_sound(NEW_WAP_ALARM['filename'])

                # 2. Handle REMOVED WAPs (Concise print)
                for bssid in removed_bssids:
                    # Look up the SSID from the *previously* detected WAP object
                    wap_name = previous_waps.get(bssid, {}).get('ssid', 'Unknown SSID')
                    
                    print(f"  [GONE] BSSID: {bssid} | Last known SSID: {wap_name}")
                    
                    # Alarm and logging
                    alarm_msg = f"WAP REMOVED: {wap_name} ({bssid})"
                    logging.warning(alarm_msg)
                    play_system_sound(REMOVED_WAP_ALARM['filename'])

            # Update the previous state for the next comparison
            previous_waps = current_waps

    except KeyboardInterrupt:
        print(f"\n[{time.strftime('%H:%M:%S')}] Monitor stopped by user (Ctrl+C). Goodbye!")
        logging.info("WAP Monitor stopped by user (Ctrl+C).")
    except Exception as e:
        print(f"\n[{time.strftime('%H:%M:%S')}] A fatal error occurred: {e}")
        logging.critical(f"A fatal error occurred in the monitoring loop: {e}", exc_info=True)

# --- Main Execution ---

if __name__ == "__main__":
    print("--- Simple Wi-Fi Access Point Monitor Initializing ---")

    # 1. Setup file logging for alarms and errors
    try:
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO, # Capture INFO, WARNING, ERROR, CRITICAL
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        print(f"[{time.strftime('%H:%M:%S')}] Event log will be saved to: {LOG_FILE}")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [FATAL ERROR] Could not set up file logging: {e}")
        # If file logging fails, we proceed without it.

    # 2. Generate alarms and start loop
    generate_required_alarms()
    print("Alarms ready. Starting monitoring loop.")
    print(f"Polling every {SCAN_INTERVAL_SECONDS}s. Press Ctrl+C to stop.")

    monitor_loop()
