# WAP Monitor - wapmon
# By Roadbobek, v1.1.1 (Linux nmcli parsing fix) STILL BROKEN !!!!!!!!!!

import time
import re
import json
import logging
import argparse
import sys
import subprocess
import os
import wave
import struct

# --- Configuration ---
SCAN_INTERVAL_SECONDS = 0.5
MAX_LSWIFI_RETRIES = 3  # Maximum times to retry the fast lswifi scan before falling back.
LOG_FILE = 'wap_monitor.log'  # Persistent log file for event history

# Define custom log level (e.g., 15, between DEBUG=10 and INFO=20)
SCAN_LOG_LEVEL = 15

# Global flags set by command-line arguments
LOG_ENABLED = False
ALARM_ENABLED = False

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
    'signal': '0%',  # Signal strength in percentage
    'channel': 'N/A',
    'band': 'N/A',
    'auth': 'N/A',
    'encryption': 'N/A'
}


# --- Custom Logging Formatter (Solution to unified output) ---

class AlertFormatter(logging.Formatter):
    """
    Custom Formatter that maps the 'WARNING' log level to the more user-friendly
    'ALERT' string, and the custom SCAN_LOG_LEVEL to 'LOG-INFO'.
    """

    def format(self, record):
        original_levelname = record.levelname

        # Display 'ALERT' for all WARNING level messages
        if record.levelno == logging.WARNING:
            record.levelname = 'ALERT'

        # Display 'LOG-INFO' for custom level 15 messages in the log file
        if record.levelno == SCAN_LOG_LEVEL:
            record.levelname = 'LOG-INFO'

        # Use the standard formatter to create the message
        formatted_message = super().format(record)

        # Restore the original level name for other log handling logic
        record.levelname = original_levelname

        return formatted_message


def log_scan_info(message):
    """
    Helper function to log scan details using the custom SCAN_LOG_LEVEL (15).
    This ensures the message is logged to the file (level 15) but suppressed
    from the console (level 20).
    """
    # We use logging.log(level, message) to use the custom level name
    logging.log(SCAN_LOG_LEVEL, message)


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
        logging.error(f"Could not generate WAV file {filename}: {e}")


def play_system_sound(filename):
    """Plays the generated WAV file using the simplest OS-specific method."""
    if not ALARM_ENABLED:
        return

    try:
        if sys.platform == "win32":  # Windows: use winsound (built-in)
            import winsound
            winsound.PlaySound(filename, winsound.SND_FILENAME | winsound.SND_ASYNC)
        elif sys.platform == "darwin":  # macOS: use afplay (built-in)
            subprocess.Popen(['afplay', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif sys.platform.startswith("linux"):  # Linux: use aplay (common utility)
            subprocess.Popen(['aplay', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            logging.error(f"Playback failed: OS not supported ({sys.platform}).")
    except Exception as e:
        logging.error(f"Playback failed (Is {sys.platform}'s sound utility installed?). Error: {e}")


def generate_required_alarms():
    """Generates the two specific WAV files if they don't already exist."""
    if not ALARM_ENABLED:
        return

    # New WAP Alarm Generation
    new = NEW_WAP_ALARM
    if not os.path.exists(new['filename']):
        # Use print here as this is initialization output before the main loop starts
        print(f"[{time.strftime('%H:%M:%S')}] Generating NEW WAP alarm sound: {new['filename']}...")
        generate_square_wave_alarm(new['filename'], new['frequency'], new['duration'], new['cycles'], new['gap'])

    # Removed WAP Alarm Generation
    removed = REMOVED_WAP_ALARM
    if not os.path.exists(removed['filename']):
        # Use print here as this is initialization output before the main loop starts
        print(f"[{time.strftime('%H:%M:%S')}] Generating REMOVED WAP alarm sound: {removed['filename']}...")
        generate_square_wave_alarm(removed['filename'], removed['frequency'], removed['duration'], removed['cycles'],
                                   removed['gap'])


# --- Cross-Platform Scanning Logic ---

def parse_lswifi_output(output_json):
    """
    Parses the lswifi JSON output and returns a dictionary of WAP objects
    keyed by BSSID.
    """
    waps = {}  # {BSSID: WAP_OBJECT}
    try:
        data = json.loads(output_json)

        if isinstance(data, list):
            for bss in data:
                bssid = bss.get('bssid')
                if not bssid:
                    continue

                bssid_formatted = bssid.upper().replace('-', ':')
                signal_percent = f"{bss.get('signal_quality_percent', 0)}%"

                wap_details = {
                    'bssid': bssid_formatted,
                    'ssid': bss.get('ssid') or WAP_TEMPLATE['ssid'],
                    'signal': signal_percent,
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
    ssid_auth_enc_pattern = re.compile(
        r"SSID \d+ : (?P<ssid>[^\n]+?)\s*Network type\s+:\s+(?P<type>[^\n]+?)\s*Authentication\s+:\s+(?P<auth>[^\n]+?)\s*Encryption\s+:\s+(?P<encryption>[^\n]+?)\s*",
        re.DOTALL
    )

    ssid_info = {}
    for match in ssid_auth_enc_pattern.finditer(output_text):
        ssid = match.group('ssid').strip()
        auth = match.group('auth').strip()
        enc = match.group('encryption').strip()
        ssid_info[ssid] = {'auth': auth, 'encryption': enc}

    bssid_signal_pattern = re.compile(
        r"SSID \d+ : (?P<ssid>[^\n]+?)\s*[\s\S]+?(?:BSSID \d+)\s+:\s+(?P<bssid>[0-9a-fA-F:]{17})\s+Signal\s+:\s+(?P<signal>\d+)%",
        re.DOTALL
    )

    for match in bssid_signal_pattern.finditer(output_text):
        bssid_formatted = match.group('bssid').upper().replace('-', ':')
        ssid = match.group('ssid').strip()
        signal = f"{match.group('signal')}%"

        auth = ssid_info.get(ssid, {}).get('auth', 'N/A')
        encryption = ssid_info.get(ssid, {}).get('encryption', 'N/A')

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
                    # Use log_scan_info to hide from console, but log to file as LOG-INFO
                    log_scan_info("Attempting fast scan using 'lswifi'...")
                else:
                    # Use log_scan_info to hide from console, but log to file as LOG-INFO
                    log_scan_info(f"Retrying 'lswifi' scan (Attempt {attempt}/{MAX_LSWIFI_RETRIES})...")

                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)

                waps = parse_lswifi_output(result.stdout)

                if waps:
                    # Use log_scan_info to hide from console, but log to file as LOG-INFO
                    log_scan_info(f"'lswifi' scan found {len(waps)} WAPs. Using fast results.")
                    return waps
                else:
                    if attempt < MAX_LSWIFI_RETRIES:
                        logging.warning("'lswifi' executed successfully but found 0 WAPs. Retrying...")
                        time.sleep(1)
                        continue
                    else:
                        logging.warning(f"'lswifi' failed after {MAX_LSWIFI_RETRIES} attempts or returned 0 WAPs.")
                        break

            except subprocess.TimeoutExpired:
                logging.error("'lswifi' scan timed out (TimeoutExpired). Falling through to netsh.")
                break
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                # IMPORTANT: Error messages are now formatted cleanly via logging
                logging.error(
                    f"'lswifi' execution failed. Is 'lswifi' installed and in PATH? Falling through to netsh. ({type(e).__name__}: {e})")
                logging.error(f"Please install lswifi or make sure you are running in venv!)")
                break

        # --- Fallback: Slow Scan using netsh (Windows Cache) ---
        logging.warning("Falling back to Windows Wi-Fi cache (netsh). Detection may be delayed.")
        cmd = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
            waps = parse_netsh_output(result.stdout)

        except Exception as e:
            logging.critical(f"netsh scan failed. Cannot retrieve WAPs. ({type(e).__name__})")

    elif sys.platform == "darwin" or sys.platform.startswith("linux"):
        # Non-Windows fallback (Simplified field extraction)

        # --- macOS: Scan using airport ---
        if sys.platform == "darwin":
            cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s']
            logging.info("Running macOS scan ('airport')...")

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                lines = result.stdout.strip().split('\n')[1:]
                for line in lines:
                    tokens = line.split()
                    if len(tokens) >= 3:
                        # Airport output columns: SSID, BSSID, RSSI, CHANNEL, HT, CC, SECURITY
                        # Note: The tokens list may contain more than 3 elements.

                        # Find RSSI (dBm) and BSSID based on common structure
                        # Since SSID can contain spaces, split() output is complex. Re-parse based on known columns:

                        # Try to find BSSID first, as it's fixed length and often the 2nd token
                        # This requires more careful parsing than a simple split() due to SSIDs with spaces.
                        # However, for simplicity and assuming common single-word SSIDs first:

                        # Re-implementing a safer split:
                        parts = line.split()

                        # Check if BSSID is present at the expected location (3rd field)
                        if len(parts) >= 3 and re.match(r'([0-9A-F]{2}:){5}[0-9A-F]{2}$',
                                                        parts[1].upper().replace('-', ':')):
                            # Assume simple split worked for common case
                            bssid = parts[1]
                            rssi_dbm = parts[2]
                            channel_raw = parts[3].split(',')[0] if len(parts) > 3 else 'N/A'
                            # Reconstruct SSID (everything before BSSID)
                            ssid_parts = line.split(bssid, 1)[0].strip()
                            ssid = ssid_parts if ssid_parts else WAP_TEMPLATE['ssid']
                        elif len(parts) >= 5 and re.match(r'([0-9A-F]{2}:){5}[0-9A-F]{2}$',
                                                          parts[-5].upper().replace('-', ':')):
                            # Fallback: Assume BSSID is the 5th element from the end (common for multi-word SSIDs)
                            bssid = parts[-5]
                            rssi_dbm = parts[-4]
                            channel_raw = parts[-3].split(',')[0]
                            # Reconstruct SSID (everything before BSSID)
                            ssid_parts = line.split(bssid, 1)[0].strip()
                            ssid = ssid_parts if ssid_parts else WAP_TEMPLATE['ssid']
                        else:
                            continue  # Skip line if BSSID location cannot be reliably found

                        # Convert RSSI (dBm) to a rough percentage (0-100)
                        signal_percent = f"{min(max(2 * (int(rssi_dbm) + 100), 0), 100)}%"
                        bssid_formatted = bssid.upper().replace('-', ':')

                        waps[bssid_formatted] = {
                            'bssid': bssid_formatted,
                            'ssid': ssid or WAP_TEMPLATE['ssid'],
                            'signal': signal_percent,
                            'channel': channel_raw,
                            'band': 'N/A',
                            'auth': 'N/A',
                            'encryption': 'N/A'
                        }

            except Exception as e:
                logging.critical(f"macOS 'airport' failed. Cannot retrieve WAPs. ({type(e).__name__})")

        # --- Linux: FORCED active scan using nmcli ---
        elif sys.platform.startswith("linux"):
            log_scan_info("Running Linux scan ('nmcli'). Forcing active rescan...")

            # 1. Execute rescan command to force an active scan
            try:
                subprocess.run(
                    ['nmcli', 'dev', 'wifi', 'rescan'],
                    capture_output=True, text=True, check=True, timeout=5
                )
                time.sleep(1.0)
            except Exception as e:
                logging.warning(f"'nmcli rescan' failed, proceeding with cached results. Error: {e}")

            # 2. List the results in terse mode
            cmd = ['nmcli', '-t', '-f', 'BSSID,SSID,SIGNAL,CHAN', 'dev', 'wifi', 'list']

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=9)
                lines = result.stdout.strip().split('\n')

                # FIX: Implement robust parsing for nmcli -t output to handle escaped colons (\:)
                for line in lines:
                    # Fields are: BSSID:SSID:SIGNAL:CHAN
                    parts = line.split(':')

                    if len(parts) < 4:
                        continue

                    # 1. BSSID is the first field. It contains escaped colons (\:).
                    bssid_raw_escaped = parts[0].strip()
                    # FIX: Unescape the BSSID first by replacing '\:' with a simple ':'
                    bssid_formatted = bssid_raw_escaped.replace(r'\:', ':').upper()

                    # 2. SIGNAL and CHAN are always the last two parts
                    signal_percent = parts[-2].strip()
                    channel = parts[-1].strip()

                    # 3. SSID is everything in between (from index 1 up to index -2)
                    ssid_raw_escaped = ':'.join(parts[1:-2]).strip()

                    # Unescape the SSID by replacing '\:' with a simple ':'
                    ssid = ssid_raw_escaped.replace(r'\:', ':')

                    if not bssid_formatted or not signal_percent or not channel:
                        continue

                        # Check for empty SSID
                    final_ssid = ssid if ssid else WAP_TEMPLATE['ssid']

                    waps[bssid_formatted] = {
                        'bssid': bssid_formatted,
                        'ssid': final_ssid,
                        'signal': f"{signal_percent}%",
                        'channel': channel or 'N/A',
                        'band': 'N/A',
                        'auth': 'N/A',
                        'encryption': 'N/A'
                    }

            except Exception as e:
                logging.critical(f"Linux 'nmcli list' failed. Cannot retrieve WAPs. ({type(e).__name__})")

    return waps


def display_initial_waps(waps_dict):
    """
    Displays all WAPs currently in the cache upon initialization to both
    the console (CLI) and the log file (LOG-INFO).
    """
    count = len(waps_dict)
    separator = "-" * 100

    # Collect all lines to be displayed/logged
    lines_to_output = []

    if count == 0:
        lines_to_output.append(separator)
        lines_to_output.append("--- Initial WAP Cache Content: No WAPs detected. ---")
        lines_to_output.append(separator)

    else:
        # 1. Header (FIX: Removed the leading '\n' to prevent blank line in file log)
        lines_to_output.append(separator)
        lines_to_output.append(f"--- Initial WAP Cache Content ({count} WAP{'s' if count > 1 else ''} Detected) ---")

        # 2. Column headers
        lines_to_output.append(f"{'BSSID':<20} {'SSID':<30} {'Signal':<10} {'Channel':<10} {'Band':<10} {'Auth':<15}")
        lines_to_output.append(separator)

        # 3. WAP entries
        # Sort for consistent display (e.g., by SSID then BSSID)
        sorted_waps = sorted(waps_dict.values(), key=lambda w: (w['ssid'] or "ZZZ", w['bssid']))
        for wap in sorted_waps:
            # Get fields with fallback to N/A
            ssid_display = wap.get('ssid') if wap.get('ssid') and wap.get(
                'ssid') != 'Hidden/Unknown' else "(Hidden SSID)"
            bssid = wap.get('bssid', 'N/A')
            signal = wap.get('signal', 'N/A')
            channel = wap.get('channel', 'N/A')
            band = wap.get('band', 'N/A')
            auth = wap.get('auth', 'N/A')

            lines_to_output.append(f"{bssid:<20} {ssid_display:<30} {signal:<10} {channel:<10} {band:<10} {auth:<15}")

        # 4. Footer
        lines_to_output.append(separator)

    # Output the collected lines to both CLI and Log (FIX: This ensures CLI visibility)
    for line in lines_to_output:
        # Print to console (CLI)
        print(line)
        # Log to file (LOG-INFO, level 15)
        log_scan_info(line)


# --- Monitor and Alarm Logic ---

def monitor_loop():
    """Main loop for WAP monitoring."""

    global previous_waps
    previous_waps = {}

    try:
        # Initial scan to populate the first list
        current_waps = scan_waps()
        previous_waps = current_waps

        # Initial logs now use logging.info and log_scan_info
        logging.info("WAP Monitor initialized successfully.")

        # Log the initial summary message (INFO level)
        logging.info(f"Monitoring started with {len(current_waps)} initial WAPs in cache.")

        # Display/Log the initial WAP details (now prints to console AND logs to file)
        display_initial_waps(current_waps)

        while True:
            time.sleep(SCAN_INTERVAL_SECONDS)
            current_waps = scan_waps()

            current_bssids = set(current_waps.keys())
            previous_bssids = set(previous_waps.keys())

            new_bssids = current_bssids - previous_bssids
            removed_bssids = previous_bssids - current_bssids

            if new_bssids or removed_bssids:
                current_time = time.strftime('%H:%M:%S')

                new_count = len(new_bssids)
                removed_count = len(removed_bssids)

                # Summary prints remain the same (via standard print, not logging)
                if new_count > 0:
                    print(f"\n[{current_time}] ** {new_count} NEW WAP{'s' if new_count > 1 else ''} detected: **")
                if removed_count > 0:
                    if new_count == 0:
                        print(
                            f"\n[{current_time}] ** {removed_count} WAP{'s' if removed_count > 1 else ''} removed: **")
                    else:
                        print(f"[{current_time}] ** {removed_count} WAP{'s' if removed_count > 1 else ''} removed: **")

                # 1. Handle NEW WAPs (Unified Logging Output)
                for bssid in new_bssids:
                    wap = current_waps[bssid]

                    ssid_display = wap['ssid'] if wap['ssid'] and wap['ssid'] != 'Hidden/Unknown' else "(Hidden SSID)"

                    # Log message is now the full, un-prefixed line, allowing the formatter to add [TIME] ALERT:
                    alert_message = (
                        f"[NEW] BSSID: {bssid} | SSID: {ssid_display} | Sig: {wap['signal']} | "
                        f"Ch: {wap['channel']} | Auth: {wap['auth']}"
                    )

                    # We only log. The console handler will print this line, replacing WARNING with ALERT.
                    logging.warning(alert_message)
                    play_system_sound(NEW_WAP_ALARM['filename'])

                # 2. Handle REMOVED WAPs (Unified Logging Output)
                for bssid in removed_bssids:
                    wap_name = previous_waps.get(bssid, {}).get('ssid', 'Unknown SSID')

                    alert_message = f"[GONE] BSSID: {bssid} | Last known SSID: {wap_name}"

                    # We only log. The console handler will print this line, replacing WARNING with ALERT.
                    logging.warning(alert_message)
                    play_system_sound(REMOVED_WAP_ALARM['filename'])

            else:
                # If no changes, use log_scan_info (level 15) to ensure it is
                # logged to the file as 'LOG-INFO' but is suppressed from the console (level 20).
                log_scan_info(f"Scan complete: No new or removed WAPs detected. Total WAPs: {len(current_waps)}.")

            # Update the previous state for the next comparison
            previous_waps = current_waps

    except KeyboardInterrupt:
        # FIX: Remove print statement to avoid duplicate output. Rely on logging.info().
        logging.info("Monitor stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        # Use critical level for fatal crashes
        logging.critical(f"A fatal error occurred in the monitoring loop: {e}", exc_info=True)


def setup_logging(log_enabled):
    """Sets up the logging handlers based on the --log argument and uses the custom formatter."""

    # 1. Define custom log level/name
    logging.addLevelName(SCAN_LOG_LEVEL, 'LOG-INFO')

    root_logger = logging.getLogger()
    # Set root logger level to SCAN_LOG_LEVEL (15) so it doesn't filter out
    # the detailed scan messages before they reach the file handler.
    root_logger.setLevel(SCAN_LOG_LEVEL)

    # Define the core alert format string
    ALERT_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s'  # Time ALERT: Message

    # 1. Console Handler (Filters out SCAN_LOG_LEVEL=15)
    console_handler = logging.StreamHandler(sys.stdout)
    # Set level to INFO (20). This ignores custom level 15 (LOG-INFO/scan details)
    # but still shows INFO (20) for startup/critical status, and WARNING (30) for alerts.
    console_handler.setLevel(logging.INFO)

    # Use the custom formatter for ALERT mapping and the new format string
    console_handler.setFormatter(AlertFormatter(ALERT_FORMAT, datefmt='%H:%M:%S'))
    root_logger.addHandler(console_handler)

    if log_enabled:
        # 2. File Handler (Enabled only if --log is passed)
        try:
            # Insert an empty line at the start of a new session in the log file.
            with open(LOG_FILE, 'a') as f:
                f.write('\n')

            file_handler = logging.FileHandler(LOG_FILE, mode='a')
            # Set level to SCAN_LOG_LEVEL (15) to capture all messages, including LOG-INFO
            file_handler.setLevel(SCAN_LOG_LEVEL)

            # Use the custom formatter which will ensure level 15 is printed as 'LOG-INFO'
            file_handler.setFormatter(AlertFormatter('%(asctime)s - %(levelname)s - %(message)s'))
            root_logger.addHandler(file_handler)

            # Use logging.info() for this message so it gets timestamped and logged.
            logging.info(f"File logging enabled (-l/--log). Event history saved to: {LOG_FILE}")
        except Exception as e:
            # We use a simple print here since logging might not be fully configured yet
            print(f"[{time.strftime('%H:%M:%S')}] [SETUP ERROR] Could not set up file logging: {e}")
            global LOG_ENABLED
            LOG_ENABLED = False


def main():
    """Parses arguments and orchestrates the monitor setup."""
    parser = argparse.ArgumentParser(
        description="A simple, fast Wi-Fi Access Point (WAP) change monitor."
    )
    parser.add_argument(
        '-l', '--log',
        action='store_true',
        help=f'Enables persistent logging to the {LOG_FILE} file.'
    )
    parser.add_argument(
        '-a', '--alarm',
        action='store_true',
        help='Enables sound alarm generation and playback for new/removed WAPs.'
    )

    args = parser.parse_args()

    # Set global flags based on arguments
    global LOG_ENABLED, ALARM_ENABLED
    LOG_ENABLED = args.log
    ALARM_ENABLED = args.alarm

    # Use print here as this is always shown at startup, before logging is configured
    print("--- Simple Wi-Fi Access Point Monitor Initializing ---")

    # 1. Setup logging system
    setup_logging(LOG_ENABLED)

    # 2. Generate alarms (conditional)
    if ALARM_ENABLED:
        generate_required_alarms()
        # Use logging.info() for timestamping and logging.
        logging.info("Alarms enabled (--alarm/-a).")
    #    else:
    #        # If alarms are not enabled, we log that status too.
    #        logging.info("Alarms disabled.")

    # Use logging.info() for timestamping and logging.
    logging.info(f"Polling every {SCAN_INTERVAL_SECONDS}s. Press Ctrl+C to stop.")

    # 3. Start main loop
    monitor_loop()


if __name__ == "__main__":
    # Ensure SCAN_LOG_LEVEL is set up before main is called, though setup_logging does it too.
    main()
