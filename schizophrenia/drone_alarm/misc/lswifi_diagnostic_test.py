import subprocess
import json
import sys
import time
import os

# --- Configuration ---
# Command to execute lswifi and get JSON output
LSWIFI_CMD = ['lswifi', '-n', '1', '--json', '-all']
# Set a generous timeout to ensure the utility has time to run
LSWIFI_TIMEOUT = 10 

def run_lswifi_diagnostic():
    """
    Runs lswifi, captures output, and attempts to parse the JSON.
    Reports all diagnostic details clearly.
    """
    print("--- lswifi Diagnostic Test Starting ---")
    print(f"Platform detected: {sys.platform}")

    if sys.platform != "win32":
        print("\nWARNING: This test is designed specifically for Windows (which uses 'lswifi').")
        print("For Linux or macOS, the main monitor script uses 'nmcli' or 'afplay/aplay'. Exiting.")
        return

    start_time = time.time()
    
    try:
        print(f"Executing command: {' '.join(LSWIFI_CMD)} (Timeout: {LSWIFI_TIMEOUT}s)")
        
        # Execute the command, capturing all output and raising an error if it fails (check=True)
        result = subprocess.run(
            LSWIFI_CMD, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=LSWIFI_TIMEOUT
        )
        
        end_time = time.time()
        
        # Diagnostic Step 1: Execution Time
        execution_time = end_time - start_time
        print(f"\n[Execution Status] Command completed successfully in {execution_time:.2f} seconds.")
        
        # --- NEW: Print Raw JSON Output for Testing ---
        print("\n--- BEGIN RAW JSON OUTPUT ---")
        print(result.stdout)
        print("--- END RAW JSON OUTPUT ---\n")
        # ---------------------------------------------
        
        # Diagnostic Step 2: JSON Parsing
        try:
            # We read the output string directly from memory (result.stdout)
            data = json.loads(result.stdout)
            
            # Diagnostic Step 3: WAP Counting
            bssids = set()
            
            # NEW/PRIMARY CASE: Check for the simplest structure: a top-level list of WAP objects.
            # This matches the output provided by the user's latest test run.
            if isinstance(data, list) and all(isinstance(item, dict) and 'bssid' in item for item in data):
                print("DEBUG: Detected list of WAP objects (User's structure).")
                for bss in data:
                    if 'bssid' in bss:
                        # Normalize MAC address format
                        bssids.add(bss['bssid'].upper().replace('-', ':'))

            # Case 2: Check for the structure with a 'scan_data' key (older lswifi versions)
            elif isinstance(data, dict) and 'scan_data' in data and isinstance(data['scan_data'], list):
                print("DEBUG: Detected dictionary with 'scan_data' key.")
                for bss in data['scan_data']:
                    if 'bssid' in bss:
                        # Normalize MAC address format
                        bssids.add(bss['bssid'].upper().replace('-', ':'))
            
            # Case 3: Check for the older list of interface dictionaries with 'BSSList'
            elif isinstance(data, list):
                print("DEBUG: Detected list structure (Legacy or alternate format).")
                for interface in data:
                    if 'BSSList' in interface:
                        for bss in interface['BSSList']:
                            if 'BSSID' in bss:
                                bssids.add(bss['BSSID'].upper().replace('-', ':'))
            else:
                print("DEBUG: Detected unknown JSON structure.")


            print(f"[Parsing Status] JSON loaded successfully.")
            print(f"[Result] Total unique WAPs found: {len(bssids)}")

            if not bssids:
                 print("\n*** CRITICAL DIAGNOSIS ***")
                 print("The utility executed successfully and returned valid JSON, but the 'scan_data' list was empty.")
                 print("This confirms the issue is within the 'lswifi' utility's ability to complete a timely hardware scan.")
                 
            print("-" * 40)
            
        except json.JSONDecodeError as e:
            print("\n[Parsing FAILED] Could not decode output as JSON.")
            print(f"Error: {e}")
            print("\n--- BEGIN RAW OUTPUT (First 500 chars) ---")
            print(result.stdout[:500])
            print("--- END RAW OUTPUT ---")

    except FileNotFoundError:
        print(f"\n[Execution FAILED] 'lswifi' command not found. Ensure it is installed and in your PATH.")
    except subprocess.TimeoutExpired:
        print(f"\n[Execution FAILED] Command timed out after {LSWIFI_TIMEOUT} seconds.")
    except subprocess.CalledProcessError as e:
        print(f"\n[Execution FAILED] Command returned non-zero exit code ({e.returncode}).")
        print(f"Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"\n[UNEXPECTED ERROR] An unhandled exception occurred: {e}")

if __name__ == "__main__":
    run_lswifi_diagnostic()
