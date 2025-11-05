import csv
import os
from typing import List, Dict, Any

# --- Configuration ---
# Set the name of the CSV file to be read.
# Ensure this file exists in the same directory as the script.
CSV_FILE_PATH = '_OUTPUT_drone_packets.csv'

def hex_to_byte_list(hex_string: str) -> List[int]:
    """Converts a hexadecimal string into a list of integer byte values."""
    # Handle incomplete or invalid hex strings
    if not hex_string or len(hex_string) % 2 != 0:
        return []
    try:
        # Iterate over the string two characters at a time and convert to int from hex base
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    except ValueError:
        print(f"Warning: Failed to parse hex string starting with '{hex_string[:10]}...'")
        return []

def load_data(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads data from the specified CSV file path.
    Each row's 'Hex_Data' is converted to a list of integer bytes.
    """
    if not os.path.exists(filepath):
        print(f"Error: CSV file not found at '{filepath}'. Please ensure the file is saved correctly.")
        return []

    data = []
    print(f"Loading data from {filepath}...")

    try:
        with open(filepath, 'r', newline='') as csvfile:
            # Use csv.DictReader to automatically use the header row (No, Time, Hex_Data) as keys
            reader = csv.DictReader(csvfile)
            for row in reader:
                hex_data = row.get('Hex_Data', '')
                if hex_data:
                    # Convert the 'Hex_Data' string to a list of integer bytes
                    row['Bytes'] = hex_to_byte_list(hex_data)
                    row['Length'] = len(row['Bytes'])

                    # Convert metadata to appropriate types for easier comparison/logging
                    try:
                        row['No'] = int(row.get('No', -1))
                        row['Time'] = float(row.get('Time', 0.0))
                    except (ValueError, TypeError):
                        pass # Keep as string if conversion fails

                    data.append(row)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return []

    print(f"Successfully loaded {len(data)} data records.")
    return data

def compare_packets(packets: List[Dict[str, Any]]):
    """
    Compares consecutive packets of the same length and prints the differences.
    """
    print("--- Byte-Level Differential Analysis ---")

    # 1. Group packets by length to ensure meaningful comparisons
    packets_by_length = {}
    for p in packets:
        length = p.get('Length')
        if length is not None and length > 0:
            if length not in packets_by_length:
                packets_by_length[length] = []
            packets_by_length[length].append(p)

    if not packets_by_length:
        print("No valid packets found to compare.")
        return

    # 2. Iterate through each group of packets with the same length
    for length, group in packets_by_length.items():
        if len(group) < 2:
            continue  # Need at least two packets to compare

        print(f"\nAnalyzing Packet Group (Length: {length} bytes) - Found {len(group)} packets.")

        # 3. Iterate over consecutive pairs (i-1 vs i) in the group
        for i in range(1, len(group)):
            prev_packet = group[i-1]
            curr_packet = group[i]

            prev_bytes = prev_packet['Bytes']
            curr_bytes = curr_packet['Bytes']

            # Find differing bytes by comparing the byte arrays element by element
            min_len = min(len(prev_bytes), len(curr_bytes))
            diff_indices = [j for j in range(min_len) if prev_bytes[j] != curr_bytes[j]]

            if not diff_indices:
                print(f"  [No. {prev_packet.get('No')} vs No. {curr_packet.get('No')}] -> Identical payloads. Skipping.")
                continue

            print(f"\n  Comparison between (Prev) No. {prev_packet.get('No')} and (Curr) No. {curr_packet.get('No')}:")
            print(f"  Time change: {curr_packet.get('Time', 0.0) - prev_packet.get('Time', 0.0):.2f}s")
            print(f"  Hex (Prev, start): {prev_packet['Hex_Data'][:40]}...")
            print(f"  Hex (Curr, start): {curr_packet['Hex_Data'][:40]}...")

            # Print the byte differences
            print("  --- Differences (Index | Prev Byte | Curr Byte) ---")
            for idx in diff_indices:
                prev_hex = f"{prev_bytes[idx]:02x}"
                curr_hex = f"{curr_bytes[idx]:02x}"
                print(f"  Byte Index {idx:02d}: {prev_hex} -> {curr_hex} (Decimal: {prev_bytes[idx]} -> {curr_bytes[idx]})")


if __name__ == '__main__':
    # 1. Load the data from the CSV file specified in CSV_FILE_PATH
    drone_packets = load_data(CSV_FILE_PATH)

    # 2. Run the differential analysis
    if drone_packets:
        compare_packets(drone_packets)
    else:
        print("Analysis stopped because no data could be loaded.")
