import csv
import binascii
import re

def find_and_clean_hex(payload_str):
    """
    Finds the start of the hex payload (marker '9301') and returns a clean, even-length hex string.
    """
    match = re.search(r'(9301[a-fA-F0-9]*)', payload_str)
    if not match:
        return None
    hex_part = match.group(1)
    return hex_part if len(hex_part) % 2 == 0 else hex_part[:-1]

def ground_truth_test(csv_path):
    """
    Isolates the first drone packet and prints a byte-by-byte hex dump
    to establish a ground truth for debugging.
    """
    print(f"--- Starting Ground Truth Byte Analysis for {csv_path} ---")

    drone_ip = "192.168.169.1"

    try:
        with open(csv_path, 'r', encoding='latin-1') as infile:
            reader = csv.reader(infile)
            header = next(reader)
            source_col = header.index("Source")
            data_col = header.index("Delta") if "Delta" in header else header.index("Data")

            for i, row in enumerate(reader):
                if row[source_col] == drone_ip:
                    print(f"Found first drone packet at row {i+2} (Packet No. {row[0]}). Processing...\n")
                    
                    hex_payload = find_and_clean_hex(row[data_col])
                    if not hex_payload:
                        print("[FATAL] Could not find hex payload in the first drone packet.")
                        return

                    raw_bytes = binascii.unhexlify(hex_payload)

                    print("Byte-by-byte hex dump of the first 50 bytes:")
                    print("Index | Hex | Dec | Char")
                    print("---------------------------")
                    for i in range(50):
                        byte = raw_bytes[i]
                        char = chr(byte) if 32 <= byte <= 126 else '.'
                        print(f"{str(i).ljust(5)} | {hex(byte)[2:].zfill(2).ljust(3)} | {str(byte).ljust(3)} | {char}")
                    
                    print("\n--- Ground Truth Test Complete ---")
                    # We only process the first packet, so we exit.
                    return 

    except (FileNotFoundError, ValueError, IndexError, binascii.Error) as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == '__main__':
    ground_truth_test('vidcap.csv')
