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

def find_nal_offset(csv_path):
    """
    Scans the payload of each packet at different offsets to find where the
    real H.264 NAL unit header might be located.
    """
    print(f"--- Starting H.264 NAL Unit Offset Analysis for {csv_path} ---")
    drone_ip = "192.168.169.1"
    header_size_bytes = 42
    max_offset_to_scan = 20  # Scan up to 20 bytes into the payload

    # Store potential NAL types found at each offset
    offset_nal_types = {i: set() for i in range(max_offset_to_scan)}
    packets_analyzed = 0

    try:
        with open(csv_path, 'r', encoding='latin-1') as infile:
            reader = csv.reader(infile)
            header = next(reader)
            source_col = header.index("Source")
            data_col = header.index("Delta") if "Delta" in header else header.index("Data")

            for i, row in enumerate(reader):
                if row[source_col] == drone_ip:
                    hex_payload = find_and_clean_hex(row[data_col])
                    if not hex_payload:
                        continue

                    raw_bytes = binascii.unhexlify(hex_payload)

                    if len(raw_bytes) > header_size_bytes + max_offset_to_scan:
                        payload = raw_bytes[header_size_bytes:]
                        packets_analyzed += 1
                        for offset in range(max_offset_to_scan):
                            # Check for the forbidden_zero_bit. Must be 0.
                            if (payload[offset] & 0x80) == 0:
                                nal_type = payload[offset] & 0x1F
                                offset_nal_types[offset].add(nal_type)
        
        print("\n--- Analysis Complete ---")
        print(f"Scanned {packets_analyzed} packets.")
        print("Found the following potential NAL unit types at each offset:")
        print("-------------------------------------------------------------")
        print("Offset | NAL Types Found")
        print("-------------------------------------------------------------")
        for offset, nal_types in offset_nal_types.items():
            if nal_types: # Only print offsets where we found valid NAL headers
                types_str = ", ".join(str(t) for t in sorted(list(nal_types)))
                print(f"{str(offset).ljust(6)} | {{ {types_str} }}")
        print("-------------------------------------------------------------")
        print("\nLook for an offset that contains types {1, 5, 7, 8} or a subset of these.")

    except (FileNotFoundError, ValueError, IndexError, binascii.Error) as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == '__main__':
    find_nal_offset('vidcap.csv')
