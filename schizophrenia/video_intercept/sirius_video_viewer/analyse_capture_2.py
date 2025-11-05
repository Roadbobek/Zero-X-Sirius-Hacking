import csv
import binascii
import re
import os


def find_and_clean_hex(payload_str):
    """
    Finds the start of the hex payload (marker '9301') and returns a clean, even-length hex string.
    """
    match = re.search(r'(9301[a-fA-F0-9]*)', payload_str)
    if not match:
        return None

    hex_part = match.group(1)

    if len(hex_part) % 2 != 0:
        return hex_part[:-1]

    return hex_part


def diagnose_nal_units(csv_path):
    """
    Diagnoses NAL unit types and their initial bytes for packets from the drone.
    This script does NOT produce a video file.
    """
    print(f"--- Starting NAL Unit Diagnostic for {csv_path} ---")

    drone_ip = "192.168.169.1"
    header_size_bytes = 42

    packets_analyzed = 0
    drone_packets_found = 0

    print("\n[FORMAT]: Packet No. | First 8 Bytes of NAL Unit (Hex) | NAL Unit Type (Calculated from first byte)")
    print("-" * 90)

    try:
        with open(csv_path, 'r', encoding='latin-1') as infile:
            reader = csv.reader(infile)
            header = next(reader)
            source_col = header.index("Source")
            data_col = header.index("Delta") if "Delta" in header else header.index("Data")

            for i, row in enumerate(reader):
                try:
                    if row[source_col] == drone_ip:
                        drone_packets_found += 1
                        hex_payload = find_and_clean_hex(row[data_col])
                        if not hex_payload:
                            continue

                        raw_bytes = binascii.unhexlify(hex_payload)

                        if len(raw_bytes) > header_size_bytes:
                            # This is the assumed NAL unit data after our custom header
                            nal_unit_data = raw_bytes[header_size_bytes:]

                            if nal_unit_data:
                                # Get the first byte of the NAL unit data
                                first_nal_byte = nal_unit_data[0]
                                # Calculate NAL unit type (first 5 bits)
                                nal_unit_type = first_nal_byte & 0x1F

                                # Display first 8 bytes of the NAL unit data in hex
                                first_8_bytes_hex = binascii.hexlify(nal_unit_data[:8]).decode('utf-8')

                                print(
                                    f"{row[0].ljust(10)} | {first_8_bytes_hex.ljust(32)} | {str(nal_unit_type).ljust(40)}")
                                packets_analyzed += 1

                except (IndexError, ValueError, binascii.Error) as e:
                    print(f"[ERROR] Row {i + 2}: {e}. Skipping packet.")
                    continue

        print(f"\n--- Diagnostic Complete ---")
        print(f"Analyzed {packets_analyzed} potential NAL units from {drone_packets_found} drone packets.")

    except FileNotFoundError:
        print(f"[FATAL] The file {csv_path} was not found.")
    except Exception as e:
        print(f"[UNHANDLED ERROR] An unexpected error occurred: {e}")


if __name__ == '__main__':
    diagnose_nal_units('vidcap.csv')
