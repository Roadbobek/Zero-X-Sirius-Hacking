import csv
import re


def analyze_packets(csv_path):
    """
    Performs a low-level analysis of every packet from the drone to identify
    different packet structures, specifically to find SPS/PPS packets.

    Args:
        csv_path (str): The path to the input CSV file.
    """
    print(f"--- Starting Low-Level Packet Analysis for {csv_path} ---")

    drone_ip = "192.168.169.1"

    try:
        with open(csv_path, 'r', encoding='latin-1') as infile:
            reader = csv.reader(infile)
            header = next(reader)
            source_col = header.index("Source")
            length_col = header.index("Length")
            data_col = header.index("Delta") if "Delta" in header else header.index("Data")

            print("\n[FORMAT]: Packet No. | Length | First 16 Bytes of Data | Contains '9301' Marker?")
            print("-" * 80)

            for i, row in enumerate(reader):
                if row[source_col] == drone_ip:
                    packet_num = row[0]
                    length = row[length_col]
                    raw_data = row[data_col]

                    # Clean the hex data for analysis
                    # This regex is more general to capture any hex-like string
                    match = re.search(r'([a-fA-F0-9]{4,})', raw_data)
                    if match:
                        hex_data = match.group(1)
                        first_bytes = hex_data[:32]  # Show first 16 bytes (32 hex chars)
                        has_marker = "Yes" if '9301' in hex_data else "No"
                        print(f"{packet_num.ljust(10)} | {length.ljust(6)} | {first_bytes.ljust(34)} | {has_marker}")
                    else:
                        print(f"{packet_num.ljust(10)} | {length.ljust(6)} | No parsable hex data found.      | No")

        print("\n--- Analysis Complete ---")

    except FileNotFoundError:
        print(f"[FATAL] The file {csv_path} was not found.")
    except (ValueError, IndexError) as e:
        print(f"[FATAL] CSV format error: {e}. Please ensure it's a valid Wireshark export.")


if __name__ == '__main__':
    analyze_packets('vidcap.csv')
