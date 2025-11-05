import csv
import binascii
import re
import os
from collections import defaultdict


def find_and_clean_hex(payload_str):
    """
    Finds the start of the hex payload (marker '9301') and returns a clean, even-length hex string.
    """
    match = re.search(r'(9301[a-fA-F0-9]*)', payload_str)
    if not match:
        return None
    hex_part = match.group(1)
    return hex_part if len(hex_part) % 2 == 0 else hex_part[:-1]


def extract_video_stream(csv_path, output_file):
    """
    Extracts an H.264 video stream, with added debugging to show the NAL unit type
    being detected for each packet.
    """
    print(f"--- Starting H.264 Stream Extraction (with NAL Debug) from {csv_path} ---")

    drone_ip = "192.168.169.1"
    total_header_size_bytes = 44
    h264_start_code = b'\x00\x00\x00\x01'

    parameter_sets = {}
    frames = defaultdict(dict)

    packets_processed = 0
    drone_packets_found = 0

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

                        if len(raw_bytes) > total_header_size_bytes:
                            nal_unit_data = raw_bytes[total_header_size_bytes:]
                            if not nal_unit_data:
                                continue

                            nal_unit_type = nal_unit_data[0] & 0x1F

                            # --- DEBUGGING --- #
                            print(f"Packet {row[0]}: Found NAL Unit Type: {nal_unit_type}")
                            # ----------------- #

                            if nal_unit_type == 7 or nal_unit_type == 8:  # SPS or PPS
                                parameter_sets[nal_unit_type] = nal_unit_data
                                packets_processed += 1
                            elif nal_unit_type == 1 or nal_unit_type == 5:  # Video Frame Data
                                frame_number = raw_bytes[8]
                                part_number = int.from_bytes(raw_bytes[32:36], 'little')
                                frames[frame_number][part_number] = nal_unit_data
                                packets_processed += 1

                except (IndexError, ValueError, binascii.Error) as e:
                    print(f"[ERROR] Row {i + 2}: {e}. Skipping packet.")
                    continue

        print(f"\n--- Assembly Phase ---")
        print(f"Found {drone_packets_found} packets from drone.")
        print(f"Identified {len(parameter_sets)} parameter set(s) (SPS/PPS).")
        print(f"Assembled {packets_processed - len(parameter_sets)} video packets into {len(frames)} unique frames.")

        if not frames or not parameter_sets:
            print("[FATAL] Critical components (SPS/PPS or frames) are missing. Cannot write video file.")
            return

        with open(output_file, 'wb') as outfile:
            for nal_type in sorted(parameter_sets.keys()):
                outfile.write(h264_start_code + parameter_sets[nal_type])

            for frame_number in sorted(frames.keys()):
                parts = frames[frame_number]
                full_frame_data = b''.join(parts[p] for p in sorted(parts.keys()))
                outfile.write(h264_start_code + full_frame_data)

        print(f"\n--- Extraction Complete ---")
        print(f"Successfully created video stream: {output_file}")

    except FileNotFoundError:
        print(f"[FATAL] The file {csv_path} was not found.")
    except Exception as e:
        print(f"[UNHANDLED ERROR] An unexpected error occurred: {e}")


if __name__ == '__main__':
    extract_video_stream('vidcap.csv', 'video.h264')
