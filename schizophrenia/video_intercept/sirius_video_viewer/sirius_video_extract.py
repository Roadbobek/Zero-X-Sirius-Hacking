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
    if len(hex_part) % 2 != 0:
        return hex_part[:-1]
    return hex_part

def extract_video_stream(csv_path, output_file):
    """
    Extracts a clean H.264 video stream by correctly identifying and separating
    SPS/PPS NAL units from video frames using the correct 44-byte header offset
    and correctly ignoring unknown NAL unit types.

    Args:
        csv_path (str): The path to the input CSV file.
        output_file (str): The path to save the final H.264 stream.
    """
    print(f"--- Starting Final H.264 Stream Extraction from {csv_path} ---")

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
                    if row[source_col] != drone_ip:
                        continue
                    
                    drone_packets_found += 1
                    hex_payload = find_and_clean_hex(row[data_col])
                    if not hex_payload:
                        continue

                    raw_bytes = binascii.unhexlify(hex_payload)

                    if len(raw_bytes) <= total_header_size_bytes:
                        continue

                    nal_unit_data = raw_bytes[total_header_size_bytes:]
                    if not nal_unit_data:
                        continue

                    nal_unit_type = nal_unit_data[0] & 0x1F

                    # NAL Unit Type 7: SPS, Type 8: PPS
                    if nal_unit_type == 7 or nal_unit_type == 8:
                        parameter_sets[nal_unit_type] = nal_unit_data
                        packets_processed += 1
                    # NAL Unit Type 1 or 5: Video Frame Data
                    elif nal_unit_type == 1 or nal_unit_type == 5:
                        frame_number = raw_bytes[8]
                        part_number = int.from_bytes(raw_bytes[32:36], 'little')
                        frames[frame_number][part_number] = nal_unit_data
                        packets_processed += 1
                    # else: All other NAL types (0, 6, etc.) are ignored.

                except (IndexError, ValueError, binascii.Error) as e:
                    print(f"[ERROR] Row {i+2}: {e}. Skipping packet.")
                    continue
        
        print(f"\n--- Assembly Phase ---")
        print(f"Found {drone_packets_found} packets from drone.")
        print(f"Identified {len(parameter_sets)} parameter set(s) (SPS/PPS).")
        print(f"Assembled {packets_processed - len(parameter_sets)} video packets into {len(frames)} unique frames.")

        if not frames or not parameter_sets:
            print("[FATAL] Critical components (SPS/PPS or frames) are missing. Cannot write video file.")
            return

        with open(output_file, 'wb') as outfile:
            # 1. Write the SPS and PPS packets first.
            for nal_type in sorted(parameter_sets.keys()):
                outfile.write(h264_start_code + parameter_sets[nal_type])
            
            # 2. Write the assembled frames, in order.
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
