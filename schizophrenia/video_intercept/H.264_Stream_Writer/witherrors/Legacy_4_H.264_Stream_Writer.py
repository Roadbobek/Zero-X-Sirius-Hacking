import csv
import binascii
import re
import os

# --- CONFIGURATION ---
FRAME_ID_OFFSET = 8
FRAME_ID_SIZE = 2
FRAGMENT_INDEX_OFFSET = 32
FRAGMENT_INDEX_SIZE = 1
DATA_PAYLOAD_OFFSET = FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE

# H.264 NAL Unit Signatures (Search Patterns)
NAL_START_CODE = b'\x00\x00\x00\x01'
SPS_NAL_TYPE = b'\x67' # NAL unit type 7 (SPS)
PPS_NAL_TYPE = b'\x68' # NAL unit type 8 (PPS)

# --- UTILITY FUNCTIONS (Data Loading and Reassembly) ---

def load_packets_from_csv(filepath):
    """Loads raw hex packet data from a Wireshark-exported CSV file including a Delta data.data column using 'latin-1' encoding."""
    raw_packet_data = []
    hex_start_pattern = re.compile(r'[^0-9a-fA-F]*([0-9a-fA-F]+)', re.IGNORECASE)

    try:
        with open(filepath, mode='r', encoding='latin-1') as file:
            reader = csv.reader(file, dialect='excel')
            try:
                next(reader) 
            except StopIteration:
                return []

            for i, row in enumerate(reader):
                if len(row) < 8:
                    continue

                raw_data_field = row[7].strip()
                match = hex_start_pattern.match(raw_data_field)
                
                if match:
                    clean_hex = match.group(1).replace(' ', '').lower()
                    
                    if len(clean_hex) > DATA_PAYLOAD_OFFSET * 2:
                        raw_packet_data.append(clean_hex)
                
    except FileNotFoundError:
        print(f"\nError: File not found at path: {filepath}")
        return None
    except Exception as e:
        print(f"\nAn error occurred while parsing the CSV file: {e}")
        return None

    return raw_packet_data

def extract_fragment_info(raw_hex_packet):
    """Extracts Frame ID, Fragment Index, and H.264 payload data."""
    try:
        packet_bytes = binascii.unhexlify(raw_hex_packet)
        frame_id_bytes = packet_bytes[FRAME_ID_OFFSET : FRAME_ID_OFFSET + FRAME_ID_SIZE]
        frame_id = frame_id_bytes.hex()
        fragment_index_bytes = packet_bytes[FRAGMENT_INDEX_OFFSET : FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE]
        fragment_index = int(fragment_index_bytes.hex(), 16) 
        payload_data = packet_bytes[DATA_PAYLOAD_OFFSET:]
        return frame_id, fragment_index, payload_data
    except Exception:
        return None, None, None

def reassemble_stream(fragments_map):
    """Reassembles the fragments into complete frames, sorted by index."""
    reassembled_frames = {}
    print("\n--- Phase 2: Reassembling Frames ---")

    for frame_id, fragments in fragments_map.items():
        fragment_list = [(index, data) for index, data in fragments.items()]
        fragment_list.sort(key=lambda x: x[0])
        full_frame_bytes = b"".join([data for index, data in fragment_list])
        reassembled_frames[frame_id] = full_frame_bytes
        
    print(f"Successfully reassembled {len(reassembled_frames)} distinct video frames.")
    return reassembled_frames

def search_for_headers(reassembled_frames):
    """
    Searches for the SPS/PPS NAL unit type bytes and robustly segments the payloads.
    Uses a constrained search window for the PPS/Slice boundary to prevent over-segmentation.
    Returns raw payloads without NAL_START_CODE prepended.
    """
    found_sps = None
    found_pps = None
    idr_frame_id = None
    idr_slice_data = None

    print("\n--- Phase 3: Searching for SPS/PPS Headers (Constrained Segmentation) ---")
    
    # Only check the keyframe '0100' where the headers are known to reside
    for frame_id, frame_data in reassembled_frames.items():
        if frame_id != '0100':
            continue

        # 1. Search for SPS NAL Type byte (0x67)
        sps_index = frame_data.find(SPS_NAL_TYPE)
        if sps_index == -1:
            continue
            
        # 2. Search for PPS NAL Type byte (0x68)
        # Search for PPS in a small window (up to 50 bytes) after SPS starts
        pps_index = -1
        search_window_end = min(sps_index + 50, len(frame_data))
        for i in range(sps_index + 1, search_window_end):
            if frame_data[i:i+1] == PPS_NAL_TYPE:
                pps_index = i
                break

        if pps_index == -1:
            continue

        # Segment 1: SPS NALU Payload (from 0x67 up to, but not including, 0x68)
        raw_sps_payload = frame_data[sps_index:pps_index]
        sps_length = len(raw_sps_payload)
        
        # 3. Search for the next NAL slice type byte (0x65, 0x41, etc.)
        # CRITICAL FIX: The PPS should be short. Force the search for the IDR slice
        # start byte to be within the next 12 bytes after the PPS starts.
        idr_slice_index = -1
        max_pps_segment_search = 12 
        search_start = pps_index + 1
        search_end = min(search_start + max_pps_segment_search, len(frame_data))

        # Check for common slice NAL types (IDR 0x65, P-Slice 0x41/0x61, 0x01/0x05)
        for nal_type in [b'\x65', b'\x45', b'\x61', b'\x41', b'\x05', b'\x01']: 
            idr_slice_index_raw = frame_data.find(nal_type, search_start, search_end)
            
            if idr_slice_index_raw != -1:
                if idr_slice_index == -1 or idr_slice_index_raw < idr_slice_index:
                    idr_slice_index = idr_slice_index_raw

        if idr_slice_index != -1:
            # Segment 2: PPS NALU Payload (from 0x68 up to the start of the IDR slice)
            raw_pps_payload = frame_data[pps_index:idr_slice_index]
            pps_length = len(raw_pps_payload)
            
            idr_frame_id = frame_id
            # Segment 3: IDR Slice (from its NAL type byte to the end of the frame)
            raw_idr_slice = frame_data[idr_slice_index:]

            found_sps = {'frame_id': frame_id, 'data': raw_sps_payload}
            found_pps = {'frame_id': frame_id, 'data': raw_pps_payload}
            idr_slice_data = raw_idr_slice
            
            print(f"--> FOUND SPS in Frame ID {frame_id}! (Length: {sps_length} bytes)")
            print(f"--> FOUND PPS in Frame ID {frame_id}! (Length: {pps_length} bytes)")
            print(f"--> IDENTIFIED IDR Slice payload following headers in Frame ID {idr_frame_id}!")
            break

    return found_sps, found_pps, idr_frame_id, idr_slice_data

def write_h264_stream(reassembled_frames, sps_result, pps_result, idr_frame_id, idr_slice_data, output_filename="output.h264"):
    """
    Writes the full H.264 stream to a binary file using the required H.264 Annex B format:
    NAL_START_CODE + NAL_UNIT_PAYLOAD for every single NAL unit.
    """
    print(f"\n--- Phase 5: Writing H.264 Stream to {output_filename} (Annex B Format) ---")
    
    if not sps_result or not pps_result or not idr_slice_data:
        print("Error: Missing SPS, PPS, or IDR Slice data. Cannot write file.")
        return

    try:
        with open(output_filename, 'wb') as f:
            # 1. Write the SPS header (with NAL_START_CODE)
            f.write(NAL_START_CODE)
            f.write(sps_result['data'])
            
            # 2. Write the PPS header (with NAL_START_CODE)
            f.write(NAL_START_CODE)
            f.write(pps_result['data'])
            
            print("Wrote SPS and PPS Configuration Headers.")

            # 3. Write the initial IDR Slice (the first video frame data) (with NAL_START_CODE)
            f.write(NAL_START_CODE)
            f.write(idr_slice_data)
            print(f"Wrote initial IDR Keyframe slice (Frame ID {idr_frame_id}).")

            # 4. Write all subsequent frames (P-slices/B-slices)
            frames_written = 1
            for frame_id, frame_data in reassembled_frames.items():
                if frame_id == idr_frame_id:
                    # Skip the IDR frame, as we already wrote its parts (SPS, PPS, IDR Slice)
                    continue
                
                # Prepend the Start Code Prefix to every subsequent frame payload 
                f.write(NAL_START_CODE)
                f.write(frame_data)
                frames_written += 1
                
            print(f"Wrote {frames_written - 1} subsequent video slices.")
            print(f"✅ FINAL SUCCESS: Wrote a total of {frames_written} NAL units to {output_filename}.")
            
    except Exception as e:
        print(f"\nError writing H.264 file: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    
    csv_filename = input("Please enter the name of your Wireshark CSV file including a Delta data.data column (e.g., video_capture.csv): ")
    
    print(f"\nAttempting to load data from {csv_filename}...")
    RAW_PACKET_DATA = load_packets_from_csv(csv_filename)
    
    if RAW_PACKET_DATA is None:
        exit()

    if not RAW_PACKET_DATA:
        print("No valid video packets were found in the file. Ensure the file is a correct Wireshark CSV export including a Delta data.data column.")
        exit()

    print(f"Starting H.264 Reassembly and Stream Writing. Analyzing {len(RAW_PACKET_DATA)} raw packets.")
    print("----------------------------------------------------------------------")
    
    # Phase 1: Data Structuring (Extract and Group)
    frame_fragments = {}
    for raw_hex in RAW_PACKET_DATA:
        frame_id, fragment_index, payload_data = extract_fragment_info(raw_hex)
        
        if frame_id and fragment_index is not None and payload_data:
            if frame_id not in frame_fragments:
                frame_fragments[frame_id] = {}
            
            frame_fragments[frame_id][fragment_index] = payload_data
        
    # Phase 2: Stream Reassembly
    reassembled_frames = reassemble_stream(frame_fragments)

    # Phase 3: Header Search and IDR Slice Identification
    sps_result, pps_result, idr_frame_id, idr_slice_data = search_for_headers(reassembled_frames)

    # Phase 4: Reporting
    print("\n--- Phase 4: Header Confirmation ---")
    if sps_result and pps_result and idr_slice_data:
        print("Configuration Headers and IDR Slice successfully isolated.")
        
        # Phase 5: Write the H.264 file
        write_h264_stream(reassembled_frames, sps_result, pps_result, idr_frame_id, idr_slice_data)
        print("\n>>> NEXT STEP: Locate 'output.h264' and attempt to play it with VLC or ffplay!")
    else:
        print("\n⚠️ FAILURE: Could not find all necessary components (SPS/PPS/IDR Slice) for writing the file.")
        print("Review the data or capture another stream starting from the video's beginning.")
