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
MAX_SAFE_PPS_LENGTH = 8 

# --- UTILITY FUNCTIONS ---

def remove_emulation_prevention_bytes(data):
    """
    Removes H.264 Emulation Prevention Bytes (0x03) that follow 0x00 0x00.
    """
    return data.replace(b'\x00\x00\x03', b'\x00\x00')

def load_packets_from_csv(filepath):
    """Loads raw hex packet data from a Wireshark-exported CSV file."""
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
    Searches for headers, segments payloads, and handles PPS truncation/repair.
    """
    found_sps = None
    found_pps = None
    idr_frame_id = None
    idr_slice_data = None

    print("\n--- Phase 3: Searching for SPS/PPS Headers (Hybrid Truncation & Boundary Detection) ---")
    
    frame_data = reassembled_frames.get('0100')
    if not frame_data:
        return None, None, None, None
    
    frame_id = '0100'
    sps_length = 0
    pps_length = 0

    sps_index = frame_data.find(SPS_NAL_TYPE)
    if sps_index == -1: return None, None, None, None
        
    pps_index = -1
    search_window_end = min(sps_index + 100, len(frame_data))
    for i in range(sps_index + 1, search_window_end):
        if frame_data[i:i+1] == PPS_NAL_TYPE:
            pps_index = i
            break

    if pps_index == -1: return None, None, None, None

    # Segment 1: SPS NALU Payload
    raw_sps_payload = frame_data[sps_index:pps_index]
    sps_length = len(raw_sps_payload)
    
    # 3. Search for the next NAL slice type byte (0x65, 0x41, etc.)
    idr_slice_index = -1
    search_start = pps_index + 1
    search_end_slice = min(search_start + 50, len(frame_data)) 

    for nal_type in [b'\x65', b'\x45', b'\x05', b'\x01']: 
        idr_slice_index_raw = frame_data.find(nal_type, search_start, search_end_slice)
        if idr_slice_index_raw != -1:
            if idr_slice_index == -1 or idr_slice_index_raw < idr_slice_index:
                idr_slice_index = idr_slice_index_raw

    if idr_slice_index == -1:
        idr_slice_index = pps_index + MAX_SAFE_PPS_LENGTH
        
    # Initial Segment 2: PPS NALU Payload
    raw_pps_payload_initial = frame_data[pps_index:idr_slice_index]
    
    # Segment 3: IDR Slice
    raw_idr_slice = frame_data[idr_slice_index:]

    # --- CRITICAL REPAIR LOGIC (PPS TRUNCATION) ---
    if len(raw_pps_payload_initial) > MAX_SAFE_PPS_LENGTH:
        raw_pps_payload = raw_pps_payload_initial[:MAX_SAFE_PPS_LENGTH]
        excess_bytes = raw_pps_payload_initial[MAX_SAFE_PPS_LENGTH:]
        raw_idr_slice = excess_bytes + raw_idr_slice
        
        pps_length = len(raw_pps_payload)
        print(f"--> WARNING: PPS length ({len(raw_pps_payload_initial)} bytes) exceeded max safe length ({MAX_SAFE_PPS_LENGTH}).")
        print(f"--> PPS truncated to {pps_length} bytes. {len(excess_bytes)} bytes moved to IDR slice.")
    else:
        raw_pps_payload = raw_pps_payload_initial
        pps_length = len(raw_pps_payload)
        
    found_sps = {'frame_id': frame_id, 'data': raw_sps_payload}
    found_pps = {'frame_id': frame_id, 'data': raw_pps_payload}
    idr_slice_data = raw_idr_slice
    idr_frame_id = frame_id
    
    print(f"--> FOUND SPS in Frame ID {frame_id}! (Length: {sps_length} bytes)")
    print(f"--> FINAL PPS in Frame ID {frame_id}! (Length: {pps_length} bytes)")
    print(f"--> IDENTIFIED IDR Slice payload following headers in Frame ID {idr_frame_id}!")

    return found_sps, found_pps, idr_frame_id, idr_slice_data

def write_h264_stream(reassembled_frames, sps_result, pps_result, idr_frame_id, idr_slice_data):
    """
    Writes two H.264 streams and runs the diagnostic inspection.
    """
    output_full_filename = "output_full.h264"
    output_no_headers_filename = "output_no_headers.h264"
    
    print(f"\n--- Phase 5: Writing H.264 Streams (Hybrid Repair Applied) ---")
    
    if not sps_result or not pps_result or not idr_slice_data:
        print("Error: Missing SPS, PPS, or IDR Slice data. Cannot write file.")
        return

    # Prepare cleaned components once
    cleaned_sps = remove_emulation_prevention_bytes(sps_result['data'])
    cleaned_pps = remove_emulation_prevention_bytes(pps_result['data'])
    cleaned_idr = remove_emulation_prevention_bytes(idr_slice_data)
    
    total_nal_units = 0

    try:
        # --- File 1: Full Stream ---
        with open(output_full_filename, 'wb') as f:
            f.write(NAL_START_CODE); f.write(cleaned_sps)
            f.write(NAL_START_CODE); f.write(cleaned_pps)
            f.write(NAL_START_CODE); f.write(cleaned_idr)
            total_nal_units = 3

            for frame_id, frame_data in reassembled_frames.items():
                if frame_id == idr_frame_id: continue
                cleaned_frame = remove_emulation_prevention_bytes(frame_data)
                f.write(NAL_START_CODE); f.write(cleaned_frame)
                total_nal_units += 1
                
        # --- File 2: Headerless Stream ---
        nal_units_no_headers = 0
        with open(output_no_headers_filename, 'wb') as f:
            f.write(NAL_START_CODE); f.write(cleaned_idr)
            nal_units_no_headers += 1

            for frame_id, frame_data in reassembled_frames.items():
                if frame_id == idr_frame_id: continue
                cleaned_frame = remove_emulation_prevention_bytes(frame_data)
                f.write(NAL_START_CODE); f.write(cleaned_frame)
                nal_units_no_headers += 1
                
        print(f"Wrote FULL stream (SPS, PPS, {total_nal_units} slices) to {output_full_filename}.")
        print(f"Wrote HEADERLESS stream ({nal_units_no_headers} slices) to {output_no_headers_filename}.")

        print(f"✅ FINAL SUCCESS: Wrote a total of {total_nal_units + nal_units_no_headers} NAL units across both files.")
        
        # --- Diagnostic Inspection ---
        if os.path.exists(output_no_headers_filename):
            print("\n--- Diagnostic: Inspecting Headerless Start ---")
            with open(output_no_headers_filename, 'rb') as f:
                data = f.read(128) # Read first 128 bytes
            
            # Search for the first NAL start code (00 00 00 01)
            start_index = data.find(NAL_START_CODE)
            
            if start_index != -1:
                # The actual NAL unit payload starts 4 bytes after the start code
                payload_start = start_index + 4
                
                # Show the NAL unit header and surrounding data
                diagnostic_bytes = data[payload_start : payload_start + 32]
                diagnostic_hex = binascii.hexlify(diagnostic_bytes).decode('utf-8')
                
                # Format with spaces for readability
                formatted_hex = ' '.join(diagnostic_hex[i:i+2] for i in range(0, len(diagnostic_hex), 2))
                
                print(f"Hex Dump of the first 32 bytes (after 00 00 00 01 start code):")
                print(formatted_hex)
            else:
                print("Could not find NAL start code in headerless file.")
        
        print("\n>>> NEXT STEP: Provide the 'Hex Dump' output from the diagnostic.")
            
    except Exception as e:
        print(f"\nError writing H.264 file: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    csv_filename = input("Please enter the name of your Wireshark CSV file including a Delta data.data column (e.g., video_capture.csv): ")
    
    print(f"\nAttempting to load data from {csv_filename}...")
    RAW_PACKET_DATA = load_packets_from_csv(csv_filename)
    
    if RAW_PACKET_DATA is None: exit()

    if not RAW_PACKET_DATA:
        print("No valid video packets were found in the file.")
        exit()

    print(f"Starting H.264 Reassembly and Stream Writing. Analyzing {len(RAW_PACKET_DATA)} raw packets.")
    print("----------------------------------------------------------------------")
    
    frame_fragments = {}
    for raw_hex in RAW_PACKET_DATA:
        frame_id, fragment_index, payload_data = extract_fragment_info(raw_hex)
        if frame_id and fragment_index is not None and payload_data:
            if frame_id not in frame_fragments: frame_fragments[frame_id] = {}
            frame_fragments[frame_id][fragment_index] = payload_data
        
    reassembled_frames = reassemble_stream(frame_fragments)
    sps_result, pps_result, idr_frame_id, idr_slice_data = search_for_headers(reassembled_frames)

    print("\n--- Phase 4: Header Confirmation ---")
    if sps_result and pps_result and idr_slice_data:
        print("Configuration Headers and IDR Slice successfully isolated and repaired.")
        write_h264_stream(reassembled_frames, sps_result, pps_result, idr_frame_id, idr_slice_data)
    else:
        print("\n⚠️ FAILURE: Could not find all necessary components (SPS/PPS/IDR Slice) for writing the file.")
