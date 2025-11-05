import csv
import binascii
import re
import os

# --- CRITICAL CONFIGURATION ---
# Determined from diagnostic: 00 19 a0 ... 73 40. This is the custom header length
# that must be stripped from the start of every video slice payload.
PROPRIETARY_HEADER_SKIP_BYTES = 19 
FRAME_ID_OFFSET = 8
FRAME_ID_SIZE = 2
FRAGMENT_INDEX_OFFSET = 32
FRAGMENT_INDEX_SIZE = 1
DATA_PAYLOAD_OFFSET = FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE

# H.264 NAL Unit Signatures (Search Patterns)
NAL_START_CODE = b'\x00\x00\x00\x01'
SPS_NAL_TYPE = b'\x67'  
PPS_NAL_TYPE = b'\x68'
MAX_SAFE_PPS_LENGTH = 8 

# --- CRITICAL CHANGE: These hardcoded placeholders are NO LONGER USED. 
# We now use the SPS/PPS discovered in the raw data itself.
STANDARD_SPS_INJECT = b'PLACEHOLDER_NOT_USED'
STANDARD_PPS_INJECT = b'PLACEHOLDER_NOT_USED'


# --- UTILITY FUNCTIONS ---

def remove_emulation_prevention_bytes(data):
    """
    Removes H.264 Emulation Prevention Bytes (0x03) that follow 0x00 0x00.
    """
    return data.replace(b'\x00\x00\x03', b'\x00\x00')

def load_packets_from_csv(filepath):
    """Loads raw hex packet data from a Wireshark-exported CSV file."""
    raw_packet_data = []
    # This regex is designed to find the first sequence of hex characters in the field
    hex_start_pattern = re.compile(r'[^0-9a-fA-F]*([0-9a-fA-F]+)', re.IGNORECASE)

    try:
        with open(filepath, mode='r', encoding='latin-1') as file:
            reader = csv.reader(file, dialect='excel')
            try:
                # Skip header row
                next(reader) 
            except StopIteration:
                return []

            for i, row in enumerate(reader):
                if len(row) < 8:
                    continue

                # Assuming row[7] contains the raw hex data string (Delta data.data)
                raw_data_field = row[7].strip()
                match = hex_start_pattern.match(raw_data_field)
                
                if match:
                    clean_hex = match.group(1).replace(' ', '').lower()
                    
                    if len(clean_hex) > DATA_PAYLOAD_OFFSET * 2: # * 2 because two hex chars make one byte
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
        # Fragment index is an integer value
        fragment_index = int(fragment_index_bytes.hex(), 16) 
        # Payload starts after the fixed header structure
        payload_data = packet_bytes[DATA_PAYLOAD_OFFSET:]
        return frame_id, fragment_index, payload_data
    except Exception:
        # Silently skip malformed packets
        return None, None, None

def reassemble_stream(fragments_map):
    """Reassembles the fragments into complete frames, sorted by index."""
    reassembled_frames = {}
    print("\n--- Phase 2: Reassembling Frames ---")

    for frame_id, fragments in fragments_map.items():
        # Convert dictionary to list of (index, data) tuples and sort by index
        fragment_list = [(index, data) for index, data in fragments.items()]
        fragment_list.sort(key=lambda x: x[0])
        # Concatenate the data payloads
        full_frame_bytes = b"".join([data for index, data in fragment_list])
        reassembled_frames[frame_id] = full_frame_bytes
        
    print(f"Successfully reassembled {len(reassembled_frames)} distinct video frames.")
    return reassembled_frames

def search_for_headers(reassembled_frames):
    """
    Searches for and extracts the original SPS and PPS payloads,
    and identifies the start of the IDR (Keyframe) slice.
    """
    print("\n--- Phase 3: Searching for SPS/PPS Headers and IDR Slice Boundary ---")
    
    frame_data = reassembled_frames.get('0100')
    if not frame_data:
        print("Error: Reassembled frame '0100' not found.")
        return None, None, None, None, None, None
        
    frame_id = '0100'
    
    # 1. Find SPS NAL type byte (0x67)
    sps_index = frame_data.find(SPS_NAL_TYPE)
    if sps_index == -1: 
        print("Error: SPS NAL type ('67') not found.")
        return None, None, None, None, None, None
        
    # 2. Find PPS NAL type byte (0x68), searching after SPS
    pps_index = -1
    search_window_end = min(sps_index + 100, len(frame_data))
    for i in range(sps_index + 1, search_window_end):
        if frame_data[i:i+1] == PPS_NAL_TYPE:
            pps_index = i
            break

    if pps_index == -1: 
        print("Error: PPS NAL type ('68') not found.")
        return None, None, None, None, None, None
        
    # 3. Search for the next NAL slice type byte (e.g., IDR slice type 0x65 or 0x05)
    idr_slice_index = -1
    search_start = pps_index + 1
    search_end_slice = min(search_start + 50, len(frame_data)) 

    # Search for common slice types in the expected range
    for nal_type in [b'\x65', b'\x45', b'\x05', b'\x01']: 
        idr_slice_index_raw = frame_data.find(nal_type, search_start, search_end_slice)
        if idr_slice_index_raw != -1:
            if idr_slice_index == -1 or idr_slice_index_raw < idr_slice_index:
                idr_slice_index = idr_slice_index_raw

    # Fallback if an explicit slice header is not found
    if idr_slice_index == -1:
        idr_slice_index = pps_index + MAX_SAFE_PPS_LENGTH
        
    # **Calculate Actual SPS and PPS Payloads**
    native_sps_payload = frame_data[sps_index:pps_index]
    raw_pps_payload_initial = frame_data[pps_index:idr_slice_index]
    
    # Logic to handle the warning you saw: Truncate PPS if it seems too long
    if len(raw_pps_payload_initial) > MAX_SAFE_PPS_LENGTH:
        excess_bytes = raw_pps_payload_initial[MAX_SAFE_PPS_LENGTH:]
        idr_slice_data = excess_bytes + frame_data[idr_slice_index:]
        pps_length = MAX_SAFE_PPS_LENGTH
        print(f"--> WARNING: PPS segment was too long. Truncated PPS to {pps_length} bytes and moved {len(excess_bytes)} bytes to IDR slice.")
    else:
        idr_slice_data = frame_data[idr_slice_index:]
        pps_length = len(raw_pps_payload_initial)

    native_pps_payload = raw_pps_payload_initial[:pps_length]
        
    print(f"--> FOUND NATIVE SPS payload! (Length: {len(native_sps_payload)} bytes)")
    print(f"--> FOUND NATIVE PPS payload! (Length: {len(native_pps_payload)} bytes)")
    print(f"--> IDENTIFIED IDR Slice payload following headers in Frame ID {frame_id}!")

    # Now we return the actual SPS and PPS payloads to be used in writing.
    return True, True, frame_id, idr_slice_data, native_sps_payload, native_pps_payload

def write_final_clean_stream(reassembled_frames, idr_frame_id, idr_slice_data, sps_nal_unit, pps_nal_unit):
    """
    Writes the final clean H.264 stream by using the discovered native headers
    and stripping the 19-byte proprietary header from every slice.
    """
    output_final_filename = "output_final_clean.h264"
    
    print(f"\n--- Phase 5: Writing Final Clean H.264 Stream (Using Native Headers) ---")
    
    if not idr_slice_data or not sps_nal_unit or not pps_nal_unit:
        print("Error: Missing crucial data (SPS, PPS, or IDR Slice). Cannot write file.")
        return

    total_slices = 0

    try:
        with open(output_final_filename, 'wb') as f:
            # 1. INJECT NATIVE H.264 Headers (SPS and PPS)
            # CRITICAL FIX: Use the actual SPS/PPS discovered in the data!
            f.write(NAL_START_CODE); f.write(sps_nal_unit)
            f.write(NAL_START_CODE); f.write(pps_nal_unit)
            
            # 2. Process and write the IDR slice (Keyframe)
            raw_idr_payload = idr_slice_data[PROPRIETARY_HEADER_SKIP_BYTES:]
            final_idr = remove_emulation_prevention_bytes(raw_idr_payload)

            f.write(NAL_START_CODE); f.write(final_idr)
            total_slices += 1

            # 3. Process and write all subsequent P-slices
            # Iterate through frames, ensuring the IDR frame is processed first.
            sorted_frames = sorted(reassembled_frames.items(), key=lambda item: item[0])
            
            for frame_id, frame_data in sorted_frames:
                if frame_id == idr_frame_id: continue # Already written the IDR slice
                
                # Strip the fixed-size proprietary header FIRST.
                raw_frame_payload = frame_data[PROPRIETARY_HEADER_SKIP_BYTES:]
                # Then, remove emulation prevention bytes from the H.264 payload.
                final_frame = remove_emulation_prevention_bytes(raw_frame_payload)
                
                f.write(NAL_START_CODE); f.write(final_frame)
                total_slices += 1
                
        print(f"Wrote FINAL CLEAN stream (Native SPS/PPS + {total_slices} stripped slices) to {output_final_filename}.")
        print(f"✅ Final Success: Wrote a total of {total_slices + 2} NAL units.")
        
        # --- Diagnostic Inspection ---
        if os.path.exists(output_final_filename):
            print("\n--- Diagnostic: Inspecting Cleaned Stream Start ---")
            with open(output_final_filename, 'rb') as f:
                data = f.read(100)
            
            # Diagnostic for the start of the IDR slice
            sps_start = data.find(NAL_START_CODE)
            pps_start = data.find(NAL_START_CODE, sps_start + 4)
            idr_start = data.find(NAL_START_CODE, pps_start + 4)
            
            if idr_start != -1:
                payload_start = idr_start + 4
                diagnostic_bytes = data[payload_start : payload_start + 10]
                diagnostic_hex = binascii.hexlify(diagnostic_bytes).decode('utf-8')
                formatted_hex = ' '.join(diagnostic_hex[i:i+2] for i in range(0, len(diagnostic_hex), 2))
                
                print(f"Hex Dump of the first 10 bytes of the *cleaned* IDR slice:")
                print(formatted_hex)
                if diagnostic_hex.startswith('05') or diagnostic_hex.startswith('65'):
                    print("SUCCESS CONFIRMED: Slice payload still correctly starts with a slice header.")
                else:
                    print("WARNING: Slice header changed unexpectedly.")
            
        print("\n>>> NEXT STEP: Attempt to play the **output_final_clean.h264** file!")
            
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
    
    # Capture the two new return values: native_sps and native_pps
    sps_found, pps_found, idr_frame_id, idr_slice_data, native_sps, native_pps = search_for_headers(reassembled_frames)

    print("\n--- Phase 4: Header Confirmation ---")
    if sps_found and pps_found and idr_slice_data:
        print(f"Native H.264 Headers (SPS: {len(native_sps)} bytes, PPS: {len(native_pps)} bytes) successfully extracted.")
        write_final_clean_stream(reassembled_frames, idr_frame_id, idr_slice_data, native_sps, native_pps)
    else:
        print("\n⚠️ FAILURE: Could not find all necessary components (SPS/PPS/IDR Slice) for writing the file.")
