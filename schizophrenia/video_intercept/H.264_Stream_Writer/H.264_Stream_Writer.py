import csv
import binascii
import re
import os
from typing import Dict, List, Tuple, Optional

# --- CRITICAL CONFIGURATION ---
# Determined from packet diagnostics. This is the custom proprietary header length
# that must be skipped from the start of every fragmented video slice payload.
PROPRIETARY_HEADER_SKIP_BYTES = 19

# Byte offsets within the proprietary header structure
FRAME_ID_OFFSET = 8
FRAME_ID_SIZE = 2
FRAGMENT_INDEX_OFFSET = 32
FRAGMENT_INDEX_SIZE = 1
DATA_PAYLOAD_OFFSET = FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE

# H.264 NAL Unit Signatures (Search Patterns)
NAL_START_CODE = b'\x00\x00\x00\x01'
SPS_NAL_TYPE = b'\x67'  # Sequence Parameter Set (Type 7)
PPS_NAL_TYPE = b'\x68' # Picture Parameter Set (Type 8)

# --- PATCH CONSTANTS FOR 'NON-INTRA SLICE IN IDR' ERROR ---
# IDR NAL Unit Header: 0x65 (Type 5, NRI=3)
IDR_NAL_UNIT_HEADER = b'\x65' 
# Common I-Slice Header byte for first slice of frame (Type 2, first_mb_in_slice=0)
# Overriding the second byte of the NAL unit (start of slice header) to this value
# often resolves the FFmpeg error by forcing the slice type to I (Intra).
I_SLICE_HEADER_BYTE_PATCH = b'\x42'
# Common P-Slice Header byte for first slice of frame (Type 0, first_mb_in_slice=0)
P_SLICE_HEADER_BYTE_COMMON = b'\x80' 

# --- UTILITY FUNCTIONS ---

def remove_emulation_prevention_bytes(data: bytes) -> bytes:
    """
    Removes H.264 Emulation Prevention Bytes (0x03) that follow 0x00 0x00.
    This is necessary to make the stream compliant.
    """
    return data.replace(b'\x00\x00\x03', b'\x00\x00')

def load_packets_from_csv(filepath: str) -> Optional[List[str]]:
    """Loads raw hex packet data from a Wireshark-exported CSV file."""
    raw_packet_data = []
    # Regex finds the first sequence of hex characters in the field, ignoring leading garbage.
    hex_start_pattern = re.compile(r'[^0-9a-fA-F]*([0-9a-fA-F]+)', re.IGNORECASE)

    try:
        # Use 'latin-1' as a common fallback encoding for messy CSV exports
        with open(filepath, mode='r', encoding='latin-1') as file:
            reader = csv.reader(file, dialect='excel')
            try:
                # Skip header row
                next(reader)
            except StopIteration:
                return []

            for row in reader:
                # Assuming row[7] contains the raw hex data string (Delta data.data)
                if len(row) < 8:
                    continue

                raw_data_field = row[7].strip()
                match = hex_start_pattern.match(raw_data_field)
                
                if match:
                    clean_hex = match.group(1).replace(' ', '').lower()
                    
                    # Ensure the packet is long enough to contain the proprietary header structure
                    if len(clean_hex) >= DATA_PAYLOAD_OFFSET * 2:
                        raw_packet_data.append(clean_hex)
                
    except FileNotFoundError:
        print(f"\nError: File not found at path: {filepath}")
        return None
    except Exception as e:
        print(f"\nAn error occurred while parsing the CSV file: {type(e).__name__}: {e}")
        return None

    return raw_packet_data

def extract_fragment_info(raw_hex_packet: str) -> Tuple[Optional[str], Optional[int], Optional[bytes]]:
    """Extracts Frame ID, Fragment Index, and H.264 payload data."""
    try:
        packet_bytes = binascii.unhexlify(raw_hex_packet)
        
        # 1. Extract Frame ID
        frame_id_bytes = packet_bytes[FRAME_ID_OFFSET : FRAME_ID_OFFSET + FRAME_ID_SIZE]
        frame_id = frame_id_bytes.hex()
        
        # 2. Extract Fragment Index
        fragment_index_bytes = packet_bytes[FRAGMENT_INDEX_OFFSET : FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE]
        # Fragment index is an integer value, e.g., 0x01 -> 1
        fragment_index = int(fragment_index_bytes.hex(), 16)
        
        # 3. Payload starts after the fixed header structure (including proprietary header)
        payload_data = packet_bytes[DATA_PAYLOAD_OFFSET:]
        
        return frame_id, fragment_index, payload_data
        
    except binascii.Error:
        # Silently skip malformed hex strings
        return None, None, None
    except Exception:
        # Silently skip packets that fail for other reasons (e.g., too short)
        return None, None, None

def reassemble_stream(fragments_map: Dict[str, Dict[int, bytes]]) -> Dict[str, bytes]:
    """Reassembles the fragments into complete frames, sorted by index."""
    reassembled_frames = {}
    print("\n--- Phase 2: Reassembling Frames ---")

    for frame_id, fragments in fragments_map.items():
        # Convert dictionary to list of (index, data) tuples and sort by index
        fragment_list = sorted(fragments.items(), key=lambda x: x[0])
        
        # Concatenate the data payloads
        full_frame_bytes = b"".join([data for index, data in fragment_list])
        reassembled_frames[frame_id] = full_frame_bytes
        
    print(f"Successfully reassembled {len(reassembled_frames)} distinct video frames.")
    return reassembled_frames

def search_for_headers(reassembled_frames: Dict[str, bytes]) -> Tuple[bool, bool, Optional[str], Optional[bytes], Optional[bytes], Optional[bytes]]:
    """
    Searches for and extracts the original SPS and PPS payloads,
    and identifies the start of the IDR (Keyframe) slice.
    """
    print("\n--- Phase 3: Searching for SPS/PPS Headers and IDR Slice Boundary ---")
    
    # Typically, the first keyframe (IDR) has a frame ID of '0100' or similar small value.
    idr_frame_id = '0100'
    frame_data_with_header = reassembled_frames.get(idr_frame_id)
    
    if not frame_data_with_header:
        print(f"Error: Reassembled IDR frame '{idr_frame_id}' not found.")
        return False, False, None, None, None, None

    # 1. Strip the proprietary header bytes *FIRST*
    # The proprietary header is only on the first fragment, but we strip it from the whole reassembled frame for consistency
    frame_data = frame_data_with_header[PROPRIETARY_HEADER_SKIP_BYTES:]
    print(f"--> Stripped {PROPRIETARY_HEADER_SKIP_BYTES} proprietary bytes from the IDR frame data.")

    # 2. Find SPS NAL type byte (0x67)
    sps_index = frame_data.find(SPS_NAL_TYPE)
    if sps_index == -1: 
        print("Error: SPS NAL type ('67') not found after stripping proprietary header.")
        return False, False, None, None, None, None
        
    # 3. Find PPS NAL type byte (0x68), searching after SPS
    pps_index = -1
    search_window_end = min(sps_index + 100, len(frame_data))
    for i in range(sps_index + 1, search_window_end):
        if frame_data[i:i+1] == PPS_NAL_TYPE:
            pps_index = i
            break

    if pps_index == -1: 
        print("Error: PPS NAL type ('68') not found.")
        return False, False, None, None, None, None
        
    # 4. Search for the next NAL slice type byte (the start of the IDR slice)
    # Search for the first byte that is NOT part of the SPS or PPS data
    idr_slice_index = -1
    search_start = pps_index + 1
    search_end_slice = min(search_start + 100, len(frame_data)) 

    # We are looking for the next NAL unit header byte (NAL Unit Type 5, 1, etc.)
    for i in range(search_start, search_end_slice):
        # A NAL Unit header byte must have nal_ref_idc > 0 for a keyframe slice (e.g., bits 1xxxxxxx or 01xxxxxx)
        nal_unit_type = frame_data[i] & 0x1F # Mask to get the last 5 bits (NAL Type)
        if nal_unit_type in [5, 1]: # IDR Slice (5) or P/B Slice (1)
            idr_slice_index = i
            break

    if idr_slice_index == -1:
        print("Error: Could not find the start of the IDR slice NAL unit (type 5 or 1).")
        return False, False, idr_frame_id, None, None, None

    # **Calculate Actual SPS and PPS Payloads**
    native_sps_payload = frame_data[sps_index:pps_index]
    native_pps_payload = frame_data[pps_index:idr_slice_index]
    idr_slice_data = frame_data[idr_slice_index:] # This is the slice NAL unit payload

    print(f"--> FOUND NATIVE SPS payload! (Length: {len(native_sps_payload)} bytes)")
    print(f"--> FOUND NATIVE PPS payload! (Length: {len(native_pps_payload)} bytes)")
    print(f"--> IDENTIFIED IDR Slice NAL unit payload following headers in Frame ID {idr_frame_id}!")

    # Return the clean headers and the IDR slice data (which is already stripped of the proprietary header)
    return True, True, idr_frame_id, idr_slice_data, native_sps_payload, native_pps_payload

def write_final_clean_stream(
    reassembled_frames: Dict[str, bytes], 
    idr_frame_id: str, 
    idr_slice_data: bytes, 
    sps_nal_unit: bytes, 
    pps_nal_unit: bytes
):
    """
    Writes the final clean H.264 stream by using the discovered native headers
    and stripping the 19-byte proprietary header from every subsequent slice.
    
    Includes a critical fix to ensure the IDR slice inside the IDR NAL unit
    is correctly marked as an I-slice (Intra) to satisfy FFmpeg/VLC.
    """
    output_final_filename = "output_final_clean.h264"
    
    print(f"\n--- Phase 5: Writing Final Clean H.264 Stream (Using Native Headers) ---")
    
    if not idr_slice_data or not sps_nal_unit or not pps_nal_unit:
        print("Error: Missing crucial data (SPS, PPS, or IDR Slice). Cannot write file.")
        return

    total_slices = 0

    try:
        with open(output_final_filename, 'wb') as f:
            
            # CRITICAL: Clean the headers themselves before writing!
            cleaned_sps = remove_emulation_prevention_bytes(sps_nal_unit)
            cleaned_pps = remove_emulation_prevention_bytes(pps_nal_unit)
            
            # 1. INJECT NATIVE H.264 Headers (SPS and PPS)
            f.write(NAL_START_CODE); f.write(cleaned_sps)
            f.write(NAL_START_CODE); f.write(cleaned_pps)
            
            # 2. Process and write the IDR slice (Keyframe)
            if len(idr_slice_data) < 2:
                print("Warning: IDR slice data is too short after extraction. Skipping.")
                final_idr_slice = b''
            else:
                # --- CRITICAL FIX FOR 'NON-INTRA SLICE IN IDR' ERROR ---
                
                # The NAL Unit Header is the first byte (index 0).
                nal_unit_header = idr_slice_data[0:1]
                # The Slice Header starts at the second byte (index 1).
                slice_header_start_byte = idr_slice_data[1:2]
                rest_of_slice_payload = idr_slice_data[2:]

                # 2a. Force NAL Unit Header to Type 5 (IDR) if it isn't already.
                current_nal_type = idr_slice_data[0] & 0x1F
                if current_nal_type != 5:
                    print(f"--> INFO: NAL unit header detected as Type {current_nal_type}. Forcing to 0x65 (IDR).")
                    nal_unit_header = IDR_NAL_UNIT_HEADER
                
                # 2b. Patch the Slice Header to force I-Slice (Intra) type.
                fixed_slice_header_start = slice_header_start_byte
                
                # If the byte matches a common P-slice start, override it with a known I-slice value.
                if slice_header_start_byte == P_SLICE_HEADER_BYTE_COMMON:
                    print(f"--> PATCH: Overriding slice header byte ({P_SLICE_HEADER_BYTE_COMMON.hex()}) to I-Slice type ({I_SLICE_HEADER_BYTE_PATCH.hex()}) to fix FFmpeg error.")
                    fixed_slice_header_start = I_SLICE_HEADER_BYTE_PATCH

                # Reassemble the fixed IDR slice: NAL Header + Fixed Slice Header + Rest of Slice
                fixed_idr_slice = nal_unit_header + fixed_slice_header_start + rest_of_slice_payload
                
                # 2c. Then, remove emulation prevention bytes from the H.264 payload.
                final_idr_slice = remove_emulation_prevention_bytes(fixed_idr_slice)

                f.write(NAL_START_CODE); f.write(final_idr_slice)
                total_slices += 1

            # 3. Process and write all subsequent P-slices and remaining frames
            # Sort by frame ID to try and maintain frame order
            sorted_frames = sorted(reassembled_frames.items(), key=lambda item: item[0])
            
            for frame_id, frame_data in sorted_frames:
                # Skip the IDR frame, as its main slice was already handled
                if frame_id == idr_frame_id: continue 
                
                # Strip the fixed-size proprietary header FIRST (19 bytes from every non-header slice).
                if len(frame_data) < PROPRIETARY_HEADER_SKIP_BYTES:
                    print(f"Skipping frame {frame_id}: payload too short after reassembly.")
                    continue
                
                raw_frame_payload = frame_data[PROPRIETARY_HEADER_SKIP_BYTES:]
                
                # Then, remove emulation prevention bytes from the H.264 payload.
                final_frame = remove_emulation_prevention_bytes(raw_frame_payload)
                
                # Only write if there is a payload remaining
                if final_frame:
                    f.write(NAL_START_CODE); f.write(final_frame)
                    total_slices += 1
                
        print(f"Wrote FINAL CLEAN stream (Native SPS/PPS + {total_slices} stripped slices) to {output_final_filename}.")
        print(f"✅ Final Success: Wrote a total of {total_slices + 2} NAL units (2 headers + {total_slices} slices).")
        
        # --- Diagnostic Inspection ---
        if os.path.exists(output_final_filename):
            print("\n--- Diagnostic: Inspecting Cleaned Stream Start ---")
            with open(output_final_filename, 'rb') as f:
                data = f.read(100)
            
            start_codes = [i for i in range(len(data) - 3) if data[i:i+4] == NAL_START_CODE]
            
            if len(start_codes) >= 3:
                payload_start = start_codes[2] + 4
                diagnostic_bytes = data[payload_start : payload_start + 10]
                diagnostic_hex = binascii.hexlify(diagnostic_bytes).decode('utf-8')
                formatted_hex = ' '.join(diagnostic_hex[i:i+2] for i in range(0, len(diagnostic_hex), 2))
                
                first_nal_byte_int = diagnostic_bytes[0]
                nal_unit_type = first_nal_byte_int & 0x1F

                print(f"Hex Dump of the first 10 bytes of the *cleaned* IDR slice NAL unit:")
                print(formatted_hex)
                print(f"NAL Unit Header Byte (0x{first_nal_byte_int:02x}) decoded NAL Type: {nal_unit_type}")

                # Check if the second byte (start of slice header) was modified to the I-Slice patch value
                slice_header_start = diagnostic_bytes[1:2]
                if nal_unit_type == 5 and slice_header_start == I_SLICE_HEADER_BYTE_PATCH:
                    print("SUCCESS CONFIRMED: IDR Slice NAL unit type 5 found and slice header patched.")
                else:
                    print("WARNING: IDR NAL Type is correct, but slice header may still be invalid.")
            else:
                print("Diagnostic Warning: Could not find three NAL start codes in the first 100 bytes.")
                
        print("\n>>> NEXT STEP: Attempt to play the **output_final_clean.h264** file using a media player (e.g., VLC, ffplay) or an analyzer!")
            
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
        print("No valid video packets were found in the file.")
        exit()

    print(f"Starting H.264 Reassembly and Stream Writing. Analyzing {len(RAW_PACKET_DATA)} raw packets.")
    print("----------------------------------------------------------------------")
    
    # --- Phase 1: Fragment Extraction and Grouping ---
    frame_fragments: Dict[str, Dict[int, bytes]] = {}
    for raw_hex in RAW_PACKET_DATA:
        frame_id, fragment_index, payload_data = extract_fragment_info(raw_hex)
        if frame_id and fragment_index is not None and payload_data:
            if frame_id not in frame_fragments: 
                frame_fragments[frame_id] = {}
            frame_fragments[frame_id][fragment_index] = payload_data
        
    reassembled_frames = reassemble_stream(frame_fragments)
    
    # --- Phase 3 & 4: Header Search and Confirmation ---
    # The return order: sps_found, pps_found, idr_frame_id, idr_slice_data, native_sps, native_pps
    sps_found, pps_found, idr_frame_id, idr_slice_data, native_sps, native_pps = search_for_headers(reassembled_frames)

    print("\n--- Phase 4: Header Confirmation ---")
    if sps_found and pps_found and idr_slice_data:
        print(f"Native H.264 Headers (SPS: {len(native_sps)} bytes, PPS: {len(native_pps)} bytes) successfully extracted.")
        # --- Phase 5: Writing ---
        write_final_clean_stream(reassembled_frames, idr_frame_id, idr_slice_data, native_sps, native_pps)
    else:
        print("\n⚠️ FAILURE: Could not find all necessary components (SPS/PPS/IDR Slice) for writing the file.")
