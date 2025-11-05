import csv
import binascii
import re
import os

# --- CONFIGURATION ---
# Based on our analysis:
# Frame ID: 2 bytes starting at byte 8 (used to group fragments into a single picture)
FRAME_ID_OFFSET = 8
FRAME_ID_SIZE = 2

# Fragment Index (Sequence Number): 1 byte starting at byte 32 (used to order fragments)
FRAGMENT_INDEX_OFFSET = 32
FRAGMENT_INDEX_SIZE = 1

# H.264 NAL Unit Signatures (Search Patterns)
# SPS (Sequence Parameter Set, NAL Type 7): 0x67
SPS_SIGNATURE = binascii.unhexlify('0000000167')
# PPS (Picture Parameter Set, NAL Type 8): 0x68
PPS_SIGNATURE = binascii.unhexlify('0000000168')

# The actual video payload data starts immediately after the Fragment Index at byte 33.
DATA_PAYLOAD_OFFSET = FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE

# --- CSV PARSING ---

def load_packets_from_csv(filepath):
    """
    Loads raw hex packet data from a Wireshark-exported CSV file.
    Uses 'latin-1' encoding to avoid common UnicodeDecodeError issues with Wireshark exports.
    """
    raw_packet_data = []
    
    # Pattern to strip any non-hex characters that Wireshark often prefixes to the data
    hex_start_pattern = re.compile(r'[^0-9a-fA-F]*([0-9a-fA-F]+)', re.IGNORECASE)

    try:
        # NOTE: Changed encoding to 'latin-1' (also known as ISO-8859-1) 
        # to fix the UnicodeDecodeError common with Windows and Wireshark files.
        with open(filepath, mode='r', encoding='latin-1') as file:
            # Use 'excel' dialect to handle the double-quoted strings
            reader = csv.reader(file, dialect='excel')
            
            # Skip the header row
            try:
                next(reader) 
            except StopIteration:
                print("Error: The CSV file appears empty.")
                return []

            # Iterate over data rows
            for i, row in enumerate(reader):
                # The raw hex string should be in the last column (index 7, or the 8th column)
                if len(row) < 8:
                    # Skip rows that don't have enough columns (might be control packets)
                    continue

                # We assume the raw hex is in column 7 (the 8th column)
                raw_data_field = row[7].strip()
                
                # Use regex to find and capture the actual hex sequence, stripping prefix characters
                match = hex_start_pattern.match(raw_data_field)
                
                if match:
                    # Clean the hex string by removing whitespace (if any) and converting to lowercase
                    clean_hex = match.group(1).replace(' ', '').lower()
                    
                    if len(clean_hex) > DATA_PAYLOAD_OFFSET * 2: # Ensure it's long enough to contain our headers
                        raw_packet_data.append(clean_hex)
                
    except FileNotFoundError:
        print(f"\nError: File not found at path: {filepath}")
        return None
    except Exception as e:
        print(f"\nAn error occurred while parsing the CSV file: {e}")
        # Note: If this still fails, the user might need to use 'cp1252' or 'utf-8-sig'
        return None

    return raw_packet_data

# --- CORE ANALYSIS FUNCTIONS (REMAINS THE SAME) ---

# Dictionary to hold the reassembled frames:
# Structure: { frame_id: { fragment_index: payload_bytes, ... } }
frame_fragments = {}

def extract_fragment_info(raw_hex_packet):
    """
    Extracts the Frame ID (2 bytes at offset 8) and Fragment Index (1 byte at offset 32)
    from a raw hex string and returns the payload data.
    """
    try:
        # Convert hex string to bytes
        packet_bytes = binascii.unhexlify(raw_hex_packet)

        # 1. Extract Frame ID (used for grouping)
        frame_id_bytes = packet_bytes[FRAME_ID_OFFSET : FRAME_ID_OFFSET + FRAME_ID_SIZE]
        frame_id = frame_id_bytes.hex()

        # 2. Extract Fragment Index (used for ordering)
        fragment_index_bytes = packet_bytes[FRAGMENT_INDEX_OFFSET : FRAGMENT_INDEX_OFFSET + FRAGMENT_INDEX_SIZE]
        # Convert hex byte to integer index
        fragment_index = int(fragment_index_bytes.hex(), 16) 

        # 3. Extract Payload Data (the H.264 part)
        payload_data = packet_bytes[DATA_PAYLOAD_OFFSET:]

        return frame_id, fragment_index, payload_data

    except Exception as e:
        # This often happens when a packet is too short or malformed
        # print(f"Skipping malformed/short packet: {e}")
        return None, None, None

def reassemble_stream(fragments_map):
    """
    Reassembles the fragments into complete frames, sorted by index.
    Returns a dictionary: {frame_id: full_frame_bytes}
    """
    reassembled_frames = {}
    print("\n--- Phase 2: Reassembling Frames ---")

    for frame_id, fragments in fragments_map.items():
        # Get fragments as a list of (index, data) tuples
        fragment_list = [(index, data) for index, data in fragments.items()]
        
        # Sort fragments by their index (sequence number)
        fragment_list.sort(key=lambda x: x[0])
        
        # Concatenate the data payloads in order
        full_frame_bytes = b"".join([data for index, data in fragment_list])
        reassembled_frames[frame_id] = full_frame_bytes
        
    print(f"Successfully reassembled {len(reassembled_frames)} distinct video frames.")
    return reassembled_frames

def search_for_headers(reassembled_frames):
    """
    Searches the reassembled frames for the H.264 SPS and PPS NAL unit signatures.
    """
    found_sps = None
    found_pps = None

    print("\n--- Phase 3: Searching for SPS/PPS Headers ---")
    
    for frame_id, frame_data in reassembled_frames.items():
        
        # Search for SPS (00 00 00 01 67)
        sps_index = frame_data.find(SPS_SIGNATURE)
        if sps_index != -1 and not found_sps:
            # Look for the next Start Code Prefix (00 00 00 01) to define the end of the NAL unit
            next_scp_index = frame_data.find(b'\x00\x00\x00\x01', sps_index + 1)
            
            sps_nal_unit = frame_data[sps_index : next_scp_index] if next_scp_index != -1 else frame_data[sps_index:]
            
            found_sps = {
                'frame_id': frame_id, 
                'data': sps_nal_unit
            }
            print(f"--> FOUND SPS in Frame ID {frame_id}!")

        # Search for PPS (00 00 00 01 68)
        pps_index = frame_data.find(PPS_SIGNATURE)
        if pps_index != -1 and not found_pps:
            # Look for the next Start Code Prefix (00 00 00 01) to define the end of the NAL unit
            next_scp_index = frame_data.find(b'\x00\x00\x00\x01', pps_index + 1)
            
            pps_nal_unit = frame_data[pps_index : next_scp_index] if next_scp_index != -1 else frame_data[pps_index:]
            
            found_pps = {
                'frame_id': frame_id, 
                'data': pps_nal_unit
            }
            print(f"--> FOUND PPS in Frame ID {frame_id}!")
            
        if found_sps and found_pps:
            break
            
    return found_sps, found_pps

# --- Main Execution ---

if __name__ == "__main__":
    
    csv_filename = input("Please enter the name of your Wireshark CSV file (e.g., video_capture.csv): ")
    
    print(f"\nAttempting to load data from {csv_filename}...")
    RAW_PACKET_DATA = load_packets_from_csv(csv_filename)
    
    if RAW_PACKET_DATA is None:
        exit() # Exit if file loading failed

    if not RAW_PACKET_DATA:
        print("No valid video packets were found in the file. Ensure the file is a correct Wireshark CSV export.")
        exit()

    print(f"Starting H.264 Reassembly and Search. Analyzing {len(RAW_PACKET_DATA)} raw packets.")
    print("----------------------------------------------------------------------")
    
    # Phase 1: Data Structuring (Extract and Group)
    for raw_hex in RAW_PACKET_DATA:
        frame_id, fragment_index, payload_data = extract_fragment_info(raw_hex)
        
        if frame_id and fragment_index is not None and payload_data:
            if frame_id not in frame_fragments:
                frame_fragments[frame_id] = {}
            
            # Store the payload data against its index
            frame_fragments[frame_id][fragment_index] = payload_data
        
    # Phase 2: Stream Reassembly
    reassembled_frames = reassemble_stream(frame_fragments)

    # Phase 3: Header Search
    sps_result, pps_result = search_for_headers(reassembled_frames)

    # Phase 4: Reporting
    print("\n--- Phase 4: Final Report ---")
    if sps_result and pps_result:
        print("\n✅ SUCCESS: Found both SPS and PPS headers!")
        
        print("\n[SPS HEADER (Sequence Parameter Set)]")
        print(f"Found in Frame ID: {sps_result['frame_id']}")
        # Convert bytes to hex string for display
        sps_hex = binascii.hexlify(sps_result['data']).decode('utf-8').upper()
        print(f"Raw Hex (SPS): {sps_hex}")
        
        print("\n[PPS HEADER (Picture Parameter Set)]")
        print(f"Found in Frame ID: {pps_result['frame_id']}")
        pps_hex = binascii.hexlify(pps_result['data']).decode('utf-8').upper()
        print(f"Raw Hex (PPS): {pps_hex}")
        
        print("\n>>> NEXT STEP: You now have the crucial configuration headers!")
        print("We can write a final script to stitch these headers to the rest of the stream.")
    else:
        print("\n⚠️ FAILURE: Could not find both SPS and PPS signatures.")
        print("ACTION: Ensure the new capture was taken from the very start of the video transmission.")
        print(f"SPS Found: {'Yes' if sps_result else 'No'}")
        print(f"PPS Found: {'Yes' if pps_result else 'No'}")
