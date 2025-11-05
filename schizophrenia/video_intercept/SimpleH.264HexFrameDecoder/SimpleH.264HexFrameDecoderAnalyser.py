import binascii
import sys
import re

# Standard H.264 NAL Unit Types
NAL_UNIT_TYPES = {
    0: "Unspecified",
    1: "Coded slice of a non-IDR picture (P- or B-slice)",
    2: "Coded slice data partition A",
    3: "Coded slice data partition B",
    4: "Coded slice data partition C",
    5: "Coded slice of an IDR picture (I-slice/Keyframe)",
    6: "Supplemental enhancement information (SEI)",
    7: "Sequence parameter set (SPS)",
    8: "Picture parameter set (PPS)",
    9: "Access unit delimiter (AUD)",
    10: "End of sequence (EOS)",
    11: "End of stream (EOT)",
    12: "Filler data",
    19: "Coded slice of an auxiliary coded picture (Non-IDR, non-reference)",
    20: "Coded slice extension",
}

def sanitize_payload(hex_string):
    """
    Removes all non-hexadecimal characters and converts the string to lowercase.
    This helps clean up data copied from logs or terminals.
    """
    # Use regex to keep only 0-9, a-f, A-F, and convert to lowercase
    return re.sub(r'[^0-9a-fA-F]', '', hex_string).lower()

def decode_h264_frame(hex_payload):
    """
    Takes a raw hex string, converts it to binary, and attempts to parse
    the H.264 NAL units within the payload.
    """
    # 1. Sanitize the input string
    cleaned_payload = sanitize_payload(hex_payload)

    # 2. Handle odd length string issue
    if len(cleaned_payload) % 2 != 0:
        print("WARNING: Sanitized payload length is odd.")
        print("         This means the last half-byte (4 bits) is missing or corrupted.")
        print("         Trimming the last character to proceed with decoding.")
        cleaned_payload = cleaned_payload[:-1]
    
    if not cleaned_payload:
        print("ERROR: Payload is empty or contained only invalid characters after cleaning.")
        return

    payload_length_chars = len(cleaned_payload)
    payload_length_bytes = payload_length_chars // 2
    print(f"Cleaned Payload length: {payload_length_chars} characters ({payload_length_bytes} bytes)")

    try:
        binary_payload = binascii.unhexlify(cleaned_payload)
    except binascii.Error as e:
        print(f"FATAL ERROR: Failed to convert hex to binary even after cleaning.")
        print(f"Details: {e}")
        return

    # H.264 Annex B format (common in raw streams) uses start codes: 0x00 00 01 or 0x00 00 00 01
    # However, if this is a single packet payload (like from RTP/UDP), it might not have the start code.
    # We will assume the payload is a raw stream of NAL units separated by start codes,
    # or a single NAL unit (if no start code is found).
    
    # We'll use a placeholder for start code 0x00 00 01
    start_code = b'\x00\x00\x01'
    nal_units = binary_payload.split(start_code)
    
    if len(nal_units) == 1 and len(nal_units[0]) > 0:
        # Check if the single block is a NAL unit starting with 0x00 00 00 01
        if binary_payload.startswith(b'\x00\x00\x00\x01'):
            nal_units = binary_payload.split(b'\x00\x00\x00\x01')
        else:
            # Assume the whole packet is a single NAL unit payload without a start code (e.g., fragmented RTP)
            # Create a fake split list to process the whole payload as one unit.
            nal_units = [b'', binary_payload] # The first element is empty due to the split, but we keep it structured.

    
    print("-" * 50)
    print("H.264 NAL Unit Analysis:")
    
    nal_count = 0
    for i, unit in enumerate(nal_units):
        if not unit:
            continue

        # NAL Unit Header is the first byte
        nal_header = unit[0]
        
        # NAL Ref Idc (NRI) is bits 1-2 (mask with 0x60 and shift right by 5)
        nri = (nal_header & 0x60) >> 5
        
        # NAL Unit Type is bits 3-7 (mask with 0x1F)
        nal_type = nal_header & 0x1F
        
        type_name = NAL_UNIT_TYPES.get(nal_type, f"Reserved/Unknown ({nal_type})")
        
        print(f"\n--- NAL Unit {nal_count + 1} ---")
        print(f"  Start Code Found: {'Yes' if i > 0 else 'No (Single Unit Assumption)'}")
        print(f"  NAL Unit Type ({nal_type}): {type_name}")
        print(f"  NAL Ref IDC (NRI): {nri} (Importance: {['Not Important', 'Low', 'Medium', 'High'][nri]})")
        print(f"  Payload Size: {len(unit)} bytes")
        
        nal_count += 1

    if nal_count == 0:
        print("\nNo recognizable H.264 NAL units were found.")
        print("This could be due to: 1. The payload is not H.264. 2. It is heavily fragmented (RTP). 3. It is not using standard Annex B start codes.")

    print("-" * 50)


if __name__ == "__main__":
    # In a real-world scenario, you might read from a file or a more sophisticated input.
    # For this script, we'll read the input from the command line arguments or stdin.
    
    if len(sys.argv) > 1:
        # Read from command line argument (e.g., python script.py <hex_string>)
        raw_payload = sys.argv[1]
    else:
        # Read from stdin (e.g., python script.py <<< "hex_string")
        print("Enter the hex payload (or pipe it into the script):")
        raw_payload = sys.stdin.read().strip()

    print(f"Input payload length: {len(raw_payload)} characters")
    decode_h264_frame(raw_payload)
