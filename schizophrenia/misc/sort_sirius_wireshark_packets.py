import re
import csv
import os

# --- Configuration ---
INPUT_FILENAME = 'udpport8800connecction.txt'  # **CHANGE THIS if your file is named differently!**
OUTPUT_FILENAME = 'OUTPUT_udpport8800connecction.csv'
# ---------------------

# Regular expressions to find the necessary data components:

# 1. Finds the Packet Number and Time at the start of the summary line.
# This pattern is highly flexible and only looks for the digits of the packet No.
# and the floating point Time, ignoring all the unpredictable IP/Protocol data that follows.
PACKET_HEADER_PATTERN = re.compile(r'^\s*(\d+)\s+([0-9.]+)\s+')

# 2. Finds the "Data: " line containing the full hexadecimal payload
# This pattern remains robust as it searches for the literal "Data: " field
# which is part of the detailed text dump and is consistent across exports.
DATA_HEX_PATTERN = re.compile(r'^\s*Data: ([0-9a-fA-F]+)\s*$')

def extract_packet_data(input_file_path, output_file_path):
    """
    Reads a large Wireshark text export, extracts the packet number, time,
    and the raw UDP data payload, and saves it to a clean CSV file.
    """
    print(f"Starting analysis of: {input_file_path}")
    
    # Store the extracted data
    extracted_data = []
    
    # Track state while reading the file
    current_packet = None
    
    try:
        with open(input_file_path, 'r') as infile:
            for line in infile:
                
                # 1. Find the Packet Header line (contains No. and Time)
                header_match = PACKET_HEADER_PATTERN.match(line)
                if header_match:
                    # Start of a new packet record
                    packet_num = header_match.group(1)
                    time_val = header_match.group(2)
                    current_packet = {
                        'No': int(packet_num),
                        'Time': float(time_val),
                        'Hex_Data': ''
                    }
                    continue

                # 2. Find the Raw Hex Data line
                data_match = DATA_HEX_PATTERN.match(line)
                if data_match and current_packet:
                    # Found the data for the current packet
                    current_packet['Hex_Data'] = data_match.group(1)
                    extracted_data.append(current_packet)
                    # Reset current_packet to prepare for the next packet record
                    current_packet = None 
                    
            print(f"Finished reading file. Extracted {len(extracted_data)} packets.")

    except FileNotFoundError:
        print(f"ERROR: Input file not found at {input_file_path}")
        return

    # Write the results to a CSV file
    try:
        with open(output_file_path, 'w', newline='') as outfile:
            fieldnames = ['No', 'Time', 'Hex_Data']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(extracted_data)
        
        print(f"SUCCESS: Data successfully written to {output_file_path}")
        print("This file should be small and ready for deeper analysis.")
        
    except Exception as e:
        print(f"ERROR writing CSV file: {e}")

def hex_to_byte_list(hex_string):
    """
    Utility function to convert the long hex string into a list of byte integers.
    """
    if not hex_string:
        return []
    try:
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    except ValueError:
        print(f"Error converting hex string: {hex_string}")
        return []

# --- Example Usage (Run the extraction) ---
if __name__ == '__main__':
    # 1. Run the extraction to generate the small CSV file
    extract_packet_data(INPUT_FILENAME, OUTPUT_FILENAME)

    # 2. Demonstration of the parsing function for analysis
    if os.path.exists(OUTPUT_FILENAME):
        print("\n--- Demonstration: Parsing the first packet's Hex Data ---")
        
        try:
            with open(OUTPUT_FILENAME, 'r') as f:
                reader = csv.DictReader(f)
                first_packet = next(reader, None)
            
            if first_packet:
                raw_hex = first_packet['Hex_Data']
                byte_list = hex_to_byte_list(raw_hex)
                
                print(f"Packet No: {first_packet['No']}, Time: {first_packet['Time']}")
                print(f"Original Hex String (Length {len(raw_hex)}): {raw_hex[:60]}...")
                print(f"List of Bytes (Length {len(byte_list)}): {byte_list[:20]}...")
                print("\nNext step: Use this byte list to identify the Sequence Counter, Command, and Checksum fields!")
                
        except Exception as e:
            print(f"Could not read the generated CSV for demonstration: {e}")