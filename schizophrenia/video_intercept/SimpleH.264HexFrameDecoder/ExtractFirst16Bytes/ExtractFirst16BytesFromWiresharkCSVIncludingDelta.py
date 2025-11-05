import csv
import sys
import os

# The expected column index for the raw packet data (the hex string) is 7 (8th column).
PACKET_DATA_COLUMN_INDEX = 7
# 16 bytes * 2 hex characters per byte = 32 characters
BYTES_TO_EXTRACT = 32
INPUT_FILENAME = "video_capture_5.10_Delta_CSV.csv"
OUTPUT_FILENAME = "extracted_bytes_video_capture_5.10_Delta_CSV.txt"

def get_packet_range(max_packets):
    """
    Prompts the user for the packet range and validates the input.
    Returns (start_no, end_no) as integers.
    """
    print(f"\nTotal packets found in '{INPUT_FILENAME}': {max_packets}")
    print("Enter the packet range to analyze (e.g., '50' for 1-50, or '50-100'):")
    
    while True:
        try:
            user_input = input("Range: ").strip()
            
            if '-' in user_input:
                # Handle range input like '50-100'
                start_str, end_str = user_input.split('-')
                start_no = int(start_str.strip())
                end_no = int(end_str.strip())
            else:
                # Handle single number input like '50' (meaning 1-50)
                end_no = int(user_input)
                start_no = 1
                
            # Basic validation
            if start_no < 1 or end_no < 1 or start_no > end_no:
                print("Invalid range. Start packet number must be >= 1 and start must be <= end.")
                continue
                
            if start_no > max_packets or end_no > max_packets:
                 print(f"The maximum packet number is {max_packets}. Please enter a valid range.")
                 continue

            return start_no, end_no

        except ValueError:
            print("Invalid input format. Please use a number (e.g., '50') or a range (e.g., '50-100').")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)

def clean_and_extract_bytes(hex_string, length=BYTES_TO_EXTRACT):
    """
    Cleans up the raw hex string (removes artifacts like '[â\200\246]') 
    and extracts the first 32 characters (16 bytes).
    """
    # The data often starts with non-hex characters/placeholders (e.g., '[â\200\246] ')
    # A simple way to clean is to strip and then remove any non-hex characters.
    # We only care about the hex data.
    
    # 1. Remove common artifacts like the one seen in your sample data
    cleaned_string = hex_string.split('] ')[-1].strip()
    
    # 2. Further cleaning (ensure only hex characters remain)
    # This is important because Python's CSV reader might keep the escape sequence
    # from the original data (e.g., '\200').
    valid_hex = set('0123456789abcdefABCDEF')
    final_hex_string = ''.join(filter(lambda x: x in valid_hex, cleaned_string))
    
    # 3. Extract the required length
    if len(final_hex_string) < length:
        # Pad with zeros if the packet is too short (unlikely for 16 bytes)
        return final_hex_string.ljust(length, '0')
        
    return final_hex_string[:length]

def process_packets(start_no, end_no, all_data):
    """
    Processes the data within the given range and extracts the required bytes.
    Returns a list of formatted strings.
    """
    output_lines = []
    
    # Iterate through the rows, skipping the header (index 0).
    # Packet numbers are 1-based, so packet_no = index + 1
    for index, row in enumerate(all_data):
        packet_no = index + 1
        
        if start_no <= packet_no <= end_no:
            try:
                raw_data = row[PACKET_DATA_COLUMN_INDEX]
                extracted = clean_and_extract_bytes(raw_data)
                
                # Format the output line
                line = (
                    f"Packet No: {packet_no:<4} | "
                    f"Source: {row[2]:<15} | "
                    f"Protocol: {row[4]:<5} | "
                    f"First 16 Bytes (Hex): {extracted}"
                )
                output_lines.append(line)
                
            except IndexError:
                # Handle rows that might be malformed (e.g., missing the data column)
                output_lines.append(f"Packet No: {packet_no:<4} | ERROR: Data column (Index {PACKET_DATA_COLUMN_INDEX}) not found or malformed.")
            
    return output_lines

def main():
    """Main function to run the packet extraction process."""
    
    # Check if the input file exists
    if not os.path.exists(INPUT_FILENAME):
        print(f"Error: Input file '{INPUT_FILENAME}' not found.")
        print("Please create it with the provided sample data.")
        return

    print(f"--- Packet Byte Extractor ---")
    print(f"Reading data from: {INPUT_FILENAME}")
    
    all_data = []
    try:
        # FIX: Changed encoding from 'utf-8' to 'latin-1' (ISO-8859-1) to handle non-UTF-8 characters 
        # often found in Wireshark CSV exports, which causes the 'invalid continuation byte' error.
        with open(INPUT_FILENAME, mode='r', newline='', encoding='latin-1') as infile:
            reader = csv.reader(infile)
            header = next(reader) # Skip the header row
            for row in reader:
                # Only include rows that actually have enough columns
                if len(row) > PACKET_DATA_COLUMN_INDEX:
                    all_data.append(row)
    except Exception as e:
        print(f"An error occurred while reading the CSV file: {e}")
        return

    if not all_data:
        print("The CSV file is empty or contains only a header.")
        return
        
    max_packets = len(all_data)
    
    # 1. Get user-defined range
    start_no, end_no = get_packet_range(max_packets)
    
    # 2. Process the data
    print(f"\nProcessing packets {start_no} to {end_no}...")
    output_lines = process_packets(start_no, end_no, all_data)

    # 3. Write results to output file
    try:
        with open(OUTPUT_FILENAME, 'w') as outfile:
            outfile.write(f"--- Extracted First 16 Bytes of Packet Data ---\n")
            outfile.write(f"Source File: {INPUT_FILENAME}\n")
            outfile.write(f"Packet Range: {start_no} to {end_no}\n")
            outfile.write("-" * 80 + "\n")
            
            for line in output_lines:
                outfile.write(line + "\n")
                # Also output to CMD as requested
                print(line)

        print("-" * 80)
        print(f"Successfully extracted data for {len(output_lines)} packets.")
        print(f"Results saved to '{OUTPUT_FILENAME}'")
        
    except Exception as e:
        print(f"An error occurred while writing to the output file: {e}")

if __name__ == "__main__":
    main()
