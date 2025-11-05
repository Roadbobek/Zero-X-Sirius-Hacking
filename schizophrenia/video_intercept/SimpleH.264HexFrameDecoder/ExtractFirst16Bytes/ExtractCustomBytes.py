import csv
import sys
import os

# Configuration (using the filename you provided)
PACKET_DATA_COLUMN_INDEX = 7
INPUT_FILENAME = "video_capture_5.10_Delta_CSV.csv"
OUTPUT_FILENAME = "extracted_bytes_video_capture_5.10_Delta_CSV.txt"

def get_packet_range(max_packets):
    """
    Prompts the user for the packet range and validates the input.
    Returns (start_no, end_no) as integers (1-based, inclusive).
    """
    print(f"\nTotal packets found in '{INPUT_FILENAME}': {max_packets}")
    print("Enter the PACKET range to analyze (e.g., '50' for 1-50, or '50-100'):")
    
    while True:
        try:
            user_input = input("Packet Range: ").strip()
            
            if '-' in user_input:
                start_str, end_str = user_input.split('-')
                start_no = int(start_str.strip())
                end_no = int(end_str.strip())
            else:
                end_no = int(user_input)
                start_no = 1
                
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

def get_byte_range():
    """
    Prompts the user for the byte range to extract.
    Returns (start_byte, end_byte) as integers (0-based, inclusive).
    """
    print("\nEnter the BYTE range to extract (e.g., '0-110' for bytes 0 through 110, or '10-20'):")
    
    while True:
        try:
            user_input = input("Byte Range (0-based index): ").strip()
            
            if '-' in user_input:
                start_str, end_str = user_input.split('-')
                start_byte = int(start_str.strip())
                end_byte = int(end_str.strip())
            else:
                # If only one number is given, assume it's a single byte (e.g., '10' means 10-10)
                start_byte = int(user_input)
                end_byte = start_byte

            if start_byte < 0 or end_byte < 0 or start_byte > end_byte:
                print("Invalid byte range. Start byte must be >= 0 and start must be <= end.")
                continue
                
            return start_byte, end_byte

        except ValueError:
            print("Invalid input format. Please use a number (e.g., '10') or a range (e.g., '10-110').")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)

def get_output_format():
    """
    Prompts the user to select the output format.
    Returns 'B' for Basic or 'D' for Detailed.
    """
    print("\nSelect the output format:")
    print("D - Detailed (Packet No, Source, Protocol, Byte Range, Hex Data)")
    print("B - Basic (Packet No: Hex Data only, minimal headers)")
    
    while True:
        user_input = input("Format (D/B): ").strip().upper()
        if user_input in ['B', 'D']:
            return user_input
        else:
            print("Invalid input. Please enter 'D' for Detailed or 'B' for Basic.")

def clean_and_extract_bytes(hex_string, start_byte, end_byte):
    """
    Cleans up the raw hex string and extracts the specified byte range.
    start_byte and end_byte are 0-based, inclusive.
    """
    
    # 1. Remove common artifacts (e.g., Wireshark metadata like '[Reassembled PDU]')
    cleaned_string = hex_string.split('] ')[-1].strip()
    
    # 2. Further cleaning (ensure only hex characters remain)
    valid_hex = set('0123456789abcdefABCDEF')
    final_hex_string = ''.join(filter(lambda x: x in valid_hex, cleaned_string))
    
    # 3. Convert byte indices to hex character indices
    start_hex = start_byte * 2
    # Python slicing end index is exclusive, so we use (end_byte + 1) * 2
    end_hex = (end_byte + 1) * 2

    # 4. Extract the required range
    if start_hex >= len(final_hex_string):
        return "Not available (Range starts past end of packet)"
    
    extracted = final_hex_string[start_hex:end_hex]
    
    return extracted

def process_packets(start_no, end_no, start_byte, end_byte, all_data, output_format):
    """
    Processes the data within the given packet range and extracts the specified byte range,
    using the chosen output format.
    Returns a list of formatted strings.
    """
    output_lines = []
    
    # Iterate through the rows, skipping the header (index 0).
    for index, row in enumerate(all_data):
        packet_no = index + 1
        
        if start_no <= packet_no <= end_no:
            try:
                raw_data = row[PACKET_DATA_COLUMN_INDEX]
                extracted = clean_and_extract_bytes(raw_data, start_byte, end_byte)
                
                # Format the output line based on user choice
                if extracted.startswith("Not available"):
                     # Consistent error message regardless of format
                    line = f"Packet No: {packet_no:<4} | {extracted}"
                elif output_format == 'B':
                    # Basic format: Packet No: Hex Data only
                    line = f"{packet_no}: {extracted}"
                else:
                    # Detailed format: (Original detailed format)
                    byte_range_str = f"Bytes {start_byte}-{end_byte}"
                    line = (
                        f"Packet No: {packet_no:<4} | "
                        f"Source: {row[2]:<15} | "
                        f"Protocol: {row[4]:<5} | "
                        f"{byte_range_str:<15}: {extracted}"
                    )
                
                output_lines.append(line)
                
            except IndexError:
                # Handle rows that might be malformed (e.g., missing the data column)
                output_lines.append(f"Packet No: {packet_no:<4} | ERROR: Data column (Index {PACKET_DATA_COLUMN_INDEX}) not found or malformed.")
            
    return output_lines

def main():
    """Main function to run the packet extraction process."""
    
    if not os.path.exists(INPUT_FILENAME):
        print(f"Error: Input file '{INPUT_FILENAME}' not found.")
        print("Please ensure your Wireshark CSV file is named correctly.")
        return

    print(f"--- Packet Byte Extractor ---")
    print(f"Reading data from: {INPUT_FILENAME}")
    
    all_data = []
    try:
        # Use 'latin-1' encoding to prevent the UnicodeDecodeError
        with open(INPUT_FILENAME, mode='r', newline='', encoding='latin-1') as infile:
            reader = csv.reader(infile)
            next(reader) # Skip the header row
            for row in reader:
                if len(row) > PACKET_DATA_COLUMN_INDEX:
                    all_data.append(row)
    except Exception as e:
        print(f"An error occurred while reading the CSV file: {e}")
        return

    if not all_data:
        print("The CSV file is empty or contains only a header.")
        return
        
    max_packets = len(all_data)
    
    # 1. Get user-defined packet range
    start_no, end_no = get_packet_range(max_packets)
    
    # 2. Get user-defined byte range
    start_byte, end_byte = get_byte_range()

    # 3. Get user-defined output format (NEW STEP)
    output_format = get_output_format()
    
    # 4. Process the data
    format_label = "Basic" if output_format == 'B' else "Detailed"
    print(f"\nProcessing packets {start_no}-{end_no}, extracting bytes {start_byte}-{end_byte} using {format_label} format...")
    output_lines = process_packets(start_no, end_no, start_byte, end_byte, all_data, output_format)

    # 5. Write results to output file
    try:
        with open(OUTPUT_FILENAME, 'w') as outfile:
            
            # --- Header Content ---
            # Always write the range information requested for the Basic format
            outfile.write(f"Packet Range: {start_no} to {end_no}\n")
            outfile.write(f"Byte Range: {start_byte} to {end_byte} (0-based)\n")

            if output_format != 'B':
                # Write detailed header only if not basic
                outfile.write(f"--- Extracted Packet Data (Detailed Format) ---\n")
                outfile.write(f"Source File: {INPUT_FILENAME}\n")
                outfile.write("-" * 80 + "\n") 
            
            # --- Data Lines ---
            for line in output_lines:
                outfile.write(line + "\n")
                # Also output to CMD
                print(line)

        print("-" * 80)
        print(f"Successfully extracted data for {len(output_lines)} packets.")
        print(f"Results saved to '{OUTPUT_FILENAME}'")
        
    except Exception as e:
        print(f"An error occurred while writing to the output file: {e}")

if __name__ == "__main__":
    main()
